package main

// One sharkd per open capture, talked to over its stdio JSON-RPC.
//
// sharkd keeps the whole dissected capture in memory, so the interesting part
// of owning the processes is *ending* them: the pool holds at most `max` of
// them and closes whichever was used least recently, plus anything idle for
// longer than `idle`. Nothing else here is clever - a request is a line in and
// a line out, serialized per session by a mutex.
//
// A capture's own ESP keys need nothing from this file: plugins/ims_esp recovers
// them inside sharkd, during the load below, so that protected Gm traffic
// dissects.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type session struct {
	mu   sync.Mutex // one request at a time down the pipe
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Reader
	enc  *json.Encoder
	seq  int
	used time.Time
	dead atomic.Bool // read outside the mutex, by the pool deciding to retry
}

type pool struct {
	bin, dir string
	max      int
	idle     time.Duration

	mu   sync.Mutex
	live map[string]*session
}

func newPool(bin, dir string, max int, idle time.Duration) *pool {
	p := &pool{bin: bin, dir: dir, max: max, idle: idle, live: map[string]*session{}}
	go p.reap()
	return p
}

// call runs one JSON-RPC method against the sharkd holding `file` and returns
// its `result` untouched, so a response can be handed to the browser without
// being decoded and re-encoded on the way. A broken pipe - sharkd gone, killed,
// crashed on a malformed capture - is retried once against a fresh process,
// because the alternative is a capture that stays broken until restart.
func (p *pool) call(file, method string, params any) (json.RawMessage, error) {
	for attempt := 0; attempt < 2; attempt++ {
		s, err := p.acquire(file)
		if err != nil {
			return nil, err
		}
		raw, err := s.do(method, params)
		if err == nil {
			return raw, nil
		}
		if !s.dead.Load() {
			return nil, err // sharkd answered, and the answer was an error
		}
		p.drop(file, s)
	}
	return nil, fmt.Errorf("sharkd: %s: not answering", file)
}

func (p *pool) acquire(file string) (*session, error) {
	p.mu.Lock()
	if s, ok := p.live[file]; ok && !s.dead.Load() {
		s.used = time.Now()
		p.mu.Unlock()
		return s, nil
	}
	for len(p.live) >= p.max {
		var oldest string
		for name, s := range p.live {
			if oldest == "" || s.used.Before(p.live[oldest].used) {
				oldest = name
			}
		}
		s := p.live[oldest]
		delete(p.live, oldest)
		go s.close()
	}
	p.mu.Unlock()

	s, err := p.spawn(file)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	// another request may have opened the same file while this one was loading;
	// keep whichever is already published and let this one go
	if other, ok := p.live[file]; ok && !other.dead.Load() {
		p.mu.Unlock()
		go s.close()
		return other, nil
	}
	p.live[file] = s
	p.mu.Unlock()
	return s, nil
}

// A sharkd process with nothing loaded in it. Splitting this out of spawn is for
// hierarchy() below, which wants the process but not the pool's idea of what to
// do with one.
func (p *pool) start() (*session, error) {
	cmd := exec.Command(p.bin, "-")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr // sharkd's own diagnostics belong in the container log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s := &session{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<16), used: time.Now()}
	s.enc = json.NewEncoder(in)
	return s, nil
}

func (p *pool) spawn(file string) (*session, error) {
	s, err := p.start()
	if err != nil {
		return nil, err
	}
	if _, err := s.do("load", map[string]any{"file": filepath.Join(p.dir, file)}); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// hierarchy is the protocol-hierarchy tap over the first `frames` frames of a
// capture, for the file list (capture.go). Three things make it its own thing
// rather than a pool.call:
//
//   - the load is bounded, and the pool's sessions are not: the same capture is
//     in both at once, one holding all of it for the packet list and this one
//     holding the beginning of it.
//   - the process is not pooled, so scanning a directory cannot evict the capture
//     the user has open - the pool holds four sessions and a directory can hold
//     any number of files.
//
// It pays for plugins/ims_esp all the same - the fields that plugin asks for are
// what make any load build a dissection tree - and buys nothing with it: what a
// protected frame carries is not part of the answer to "which protocols are in
// this file". Bounded by `frames` above and cached by the scanner, so it is left
// to do that rather than turned off for this one session.
func (p *pool) hierarchy(file string, frames int) (json.RawMessage, error) {
	s, err := p.start()
	if err != nil {
		return nil, err
	}
	defer s.close()
	load := map[string]any{"file": filepath.Join(p.dir, file), "max_packets": frames}
	if _, err := s.do("load", load); err != nil {
		return nil, err
	}
	return s.do("tap", map[string]any{"tap0": "phs"})
}

func (p *pool) drop(file string, s *session) {
	p.mu.Lock()
	if cur, ok := p.live[file]; ok && cur == s {
		delete(p.live, file)
	}
	p.mu.Unlock()
	s.close()
}

// Close is only reachable from the UI's "close" button; the reaper does the
// same thing on a timer.
func (p *pool) closeFile(file string) {
	p.mu.Lock()
	s, ok := p.live[file]
	delete(p.live, file)
	p.mu.Unlock()
	if ok {
		s.close()
	}
}

func (p *pool) open() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(p.live))
	for name := range p.live {
		names = append(names, name)
	}
	return names
}

func (p *pool) reap() {
	for range time.Tick(time.Minute) {
		cutoff := time.Now().Add(-p.idle)
		p.mu.Lock()
		for name, s := range p.live {
			if s.used.Before(cutoff) {
				delete(p.live, name)
				go s.close()
			}
		}
		p.mu.Unlock()
	}
}

func (s *session) do(method string, params any) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead.Load() {
		return nil, io.ErrClosedPipe
	}
	s.used = time.Now()
	s.seq++

	req := struct {
		Version string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
	}{"2.0", s.seq, method, params}
	if err := s.enc.Encode(req); err != nil { // Encode appends the newline
		s.dead.Store(true)
		return nil, err
	}

	for {
		line, err := s.out.ReadBytes('\n')
		if err != nil {
			s.dead.Store(true)
			return nil, err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue // sharkd greets on stdout before the first response
		}
		var resp struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			s.dead.Store(true)
			return nil, fmt.Errorf("sharkd: unparsable response: %w", err)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("%s", resp.Error.Message)
		}
		return resp.Result, nil
	}
}

func (s *session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dead.CompareAndSwap(false, true) {
		return
	}
	s.in.Close() // sharkd exits on EOF; kill anything that would rather not
	go func() {
		timer := time.AfterFunc(2*time.Second, func() { s.cmd.Process.Kill() })
		s.cmd.Wait()
		timer.Stop()
	}()
}
