package main

// Several captures read as one.
//
// sharkd loads a single file, so a reference naming more than one is merged
// before it is loaded: mergecap writes the frames of all of them into one temp
// file in timestamp order, and that file is what the session holds. So the two
// sides of a call recorded either end of it are one packet list, one display
// filter and one sequence diagram, rather than two views to read against each
// other.
//
// The merge belongs to the session that asked for it - made in spawn(), deleted
// when that sharkd ends - so nothing accumulates and nothing has to be
// invalidated when one of the parts grows: the same set asked for again is
// merged again, unless the pool still holds the session, which is the case worth
// making fast and is already free. The temp file lands wherever TMPDIR says,
// the only place this server writes outside CAPTURES.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// A reference is what the UI opens: one capture, or several to be read as one,
// their names joined by commas - a character no capture name holds (nameOK in
// main.go), so a reference splits back into its parts with nothing escaped.
const refSep = ","

// How many captures one reference may name. This and the byte limit below are
// both about the temp file the merge writes: a directory of a thousand captures
// is one select-all away from being asked for as a single file.
const maxParts = 16

type merger struct {
	bin   string // mergecap
	dir   string // CAPTURES, the same directory the pool loads from
	limit int64  // most bytes of captures one reference may name
}

// parts splits a reference into the captures it names, sorted and de-duplicated
// so the same set is the same reference however it was picked - the pool keys
// its sessions on the result, and three files clicked in two orders are one
// sharkd rather than two. False for anything that is not a reference: a name in
// it that is not a capture name, or more parts than maxParts.
func parts(ref string) ([]string, bool) {
	names := strings.Split(ref, refSep)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > maxParts {
		return nil, false
	}
	for _, n := range names {
		if !nameOK.MatchString(n) {
			return nil, false
		}
	}
	return names, true
}

// file is the one capture a reference names, or a merge of the several it names.
// The bool says the path is a temp file, which the caller then owns.
func (m *merger) file(ref string) (string, bool, error) {
	names, ok := parts(ref)
	if !ok {
		return "", false, fmt.Errorf("not a capture: %s", ref)
	}
	// stat'ed before mergecap is run, so a name that is not there is said in
	// those words rather than in whatever the tool makes of it
	paths := make([]string, len(names))
	var total int64
	for i, n := range names {
		paths[i] = filepath.Join(m.dir, n)
		info, err := os.Stat(paths[i])
		if err != nil {
			return "", false, fmt.Errorf("%s: no such capture", n)
		}
		total += info.Size()
	}
	if len(paths) == 1 {
		return paths[0], false, nil
	}
	if total > m.limit {
		// rounded up, so the smallest set over the limit is not reported as 0 MB
		return "", false, fmt.Errorf("%d captures, %d MB in all: more than MERGE_LIMIT allows (%d MB)",
			len(names), (total+(1<<20)-1)>>20, m.limit>>20)
	}

	// pcapng, mergecap's own default, because it is the only format that can
	// carry what the parts hold - several interfaces, their timestamp
	// resolutions, and the comments a frame was saved with
	out, err := os.CreateTemp("", "webshark-*.pcapng")
	if err != nil {
		return "", false, err
	}
	out.Close() // the file was for its name; mergecap writes it itself
	// -I none keeps each capture's interfaces its own rather than folding
	// same-named ones together, so a frame of the merge still says which capture
	// it came from - its interface id - and two different interfaces that were
	// both called eth0 stay two. Twenty bytes a capture.
	var said bytes.Buffer
	cmd := exec.Command(m.bin, append([]string{"-I", "none", "-w", out.Name()}, paths...)...)
	cmd.Stderr = &said
	if err := cmd.Run(); err != nil {
		os.Remove(out.Name())
		return "", false, fmt.Errorf("merging %d captures: %s", len(names), reason(said.String(), err))
	}
	return out.Name(), true, nil
}

// What mergecap said went wrong: its last line of stderr - "unknown file format"
// and the like - since its exit status is only ever 1 or 2, and that only where
// it said nothing at all.
func reason(said string, err error) string {
	lines := strings.Split(strings.TrimSpace(said), "\n")
	if last := lines[len(lines)-1]; last != "" {
		return last
	}
	return err.Error()
}
