package main

// What the capture list knows about a file besides its name and size: when its
// frames were captured, and which protocols are in it. Both are wanted for every
// file in the directory at once, and that is what makes them awkward - the
// obvious way to get either is to read the whole capture, and a directory
// listing cannot afford one read of a 600 MB file, let alone one per file.
//
// So neither is asked of a loaded capture:
//
//	times    a capture file says when its frames were captured in its own
//	         header, and a pcapng repeats every block's length at both ends -
//	         which exists so that a file can be walked backwards. The first
//	         frame is at the head and the last is at the tail, two seeks, whatever
//	         the file's size.
//
//	protos   these do need dissecting, and sharkd's protocol-hierarchy tap is
//	         the same one Wireshark's Protocol Hierarchy window draws - but a tap
//	         runs over a loaded file. sharkd's `load` takes max_packets, so what
//	         is loaded is the first SCAN_FRAMES frames and no more: on a capture
//	         whose every frame is a TLS record, the whole file is 76 s of
//	         dissection and 20 000 frames of it is under two. A sample, therefore,
//	         and said to be one - see scan.Partial.
//
// The scan is the expensive half, so it is cached and it is never on the path of
// a listing: /api/captures answers with whatever has been scanned already, and
// the UI asks for the rest a file at a time.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
)

// --------------------------------------------------------------------- times --

// The frame times of one capture, as Unix milliseconds - which is what the UI
// wants, and finer than a file list has any use for. Zero means "not known":
// a format whose tail cannot be walked, a capture still being written, a header
// this does not read.
type times struct {
	First int64 `json:"first,omitempty"`
	Last  int64 `json:"last,omitempty"`
}

// pcapng block types, and the byte-order magic of a section header. Only these
// three block types are read; anything else is stepped over by its length.
const (
	blkSHB = 0x0a0d0d0a
	blkIDB = 0x00000001
	blkEPB = 0x00000006
	bomBE  = 0x1a2b3c4d
)

// Sanity bounds on a block, so that a length read out of a damaged or
// half-written file cannot send this walking through gigabytes of it. A block is
// a 4-byte-aligned 12 bytes or more; 16 MB is well past the largest frame any
// link type can carry.
const (
	minBlock = 12
	maxBlock = 16 << 20
	maxWalk  = 4096 // blocks looked at from either end before giving up
)

// captureTimes reads the first and last frame times out of a capture file.
// Failure of any kind - an unreadable file, a format not handled, a tail that
// does not walk - is an absent time rather than an error: the list falls back to
// the file's own mtime, and says that is what it is showing.
func captureTimes(path string) times {
	f, err := os.Open(path)
	if err != nil {
		return times{}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return times{}
	}

	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil {
		return times{}
	}
	if binary.BigEndian.Uint32(magic[:]) == blkSHB {
		return pcapngTimes(f, info.Size())
	}
	return pcapTimes(f, magic)
}

// A pcapng is a chain of blocks, each `type, length, body…, length` - and the
// repeated length is what makes the tail reachable: the last four bytes of the
// file are the length of the last block, so its start is that far back from the
// end, and so on. A capture ptcpdump is still writing has no complete block at
// its end, and the length read there is whatever the half-written body happens to
// hold - hence the checks in back(), which turn that into "not known" rather than
// a walk into nonsense.
//
// Timestamps live in Enhanced Packet Blocks, in units the block's interface
// declared (if_tsresol, microseconds unless said otherwise), so the interface
// descriptions are collected on the way to the first frame. A file with several
// sections is read as its first: the resolutions of a later one are not looked
// for, which costs the tail of such a file its scale - rare enough, and a wrong
// scale would be worse than no time.
func pcapngTimes(f *os.File, size int64) times {
	var bom [4]byte
	if _, err := f.ReadAt(bom[:], 8); err != nil {
		return times{}
	}
	end := binary.ByteOrder(binary.LittleEndian)
	if binary.BigEndian.Uint32(bom[:]) == bomBE {
		end = binary.BigEndian
	}

	var out times
	units := []uint64{} // per interface, in the order the descriptions appear

	// forward, to the first packet block
	for pos, n := int64(0), 0; pos+minBlock <= size && n < maxWalk; n++ {
		kind, length, body, ok := block(f, end, pos)
		if !ok {
			break
		}
		switch kind {
		case blkIDB:
			units = append(units, tsResol(f, end, body, length))
		case blkEPB:
			out.First = epbTime(f, end, body, units)
		}
		if out.First != 0 {
			break
		}
		pos += int64(length)
	}
	if out.First == 0 {
		return out // nothing walked, so the tail is not worth trying either
	}

	// ...and backwards, to the last one
	for pos, n := size, 0; pos >= minBlock && n < maxWalk; n++ {
		start, ok := back(f, end, pos)
		if !ok {
			break
		}
		kind, _, body, ok := block(f, end, start)
		if !ok {
			break
		}
		if kind == blkEPB {
			out.Last = epbTime(f, end, body, units)
			break
		}
		pos = start
	}
	return out
}

// One block's type and total length, and the offset its body starts at. The
// length is checked here, so a caller can step by it.
func block(f *os.File, end binary.ByteOrder, pos int64) (kind, length uint32, body int64, ok bool) {
	var head [8]byte
	if _, err := f.ReadAt(head[:], pos); err != nil {
		return 0, 0, 0, false
	}
	kind = end.Uint32(head[0:4])
	length = end.Uint32(head[4:8])
	if length < minBlock || length > maxBlock || length%4 != 0 {
		return 0, 0, 0, false
	}
	return kind, length, pos + 8, true
}

// The block ending at pos, found through the length repeated at its end. Both
// copies of the length have to agree, which is the check that a half-written
// block fails.
func back(f *os.File, end binary.ByteOrder, pos int64) (int64, bool) {
	var tail [4]byte
	if _, err := f.ReadAt(tail[:], pos-4); err != nil {
		return 0, false
	}
	length := end.Uint32(tail[:])
	if length < minBlock || length > maxBlock || length%4 != 0 || int64(length) > pos {
		return 0, false
	}
	start := pos - int64(length)
	_, leading, _, ok := block(f, end, start)
	if !ok || leading != length {
		return 0, false
	}
	return start, true
}

// An Enhanced Packet Block's timestamp: interface id, then the 64-bit count of
// that interface's own units, high half first whatever the byte order.
func epbTime(f *os.File, end binary.ByteOrder, body int64, units []uint64) int64 {
	var b [12]byte
	if _, err := f.ReadAt(b[:], body); err != nil {
		return 0
	}
	unit := uint64(1e6) // if_tsresol's default, and all that is left for an
	if id := int(end.Uint32(b[0:4])); id < len(units) {
		unit = units[id] // interface whose description was in another section
	}
	ts := uint64(end.Uint32(b[4:8]))<<32 | uint64(end.Uint32(b[8:12]))
	if unit == 0 {
		return 0
	}
	// in two halves: a nanosecond capture of a date this side of the year 3000
	// overflows a uint64 if the whole count is multiplied by 1000 first
	return int64(ts/unit)*1000 + int64((ts%unit)*1000/unit)
}

// if_tsresol (option 9) of one interface description, as units per second. The
// high bit of the value picks the base: 2^-n rather than 10^-n.
func tsResol(f *os.File, end binary.ByteOrder, body int64, length uint32) uint64 {
	// body is LinkType(2) Reserved(2) SnapLen(4), then the options
	pos, limit := body+8, body+int64(length)-8-4
	for pos+4 <= limit {
		var opt [4]byte
		if _, err := f.ReadAt(opt[:], pos); err != nil {
			break
		}
		code, size := end.Uint16(opt[0:2]), int64(end.Uint16(opt[2:4]))
		if code == 0 { // opt_endofopt
			break
		}
		if code == 9 && size >= 1 {
			var v [1]byte
			if _, err := f.ReadAt(v[:], pos+4); err != nil {
				break
			}
			if v[0]&0x80 != 0 {
				return 1 << (v[0] & 0x7f)
			}
			return pow10(v[0])
		}
		pos += 4 + (size+3)/4*4 // an option's value is padded to four bytes
	}
	return 1e6
}

func pow10(n byte) uint64 {
	units := uint64(1)
	for i := byte(0); i < n && i < 19; i++ {
		units *= 10
	}
	return units
}

// A classic pcap says its byte order and its timestamp scale in one magic number,
// and then holds nothing that would let its tail be found: records carry their
// length at the front only, so the last frame is only reachable by walking every
// one of them. That is a read of the whole file - the thing this file exists to
// avoid - so a pcap gets its first frame and no more, and the list shows the
// file's mtime for the other end.
func pcapTimes(f *os.File, magic [4]byte) times {
	var end binary.ByteOrder
	nano := false
	switch binary.BigEndian.Uint32(magic[:]) {
	case 0xa1b2c3d4:
		end = binary.BigEndian
	case 0xd4c3b2a1:
		end = binary.LittleEndian
	case 0xa1b23c4d:
		end, nano = binary.BigEndian, true
	case 0x4d3cb2a1:
		end, nano = binary.LittleEndian, true
	default:
		return times{}
	}
	var rec [8]byte
	if _, err := f.ReadAt(rec[:], 24); err != nil { // past the 24-byte file header
		return times{}
	}
	unit := uint64(1e6)
	if nano {
		unit = 1e9
	}
	sec, frac := uint64(end.Uint32(rec[0:4])), uint64(end.Uint32(rec[4:8]))
	return times{First: int64(sec)*1000 + int64(frac*1000/unit)}
}

// -------------------------------------------------------------------- protos --

// The protocols of one capture, as the protocol-hierarchy tap names them - which
// is the spelling a display filter uses, so a name from this list can be typed
// into the filter box of the capture it came from.
type scan struct {
	Protos []string `json:"protos"`
	// the sample hit its frame limit, so these are the protocols of the
	// beginning of the capture and not necessarily of all of it
	Partial bool `json:"partial"`
}

// Results are kept by name, size and mtime together: a capture ptcpdump is still
// writing grows, and the protocols of the file as it is now are not the ones of
// the file as it was scanned.
type scanner struct {
	pool   *pool
	frames int

	mu   sync.Mutex // one scan at a time - see get()
	done map[string]scan
}

func newScanner(p *pool, frames int) *scanner {
	return &scanner{pool: p, frames: frames, done: map[string]scan{}}
}

func scanKey(name string, info os.FileInfo) string {
	return fmt.Sprintf("%s\x00%d\x00%d", name, info.Size(), info.ModTime().UnixNano())
}

// cached is the listing's half: what is known already, and never a scan.
func (s *scanner) cached(name string, info os.FileInfo) (scan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.done[scanKey(name, info)]
	return sc, ok
}

// get is the other half, and does scan. The lock is held across the whole thing
// on purpose: the UI asks for every unscanned file in the directory at once, and
// a dissection per core would take the disk and the CPU away from the capture the
// user is actually reading. One at a time also means the second asker for a file
// finds the first one's result in the map rather than starting its own.
func (s *scanner) get(name string, info os.FileInfo) (scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := scanKey(name, info)
	if sc, ok := s.done[k]; ok {
		return sc, nil
	}
	raw, err := s.pool.hierarchy(name, s.frames)
	if err != nil {
		return scan{}, err
	}
	sc := flatten(raw, s.frames)
	s.done[k] = sc
	return sc, nil
}

// The tap's answer is a tree: `frame` at the root, and a child per protocol that
// appeared inside its parent, with the frames and bytes each accounted for.
type phsNode struct {
	Proto  string    `json:"proto"`
	Frames int       `json:"frames"`
	Protos []phsNode `json:"protos"`
}

// The layers a capture is carried over rather than the ones it is about. Every
// capture has some of these and they are the same ones every time, so a list of
// captures that led with them would read the same on every row - they go last,
// where they are still there to be filtered on. Anything not named here is
// something a dissector found *in* the traffic, whatever its depth in the tree.
var carrier = map[string]bool{
	"eth": true, "ethertype": true, "sll": true, "sll2": true, "llc": true,
	"vlan": true, "ip": true, "ipv6": true, "udp": true, "tcp": true, "sctp": true,
	"ppp": true, "null": true, "raw": true, "loop": true, "nflog": true,
}

// flatten turns that tree into the list the UI shows and filters on, in the order
// that tells a reader what the capture holds: what was found in the traffic
// first, busiest first, and the layers it travelled over after them. `frame` is
// dropped, being the tap's name for a capture having frames at all - it matches
// everything and so distinguishes nothing.
//
// Ordering by frames rather than by depth on purpose: depth puts a single
// malformed packet, or one protobuf inside one HTTP body, ahead of the thousands
// of SIP messages the capture was taken for.
func flatten(raw json.RawMessage, limit int) scan {
	var taps struct {
		Taps []struct {
			Protos []phsNode `json:"protos"`
		} `json:"taps"`
	}
	if err := json.Unmarshal(raw, &taps); err != nil {
		return scan{}
	}

	frames := map[string]int{}
	loaded := 0
	var walk func(nodes []phsNode)
	walk = func(nodes []phsNode) {
		for _, n := range nodes {
			if n.Proto == "frame" {
				loaded = max(loaded, n.Frames)
			} else {
				// a protocol under two carriers - SIP over UDP and over TCP - is
				// listed once, with the frames of both
				frames[n.Proto] += n.Frames
			}
			walk(n.Protos)
		}
	}
	for _, tap := range taps.Taps {
		walk(tap.Protos)
	}

	protos := make([]string, 0, len(frames))
	for name := range frames {
		protos = append(protos, name)
	}
	slices.SortFunc(protos, func(a, b string) int {
		if carrier[a] != carrier[b] {
			if carrier[a] {
				return 1
			}
			return -1
		}
		if frames[a] != frames[b] {
			return frames[b] - frames[a]
		}
		return strings.Compare(a, b)
	})
	// the loaded count reaching the limit is the only sign there was more file
	// after it, sharkd having been told to stop rather than asked how much it left
	return scan{Protos: protos, Partial: loaded >= limit}
}
