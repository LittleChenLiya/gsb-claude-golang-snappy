// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// observerTestPayloads are the decoded payloads of the three data frames used
// by the frame-observation test and the ExampleReader regression: a
// compressed frame, an uncompressed frame and (after a skippable frame)
// another compressed frame.
var observerTestPayloads = [][]byte{
	[]byte("hello, "),
	[]byte("snappy "),
	[]byte("world"),
}

// frameChunk serializes one framing-format chunk.
func frameChunk(chunkType byte, payload []byte) []byte {
	b := make([]byte, chunkHeaderSize+len(payload))
	b[0] = chunkType
	b[1] = byte(len(payload))
	b[2] = byte(len(payload) >> 8)
	b[3] = byte(len(payload) >> 16)
	copy(b[chunkHeaderSize:], payload)
	return b
}

// compressedFrame builds a compressed data chunk for src. If corruptCRC is
// true, the embedded checksum is invalidated.
func compressedFrame(src []byte, corruptCRC bool) []byte {
	sum := crc(src)
	if corruptCRC {
		sum ^= 0xa5a5a5a5
	}
	enc := Encode(nil, src)
	payload := make([]byte, checksumSize+len(enc))
	binary.LittleEndian.PutUint32(payload, sum)
	copy(payload[checksumSize:], enc)
	return frameChunk(chunkTypeCompressedData, payload)
}

// uncompressedFrame builds an uncompressed data chunk for src.
func uncompressedFrame(src []byte) []byte {
	payload := make([]byte, checksumSize+len(src))
	binary.LittleEndian.PutUint32(payload, crc(src))
	copy(payload[checksumSize:], src)
	return frameChunk(chunkTypeUncompressedData, payload)
}

// observerTestStream builds a small in-memory stream: stream identifier,
// compressed frame, uncompressed frame, skippable frame, then a final
// compressed frame whose CRC is corrupted iff corrupt is true.
func observerTestStream(corrupt bool) []byte {
	var b []byte
	b = append(b, magicChunk...)
	b = append(b, compressedFrame(observerTestPayloads[0], false)...)
	b = append(b, uncompressedFrame(observerTestPayloads[1])...)
	b = append(b, frameChunk(0x80, []byte("ignore me"))...) // reserved skippable
	b = append(b, compressedFrame(observerTestPayloads[2], corrupt)...)
	return b
}

// TestReaderFrameObserver feeds the Reader a stream of compressed,
// uncompressed and skippable frames followed by a frame with a bad CRC, and
// checks the observed event types, cumulative verified byte counts and the
// sequence number of the failing frame. It also mutates the Decoded snapshot
// handed to the callback and verifies that Read output is unaffected.
func TestReaderFrameObserver(t *testing.T) {
	type event struct {
		seq       int
		typ       FrameEventType
		verified  int64
		decoded   string
		hasDecode bool
		err       error
	}
	var events []event

	r := NewReader(bytes.NewReader(observerTestStream(true)))
	r.SetFrameObserver(FrameObserverFunc(func(e FrameEvent) {
		ev := event{seq: e.Seq, typ: e.Type, verified: e.VerifiedBytes, err: e.Err}
		if e.Decoded != nil {
			ev.hasDecode = true
			ev.decoded = string(e.Decoded)
			// Scribble over the snapshot we were given. The Reader must
			// not observe this through its own buffers.
			for i := range e.Decoded {
				e.Decoded[i] = 'X'
			}
		}
		events = append(events, ev)
	}))

	got, err := io.ReadAll(r)
	if err != ErrCorrupt {
		t.Fatalf("ReadAll error = %v, want %v", err, ErrCorrupt)
	}
	// The bad-CRC frame yields no output; the snapshot scribbling above must
	// not have leaked into the decoded bytes.
	if want := "hello, snappy "; string(got) != want {
		t.Errorf("decoded output = %q, want %q", got, want)
	}

	n0, n1 := len(observerTestPayloads[0]), len(observerTestPayloads[1])
	want := []event{
		{seq: 0, typ: FrameEventCompressed, verified: int64(n0), decoded: "hello, ", hasDecode: true},
		{seq: 1, typ: FrameEventUncompressed, verified: int64(n0 + n1), decoded: "snappy ", hasDecode: true},
		{seq: 2, typ: FrameEventSkippable, verified: int64(n0 + n1)},
		{seq: 3, typ: FrameEventCompressed, verified: int64(n0 + n1), decoded: "world", hasDecode: true, err: ErrCorrupt},
	}
	if len(events) != len(want) {
		t.Fatalf("got %d events, want %d: %+v", len(events), len(want), events)
	}
	for i, w := range want {
		if events[i] != w {
			t.Errorf("event[%d] = %+v, want %+v", i, events[i], w)
		}
	}
	if events[3].seq != 3 || events[3].err != ErrCorrupt {
		t.Errorf("bad-CRC frame: seq = %d, err = %v; want seq 3 with %v",
			events[3].seq, events[3].err, ErrCorrupt)
	}
}

// TestReaderFrameObserverTempFile replays the all-good stream from a small
// temporary file fixture and checks that the cumulative verified byte count
// matches the plain decoded output.
func TestReaderFrameObserverTempFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frames.sz")
	if err := os.WriteFile(path, observerTestStream(false), 0666); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var lastVerified int64
	r := NewReader(f)
	r.SetFrameObserver(FrameObserverFunc(func(e FrameEvent) {
		lastVerified = e.VerifiedBytes
	}))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := "hello, snappy world"; string(got) != want {
		t.Errorf("decoded output = %q, want %q", got, want)
	}
	if int(lastVerified) != len(got) {
		t.Errorf("final VerifiedBytes = %d, want %d (len of decoded output)", lastVerified, len(got))
	}
}

// ExampleReader is a short regression for the original (unobserved) Reader
// interface. It decodes the same three data frames used by the observer
// test, so the results line up: the verified cumulative byte count of the
// good frames equals the length of this output.
func ExampleReader() {
	got, err := io.ReadAll(NewReader(bytes.NewReader(observerTestStream(false))))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("%s (%d bytes)\n", got, len(got))
	// Output: hello, snappy world (19 bytes)
}
