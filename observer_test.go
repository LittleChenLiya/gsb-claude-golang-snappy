// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

// frame builds a framing-format chunk (4-byte header followed by body).
func frame(typ byte, body []byte) []byte {
	n := len(body)
	return append([]byte{
		typ,
		byte(n >> 0),
		byte(n >> 8),
		byte(n >> 16),
	}, body...)
}

// dataFrame builds a compressed or uncompressed data chunk with a correct
// checksum.
func dataFrame(compressed bool, payload []byte) []byte {
	var body, data []byte
	if compressed {
		data = Encode(nil, payload)
	} else {
		data = payload
	}
	body = make([]byte, 0, checksumSize+len(data))
	c := crc(payload)
	body = append(body, byte(c>>0), byte(c>>8), byte(c>>16), byte(c>>24))
	body = append(body, data...)
	if compressed {
		return frame(chunkTypeCompressedData, body)
	}
	return frame(chunkTypeUncompressedData, body)
}

// TestReaderFrameObserver wires three kinds of small frames (compressed data,
// uncompressed data and a skippable/padding frame) followed by a compressed
// data frame with a corrupted CRC, and checks the observed event types, the
// running total and the frame number carried by the CRC error. It also checks
// that mutating the snapshots handed to the observer does not change what
// Read returns.
func TestReaderFrameObserver(t *testing.T) {
	p1 := []byte("hello")  // frame 1: compressed data
	p2 := []byte("world!") // frame 2: uncompressed data
	// frame 3: skippable padding carrying payload the observer must not see.
	skippable := frame(chunkTypePadding, []byte("pad"))
	// frame 4: compressed data with a deliberately broken checksum.
	bad := dataFrame(true, []byte("oops"))
	bad[4] ^= 0xff

	stream := bytes.NewReader(nil)
	streamBytes := bytes.Join([][]byte{
		[]byte(magicChunk),
		dataFrame(true, p1),
		dataFrame(false, p2),
		skippable,
		bad,
	}, nil)
	stream.Reset(streamBytes)

	var events []FrameEvent
	r := NewReader(stream).SetFrameObserver(FrameObserverFunc(func(e FrameEvent) {
		events = append(events, e)
	}))

	got, err := ioutil.ReadAll(r)
	if err != ErrCorrupt {
		t.Fatalf("ReadAll error: got %v, want %v", err, ErrCorrupt)
	}
	if want := "helloworld!"; string(got) != want {
		t.Fatalf("decoded output: got %q, want %q", got, want)
	}

	wantKinds := []FrameKind{
		FrameCompressedData,
		FrameUncompressedData,
		FrameSkippable,
		FrameCompressedData,
	}
	if len(events) != len(wantKinds) {
		t.Fatalf("observed %d events, want %d: %+v", len(events), len(wantKinds), events)
	}
	for i, k := range wantKinds {
		if events[i].Kind != k {
			t.Errorf("event %d Kind: got %s, want %s", i, events[i].Kind, k)
		}
		if events[i].FrameNo != i+1 {
			t.Errorf("event %d FrameNo: got %d, want %d", i, events[i].FrameNo, i+1)
		}
	}

	// Running totals: only verified data frames accumulate.
	wantTotal := []int64{5, 11, 11, 11}
	for i, want := range wantTotal {
		if events[i].Total != want {
			t.Errorf("event %d Total: got %d, want %d", i, events[i].Total, want)
		}
	}
	wantN := []int{5, 6, 0, 4}
	for i, want := range wantN {
		if events[i].N != want {
			t.Errorf("event %d N: got %d, want %d", i, events[i].N, want)
		}
	}
	if string(events[0].Data) != "hello" || string(events[1].Data) != "world!" {
		t.Errorf("verified payloads: got %q and %q", events[0].Data, events[1].Data)
	}
	// Skippable and failed-CRC frames expose no payload.
	if events[2].Data != nil || events[3].Data != nil {
		t.Errorf("Data must be nil for skippable and bad-CRC events")
	}
	if !events[3].CRCError || events[0].CRCError || events[1].CRCError || events[2].CRCError {
		t.Errorf("CRCError flags: %+v", events)
	}
}

// TestReaderFrameObserverSnapshotIsolation verifies that the observer never
// gets a mutable alias of the Reader's internal buffers: clobbering every
// observed snapshot must not change the bytes produced by Read.
func TestReaderFrameObserverSnapshotIsolation(t *testing.T) {
	p1, p2 := []byte("aaaaa"), []byte("bbbbbb")
	stream := bytes.NewReader(bytes.Join([][]byte{
		[]byte(magicChunk),
		dataFrame(true, p1),
		dataFrame(false, p2),
		frame(chunkTypePadding, []byte("xx")),
	}, nil))

	r := NewReader(stream).SetFrameObserver(FrameObserverFunc(func(e FrameEvent) {
		for i := range e.Data {
			e.Data[i] = 'Z' // mutate the snapshot; must be a private copy
		}
	}))

	got, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := "aaaaabbbbbb"; string(got) != want {
		t.Fatalf("Read output after snapshot mutation: got %q, want %q", got, want)
	}
}

// TestReaderFrameObserverRegression is the short regression example for the
// original interface: reading the same stream without an observer must yield
// exactly the concatenation of the verified payloads reported by the
// observer, stopping with ErrCorrupt at the bad-CRC frame.
func TestReaderFrameObserverRegression(t *testing.T) {
	p1, p2 := []byte("hello"), []byte("world!")
	raw := bytes.Join([][]byte{
		[]byte(magicChunk),
		dataFrame(true, p1),
		dataFrame(false, p2),
		frame(0x80, []byte("skip")), // reserved skippable chunk
	}, nil)
	// A bad-CRC uncompressed frame at the tail.
	bad := dataFrame(false, []byte("nope"))
	bad[4] ^= 0x01
	raw = append(raw, bad...)

	// Original interface: plain NewReader, no observer installed.
	plain, plainErr := ioutil.ReadAll(NewReader(strings.NewReader(string(raw))))
	if plainErr != ErrCorrupt {
		t.Fatalf("plain read error: got %v, want %v", plainErr, ErrCorrupt)
	}

	// Observed run.
	var observed bytes.Buffer
	var last FrameEvent
	r := NewReader(bytes.NewReader(raw)).SetFrameObserver(FrameObserverFunc(func(e FrameEvent) {
		last = e
		if !e.CRCError && e.Kind != FrameSkippable {
			observed.Write(e.Data)
		}
	}))
	decoded, err := ioutil.ReadAll(r)
	if err != ErrCorrupt {
		t.Fatalf("observed read error: got %v, want %v", err, ErrCorrupt)
	}

	if string(plain) != string(decoded) {
		t.Fatalf("plain %q != observed %q", plain, decoded)
	}
	if observed.String() != string(decoded) {
		t.Fatalf("observed verified payloads %q != decoded %q", observed.String(), decoded)
	}
	if want := "helloworld!"; observed.String() != want {
		t.Fatalf("regression payload: got %q, want %q", observed.String(), want)
	}
	if !last.CRCError || last.FrameNo != 4 || last.N != 4 || last.Total != 11 {
		t.Fatalf("bad-CRC event: %+v, want FrameNo=4 N=4 Total=11 CRCError=true", last)
	}
}
