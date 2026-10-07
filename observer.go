// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

// FrameKind identifies the kind of a framing-format chunk reported to a
// FrameObserver.
type FrameKind int

const (
	// FrameCompressedData is a verified compressed data chunk (wire chunk
	// type 0x00).
	FrameCompressedData FrameKind = iota
	// FrameUncompressedData is a verified uncompressed data chunk (wire
	// chunk type 0x01).
	FrameUncompressedData
	// FrameSkippable is a padding or reserved skippable chunk (wire chunk
	// types 0x80-0xfe), which produces no output.
	FrameSkippable
)

func (k FrameKind) String() string {
	switch k {
	case FrameCompressedData:
		return "compressed-data"
	case FrameUncompressedData:
		return "uncompressed-data"
	case FrameSkippable:
		return "skippable"
	}
	return "unknown"
}

// FrameEvent is a read-only snapshot of one framing-format chunk as observed
// by a Reader.
//
// FrameNo is the 1-based ordinal of the observed chunk, counting compressed
// data, uncompressed data and skippable chunks but not the mandatory stream
// identifier. The numbering is preserved even when a chunk fails checksum
// verification.
//
// N is the number of decompressed payload bytes for a data chunk, and zero
// for a skippable chunk. Total is the running total of bytes of verified data
// chunks; a chunk whose CRC check fails does not add to Total.
//
// Data holds an independent copy of the verified, decompressed payload of a
// data chunk. It is nil for skippable chunks and for data chunks that failed
// CRC verification. The copy is owned by the observer: mutating it never
// affects the bytes returned by subsequent Read calls, and the observer can
// never reach the Reader's internal buffers.
type FrameEvent struct {
	Kind    FrameKind
	FrameNo int
	N       int
	Total   int64
	Data    []byte
	// CRCError reports whether the data chunk failed checksum verification.
	// When true, Data is nil, N still reports the chunk's payload length and
	// the Reader's Read method will return ErrCorrupt.
	CRCError bool
}

// FrameObserver observes framing-format chunks as a Reader verifies them.
// Observe is called synchronously while the Reader is filling its buffer,
// once per compressed data, uncompressed data or skippable chunk. It must not
// call back into the Reader.
type FrameObserver interface {
	Observe(FrameEvent)
}

// FrameObserverFunc adapts a function to the FrameObserver interface.
type FrameObserverFunc func(FrameEvent)

// Observe implements FrameObserver.
func (f FrameObserverFunc) Observe(e FrameEvent) { f(e) }

// SetFrameObserver installs (or, with nil, removes) the FrameObserver used to
// report framing-format chunks. It returns the Reader so calls can be chained.
//
// The observer sees compressed data, uncompressed data and skippable chunks
// in wire order. Only data chunks whose CRC check succeeds contribute to the
// reported running total and expose a copy of their payload; a failed CRC is
// still reported with its frame number so the bad chunk can be located.
func (r *Reader) SetFrameObserver(o FrameObserver) *Reader {
	r.observer = o
	return r
}

// observe reports a chunk to the installed observer, if any. For a verified
// data chunk, a fresh copy of the payload is passed so the observer cannot
// alias the Reader's internal decoded buffer.
func (r *Reader) observe(kind FrameKind, n int, data []byte, crcError bool) {
	if r.observer == nil {
		return
	}
	r.frameNo++
	e := FrameEvent{
		Kind:     kind,
		FrameNo:  r.frameNo,
		N:        n,
		Total:    r.observedTotal,
		CRCError: crcError,
	}
	if !crcError && kind != FrameSkippable {
		e.Data = make([]byte, len(data))
		copy(e.Data, data)
	}
	r.observer.Observe(e)
}
