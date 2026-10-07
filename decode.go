// Copyright 2011 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	// ErrCorrupt reports that the input is invalid.
	ErrCorrupt = errors.New("snappy: corrupt input")
	// ErrTooLarge reports that the uncompressed length is too large.
	ErrTooLarge = errors.New("snappy: decoded block is too large")
	// ErrUnsupported reports that the input isn't supported.
	ErrUnsupported = errors.New("snappy: unsupported input")

	errUnsupportedLiteralLength = errors.New("snappy: unsupported literal length")
)

// DecodedLen returns the length of the decoded block.
func DecodedLen(src []byte) (int, error) {
	v, _, err := decodedLen(src)
	return v, err
}

// decodedLen returns the length of the decoded block and the number of bytes
// that the length header occupied.
func decodedLen(src []byte) (blockLen, headerLen int, err error) {
	v, n := binary.Uvarint(src)
	if n <= 0 || n > 5 || v > 0xffffffff {
		return 0, 0, ErrCorrupt
	}

	const wordSize = 32 << (^uint(0) >> 32 & 1)
	if wordSize == 32 && v > 0x7fffffff {
		return 0, 0, ErrTooLarge
	}
	return int(v), n, nil
}

const (
	decodeErrCodeCorrupt                  = 1
	decodeErrCodeUnsupportedLiteralLength = 2
)

// Decode returns the decoded form of src. The returned slice may be a sub-
// slice of dst if dst was large enough to hold the entire decoded block.
// Otherwise, a newly allocated slice will be returned.
//
// The dst and src must not overlap. It is valid to pass a nil dst.
//
// Decode handles the Snappy block format, not the Snappy stream format.
func Decode(dst, src []byte) ([]byte, error) {
	dLen, s, err := decodedLen(src)
	if err != nil {
		return nil, err
	}
	if dLen <= len(dst) {
		dst = dst[:dLen]
	} else {
		dst = make([]byte, dLen)
	}
	switch decode(dst, src[s:]) {
	case 0:
		return dst, nil
	case decodeErrCodeUnsupportedLiteralLength:
		return nil, errUnsupportedLiteralLength
	}
	return nil, ErrCorrupt
}

// NewReader returns a new Reader that decompresses from r, using the framing
// format described at
// https://github.com/google/snappy/blob/master/framing_format.txt
func NewReader(r io.Reader) *Reader {
	return &Reader{
		r:       r,
		decoded: make([]byte, maxBlockSize),
		buf:     make([]byte, maxEncodedLenOfMaxBlockSize+checksumSize),
	}
}

// FrameEventType identifies the kind of a stream frame observed by a
// FrameObserver.
type FrameEventType int

const (
	// FrameEventCompressed is a compressed data chunk (chunk type 0x00).
	FrameEventCompressed FrameEventType = iota
	// FrameEventUncompressed is an uncompressed data chunk (chunk type 0x01).
	FrameEventUncompressed
	// FrameEventSkippable is a padding chunk (chunk type 0xfe) or a reserved
	// skippable chunk (chunk types 0x80-0xfd).
	FrameEventSkippable
)

// String returns a human-readable name for the frame event type.
func (t FrameEventType) String() string {
	switch t {
	case FrameEventCompressed:
		return "compressed"
	case FrameEventUncompressed:
		return "uncompressed"
	case FrameEventSkippable:
		return "skippable"
	}
	return "unknown"
}

// FrameEvent describes a single stream frame observed by a Reader while
// decoding. Events are delivered in wire order.
type FrameEvent struct {
	// Seq is the zero-based sequence number of the frame, counting data and
	// skippable frames. The stream identifier chunk is not counted. A frame
	// that fails checksum verification keeps its sequence number.
	Seq int
	// Type classifies the frame as compressed data, uncompressed data or
	// skippable.
	Type FrameEventType
	// VerifiedBytes is the cumulative number of decoded output bytes from
	// data frames whose checksum verified successfully, including this
	// frame if it is one of them. Skippable frames and frames that fail
	// verification do not contribute to this total.
	VerifiedBytes int64
	// Decoded is a snapshot copy of the frame's decoded payload for data
	// frames, and nil for skippable frames. It is a private copy made for
	// the observer: mutating it does not affect the Reader's internal
	// buffers or the bytes returned by Read.
	Decoded []byte
	// Err is non-nil if the frame failed checksum verification, in which
	// case the Reader will report the same error from Read.
	Err error
}

// FrameObserver receives a FrameEvent for every data or skippable frame a
// Reader processes, including frames that fail checksum verification.
type FrameObserver interface {
	ObserveFrame(FrameEvent)
}

// FrameObserverFunc adapts an ordinary function to a FrameObserver.
type FrameObserverFunc func(FrameEvent)

// ObserveFrame calls f(e).
func (f FrameObserverFunc) ObserveFrame(e FrameEvent) { f(e) }

// Reader is an io.Reader that can read Snappy-compressed bytes.
//
// Reader handles the Snappy stream format, not the Snappy block format.
type Reader struct {
	r       io.Reader
	err     error
	decoded []byte
	buf     []byte
	// decoded[i:j] contains decoded bytes that have not yet been passed on.
	i, j       int
	readHeader bool

	// observer, if non-nil, is notified of every data or skippable frame.
	observer FrameObserver
	// frameSeq is the sequence number of the next observed frame.
	frameSeq int
	// verified is the cumulative decoded size of verified data frames.
	verified int64
}

// SetFrameObserver registers obs to receive a FrameEvent for every data or
// skippable frame the Reader processes. Passing nil disables observation.
// The observer is retained across Reset calls.
func (r *Reader) SetFrameObserver(obs FrameObserver) {
	r.observer = obs
}

// observeFrame notifies the observer, if any, of a single frame. The decoded
// payload is copied so the observer never sees a mutable internal buffer.
func (r *Reader) observeFrame(typ FrameEventType, decoded []byte, err error) {
	r.frameSeq++
	if r.observer == nil {
		return
	}
	var snapshot []byte
	if decoded != nil {
		snapshot = make([]byte, len(decoded))
		copy(snapshot, decoded)
	}
	r.observer.ObserveFrame(FrameEvent{
		Seq:           r.frameSeq - 1,
		Type:          typ,
		VerifiedBytes: r.verified,
		Decoded:       snapshot,
		Err:           err,
	})
}

// Reset discards any buffered data, resets all state, and switches the Snappy
// reader to read from r. This permits reusing a Reader rather than allocating
// a new one.
func (r *Reader) Reset(reader io.Reader) {
	r.r = reader
	r.err = nil
	r.i = 0
	r.j = 0
	r.readHeader = false
	r.frameSeq = 0
	r.verified = 0
}

func (r *Reader) readFull(p []byte, allowEOF bool) (ok bool) {
	if _, r.err = io.ReadFull(r.r, p); r.err != nil {
		if r.err == io.ErrUnexpectedEOF || (r.err == io.EOF && !allowEOF) {
			r.err = ErrCorrupt
		}
		return false
	}
	return true
}

func (r *Reader) fill() error {
	for r.i >= r.j {
		if !r.readFull(r.buf[:4], true) {
			return r.err
		}
		chunkType := r.buf[0]
		if !r.readHeader {
			if chunkType != chunkTypeStreamIdentifier {
				r.err = ErrCorrupt
				return r.err
			}
			r.readHeader = true
		}
		chunkLen := int(r.buf[1]) | int(r.buf[2])<<8 | int(r.buf[3])<<16
		if chunkLen > len(r.buf) {
			r.err = ErrUnsupported
			return r.err
		}

		// The chunk types are specified at
		// https://github.com/google/snappy/blob/master/framing_format.txt
		switch chunkType {
		case chunkTypeCompressedData:
			// Section 4.2. Compressed data (chunk type 0x00).
			if chunkLen < checksumSize {
				r.err = ErrCorrupt
				return r.err
			}
			buf := r.buf[:chunkLen]
			if !r.readFull(buf, false) {
				return r.err
			}
			checksum := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
			buf = buf[checksumSize:]

			n, err := DecodedLen(buf)
			if err != nil {
				r.err = err
				return r.err
			}
			if n > len(r.decoded) {
				r.err = ErrCorrupt
				return r.err
			}
			if _, err := Decode(r.decoded, buf); err != nil {
				r.err = err
				return r.err
			}
			if crc(r.decoded[:n]) != checksum {
				r.observeFrame(FrameEventCompressed, r.decoded[:n], ErrCorrupt)
				r.err = ErrCorrupt
				return r.err
			}
			r.verified += int64(n)
			r.observeFrame(FrameEventCompressed, r.decoded[:n], nil)
			r.i, r.j = 0, n
			continue

		case chunkTypeUncompressedData:
			// Section 4.3. Uncompressed data (chunk type 0x01).
			if chunkLen < checksumSize {
				r.err = ErrCorrupt
				return r.err
			}
			buf := r.buf[:checksumSize]
			if !r.readFull(buf, false) {
				return r.err
			}
			checksum := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
			// Read directly into r.decoded instead of via r.buf.
			n := chunkLen - checksumSize
			if n > len(r.decoded) {
				r.err = ErrCorrupt
				return r.err
			}
			if !r.readFull(r.decoded[:n], false) {
				return r.err
			}
			if crc(r.decoded[:n]) != checksum {
				r.observeFrame(FrameEventUncompressed, r.decoded[:n], ErrCorrupt)
				r.err = ErrCorrupt
				return r.err
			}
			r.verified += int64(n)
			r.observeFrame(FrameEventUncompressed, r.decoded[:n], nil)
			r.i, r.j = 0, n
			continue

		case chunkTypeStreamIdentifier:
			// Section 4.1. Stream identifier (chunk type 0xff).
			if chunkLen != len(magicBody) {
				r.err = ErrCorrupt
				return r.err
			}
			if !r.readFull(r.buf[:len(magicBody)], false) {
				return r.err
			}
			for i := 0; i < len(magicBody); i++ {
				if r.buf[i] != magicBody[i] {
					r.err = ErrCorrupt
					return r.err
				}
			}
			continue
		}

		if chunkType <= 0x7f {
			// Section 4.5. Reserved unskippable chunks (chunk types 0x02-0x7f).
			r.err = ErrUnsupported
			return r.err
		}
		// Section 4.4 Padding (chunk type 0xfe).
		// Section 4.6. Reserved skippable chunks (chunk types 0x80-0xfd).
		if !r.readFull(r.buf[:chunkLen], false) {
			return r.err
		}
		r.observeFrame(FrameEventSkippable, nil, nil)
	}

	return nil
}

// Read satisfies the io.Reader interface.
func (r *Reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	if err := r.fill(); err != nil {
		return 0, err
	}

	n := copy(p, r.decoded[r.i:r.j])
	r.i += n
	return n, nil
}

// ReadByte satisfies the io.ByteReader interface.
func (r *Reader) ReadByte() (byte, error) {
	if r.err != nil {
		return 0, r.err
	}

	if err := r.fill(); err != nil {
		return 0, err
	}

	c := r.decoded[r.i]
	r.i++
	return c, nil
}
