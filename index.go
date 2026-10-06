// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Chunk describes one chunk found while indexing a Snappy framed stream.
//
// Offset is the position of the 4-byte chunk header in the framed stream and
// Type is the chunk type byte (for example chunkTypeCompressedData). Length is
// the chunk payload length (excluding the 4-byte header). DataStart and
// DataEnd are the offsets in the decompressed (stream-level) data produced by
// the data chunks; chunks that do not carry data (the stream identifier,
// padding and other skippable chunks) report DataStart == DataEnd == 0.
type Chunk struct {
	Offset    int64
	Type      byte
	Length    int
	DataStart int64
	DataEnd   int64
}

// Index is a read-only index over a Snappy framed stream. It records every
// chunk's offset in the source, its type and the range of decompressed data
// produced by data chunks, so that an arbitrary range of the decompressed
// data can be read without scanning or decoding the whole stream.
//
// Building an index does not decompress any data chunk; only chunk headers and
// the varint-decoded length of compressed chunks are inspected. A ranged read
// decompresses only the data chunks the range intersects, but it still
// verifies the checksum of every such chunk.
//
// An index is bound to its source: it stores the source length and a SHA-256
// digest of the source bytes. Ranged reads reject a source whose length or
// digest no longer matches, so that a stale index can never return data for a
// modified stream.
//
// Index handles the Snappy stream (framing) format only, not the Snappy block
// format: NewIndex rejects bytes that do not start with the stream identifier
// chunk.
type Index struct {
	chunks     []Chunk
	blocks     []Chunk // data chunks only, in stream order
	decodedLen int64
	sourceLen  int64
	// sourceDigest is the SHA-256 digest of the indexed source bytes.
	sourceDigest [sha256.Size]byte
}

// ErrStaleIndex is returned by Index.ReadRange when the source bytes passed to
// it are not the ones the index was built from: their length or SHA-256 digest
// differs from the indexed source.
var ErrStaleIndex = errors.New("snappy: index does not match source data")

// maxChunkLen is the largest chunk payload the framing reader accepts. It is
// the size of Reader's working buffer.
const maxChunkLen = maxEncodedLenOfMaxBlockSize + checksumSize

// NewIndex builds a read-only index over the Snappy framed stream src. It
// scans chunk headers without decompressing data chunks.
//
// Unknown skippable chunks (chunk types 0x80-0xfd, including padding) are
// recorded and skipped; unignorable chunks that are not understood (chunk
// types 0x02-0x7f) cause ErrUnsupported. A truncated stream or otherwise
// malformed framing causes ErrCorrupt. Bytes in the Snappy block format are
// rejected with ErrCorrupt because they do not start with the stream
// identifier chunk.
func NewIndex(src []byte) (*Index, error) {
	idx := &Index{sourceLen: int64(len(src))}
	sum := sha256.Sum256(src)
	idx.sourceDigest = sum

	var (
		off       int64
		dataOff   int64
		seenMagic bool
	)
	for len(src) > 0 {
		if len(src) < chunkHeaderSize {
			return nil, ErrCorrupt
		}
		chunkType := src[0]
		chunkLen := int(src[1]) | int(src[2])<<8 | int(src[3])<<16
		// The framing format requires the very first chunk to be the stream
		// identifier. Check that before honoring the length field, so that
		// bytes in the Snappy block format are rejected outright rather than
		// parsed as chunks.
		if !seenMagic && chunkType != chunkTypeStreamIdentifier {
			return nil, ErrCorrupt
		}
		if chunkLen > maxChunkLen {
			return nil, ErrUnsupported
		}
		if len(src) < chunkHeaderSize+chunkLen {
			return nil, ErrCorrupt
		}
		payload := src[chunkHeaderSize : chunkHeaderSize+chunkLen]

		c := Chunk{Offset: off, Type: chunkType, Length: chunkLen}
		switch {
		case chunkType == chunkTypeStreamIdentifier:
			// Section 4.1. The stream identifier carries the 6-byte magic.
			seenMagic = true
			if chunkLen != len(magicBody) {
				return nil, ErrCorrupt
			}
			for i := 0; i < len(magicBody); i++ {
				if payload[i] != magicBody[i] {
					return nil, ErrCorrupt
				}
			}

		case chunkType == chunkTypeCompressedData:
			// Section 4.2. The payload is a 4-byte masked checksum followed by
			// a Snappy block. The declared decoded length is read from the
			// block's varint header, but the block itself is not decoded here.
			if chunkLen < checksumSize {
				return nil, ErrCorrupt
			}
			n, err := DecodedLen(payload[checksumSize:])
			if err != nil {
				return nil, err
			}
			if n > maxBlockSize {
				return nil, ErrCorrupt
			}
			c.DataStart = dataOff
			c.DataEnd = dataOff + int64(n)
			dataOff = c.DataEnd

		case chunkType == chunkTypeUncompressedData:
			// Section 4.3. The payload is a 4-byte masked checksum followed by
			// n bytes of uncompressed data.
			if chunkLen < checksumSize {
				return nil, ErrCorrupt
			}
			n := chunkLen - checksumSize
			if n > maxBlockSize {
				return nil, ErrCorrupt
			}
			c.DataStart = dataOff
			c.DataEnd = dataOff + int64(n)
			dataOff = c.DataEnd

		case chunkType <= 0x7f:
			// Section 4.5. Reserved unskippable chunks (0x02-0x7f): they must
			// be understood, and they are not, so the stream cannot be read.
			return nil, ErrUnsupported

		default:
			// Section 4.4 (padding, 0xfe) and section 4.6 (reserved skippable
			// chunks, 0x80-0xfd): record and skip without affecting data.
		}

		idx.chunks = append(idx.chunks, c)
		if c.DataEnd > c.DataStart {
			idx.blocks = append(idx.blocks, c)
		}
		step := int64(chunkHeaderSize + chunkLen)
		off += step
		src = src[step:]
	}
	if !seenMagic {
		return nil, ErrCorrupt
	}
	idx.decodedLen = dataOff
	return idx, nil
}

// Chunks returns the indexed chunks in stream order. The returned slice must
// not be modified by the caller.
func (x *Index) Chunks() []Chunk { return x.chunks }

// DecodedLen returns the total length of the decompressed stream, i.e. the
// sum of the data lengths of all data chunks.
func (x *Index) DecodedLen() int64 { return x.decodedLen }

// SourceLen returns the length of the framed stream the index was built from.
func (x *Index) SourceLen() int64 { return x.sourceLen }

// ReadRange returns the decompressed bytes at stream-data offsets [off,
// off+length), exactly as they would appear in the fully decompressed stream.
// The range may span multiple data chunks.
//
// src must be the same framed stream the index was built from; if its length
// or SHA-256 digest differs, ReadRange returns ErrStaleIndex. Only the data
// chunks intersected by the range are decompressed, but each of them is
// checksum-verified (a mismatch returns ErrCorrupt).
//
// A range outside [0, DecodedLen()) returns an error.
func (x *Index) ReadRange(src []byte, off, length int64) ([]byte, error) {
	if off < 0 || length < 0 || off > x.decodedLen || off+length < off || off+length > x.decodedLen {
		return nil, errors.New("snappy: read range is out of bounds")
	}
	if int64(len(src)) != x.sourceLen {
		return nil, ErrStaleIndex
	}
	if sum := sha256.Sum256(src); sum != x.sourceDigest {
		return nil, ErrStaleIndex
	}
	if length == 0 {
		return []byte{}, nil
	}

	needEnd := off + length
	// Find the first data chunk whose data ends strictly after off.
	lo, hi := 0, len(x.blocks)
	for lo < hi {
		mid := (lo + hi) / 2
		if x.blocks[mid].DataEnd <= off {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	first := lo
	if first == len(x.blocks) {
		return nil, errors.New("snappy: read range is out of bounds")
	}
	// Find the first data chunk starting at or after needEnd; chunks
	// [first, last) are exactly the ones intersected by the range.
	lo, hi = first, len(x.blocks)
	for lo < hi {
		mid := (lo + hi) / 2
		if x.blocks[mid].DataStart < needEnd {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	last := lo

	out := make([]byte, 0, length)
	decoded := make([]byte, maxBlockSize)
	for bi := first; bi < last; bi++ {
		b := x.blocks[bi]
		if b.Offset+int64(chunkHeaderSize) > int64(len(src)) {
			return nil, ErrCorrupt
		}
		hdr := src[b.Offset : b.Offset+chunkHeaderSize]
		chunkLen := int(hdr[1]) | int(hdr[2])<<8 | int(hdr[3])<<16
		if chunkLen != b.Length || b.Offset+int64(chunkHeaderSize+chunkLen) > int64(len(src)) {
			return nil, ErrCorrupt
		}
		payload := src[b.Offset+chunkHeaderSize : b.Offset+int64(chunkHeaderSize+chunkLen)]
		checksum := binary.LittleEndian.Uint32(payload[:checksumSize])

		var block []byte
		switch b.Type {
		case chunkTypeCompressedData:
			d, err := Decode(decoded[:0], payload[checksumSize:])
			if err != nil {
				return nil, err
			}
			if int64(len(d)) != b.DataEnd-b.DataStart {
				return nil, ErrCorrupt
			}
			if crc(d) != checksum {
				return nil, ErrCorrupt
			}
			block = d
		case chunkTypeUncompressedData:
			data := payload[checksumSize:]
			if int64(len(data)) != b.DataEnd-b.DataStart {
				return nil, ErrCorrupt
			}
			if crc(data) != checksum {
				return nil, ErrCorrupt
			}
			block = data
		default:
			return nil, ErrCorrupt
		}

		// Intersect the requested range with this chunk's data range.
		s, e := b.DataStart, b.DataEnd
		if s < off {
			s = off
		}
		if e > needEnd {
			e = needEnd
		}
		out = append(out, block[s-b.DataStart:e-b.DataStart]...)
	}
	if int64(len(out)) != length {
		return nil, ErrCorrupt
	}
	return out, nil
}
