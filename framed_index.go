// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
)

// This file implements a read-only index over a Snappy framed (stream)
// format source. The index records, for every chunk, its byte offset in the
// framed source, its chunk type and the range of decompressed bytes it
// produces. It enables random-access range reads that decompress only the
// chunks overlapping the requested range (still verifying the CRC of each
// decompressed chunk), without touching the rest of the stream.
//
// The index is bound to the exact source it was built from via the source
// length and a 64-bit digest; CheckSource (and therefore ReadRange) rejects
// a modified source.
//
// Only the framed format is indexed. A raw Snappy block (the Encode/Decode
// format) is rejected with ErrNotFramed, never silently treated as framed.

var (
	// ErrNotFramed reports that the input is not a Snappy framed stream
	// (it does not start with the stream identifier chunk). In particular,
	// raw Snappy block data is rejected with this error.
	ErrNotFramed = errors.New("snappy: not a framed stream")

	// ErrIndexSourceMismatch reports that a source does not match the
	// length and digest recorded in an Index.
	ErrIndexSourceMismatch = errors.New("snappy: source does not match index")

	// ErrRangeOutOfBounds reports that a requested decompressed range lies
	// outside the indexed stream.
	ErrRangeOutOfBounds = errors.New("snappy: range out of bounds")
)

// ChunkInfo describes a single chunk of a Snappy framed stream.
type ChunkInfo struct {
	// Offset is the byte offset of the chunk header within the framed
	// source.
	Offset int64
	// Type is the chunk type byte (e.g. 0x00 compressed data, 0x01
	// uncompressed data, 0xff stream identifier).
	Type byte
	// CompressedLen is the chunk length field: the number of payload bytes
	// following the 4-byte chunk header.
	CompressedLen int
	// UncompressedOffset is the offset, in the decompressed stream, of the
	// first byte produced by this chunk.
	UncompressedOffset int64
	// UncompressedLen is the number of decompressed bytes this chunk
	// produces. It is zero for non-data chunks (stream identifiers,
	// padding and skippable chunks).
	UncompressedLen int
}

// Data reports whether the chunk carries decompressed data (compressed or
// uncompressed data chunk types).
func (c ChunkInfo) Data() bool {
	return c.Type == chunkTypeCompressedData || c.Type == chunkTypeUncompressedData
}

// Index is a read-only index over a Snappy framed stream. It is bound to
// the source it was built from: CheckSource and ReadRange reject any source
// whose length or digest differs.
type Index struct {
	// SourceLen is the length in bytes of the indexed framed source.
	SourceLen int64
	// Digest is a 64-bit FNV-1a digest of the entire framed source.
	Digest uint64
	// TotalLen is the total decompressed length of the stream.
	TotalLen int64
	// Chunks lists every chunk of the stream in order, including
	// non-data chunks.
	Chunks []ChunkInfo
}

func sourceDigest(b []byte) uint64 {
	h := fnv.New64a()
	h.Write(b)
	return h.Sum64()
}

// IndexFramedStream parses src, which must be a complete Snappy framed
// stream, and returns an index over its chunks. The source is parsed
// structurally only: chunk payloads are not decompressed at index time.
//
// The stream must begin with the stream identifier chunk; anything else
// (including raw Snappy block data) yields ErrNotFramed. Reserved
// skippable chunks (types 0x80-0xfe) are recorded and skipped. Reserved
// unskippable chunks (types 0x02-0x7f) cannot be understood and yield
// ErrUnsupported.
func IndexFramedStream(src []byte) (*Index, error) {
	ix := &Index{
		SourceLen: int64(len(src)),
		Digest:    sourceDigest(src),
	}
	pos := 0
	var uoff int64
	readHeader := false
	for pos < len(src) {
		if len(src)-pos < chunkHeaderSize {
			return nil, ErrCorrupt
		}
		chunkType := src[pos]
		if !readHeader {
			if chunkType != chunkTypeStreamIdentifier {
				return nil, ErrNotFramed
			}
			readHeader = true
		}
		chunkLen := int(src[pos+1]) | int(src[pos+2])<<8 | int(src[pos+3])<<16
		if chunkLen > len(src)-pos-chunkHeaderSize {
			return nil, ErrCorrupt
		}
		ci := ChunkInfo{
			Offset:             int64(pos),
			Type:               chunkType,
			CompressedLen:      chunkLen,
			UncompressedOffset: uoff,
		}
		payload := src[pos+chunkHeaderSize : pos+chunkHeaderSize+chunkLen]
		switch chunkType {
		case chunkTypeCompressedData:
			// Section 4.2. Compressed data (chunk type 0x00).
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
			ci.UncompressedLen = n
			uoff += int64(n)

		case chunkTypeUncompressedData:
			// Section 4.3. Uncompressed data (chunk type 0x01).
			if chunkLen < checksumSize {
				return nil, ErrCorrupt
			}
			n := chunkLen - checksumSize
			if n > maxBlockSize {
				return nil, ErrCorrupt
			}
			ci.UncompressedLen = n
			uoff += int64(n)

		case chunkTypeStreamIdentifier:
			// Section 4.1. Stream identifier (chunk type 0xff).
			if chunkLen != len(magicBody) || string(payload) != magicBody {
				return nil, ErrCorrupt
			}

		default:
			if chunkType <= 0x7f {
				// Section 4.5. Reserved unskippable chunks (chunk
				// types 0x02-0x7f): we cannot understand them, so
				// indexing must fail.
				return nil, ErrUnsupported
			}
			// Section 4.4 Padding (chunk type 0xfe).
			// Section 4.6. Reserved skippable chunks (chunk types
			// 0x80-0xfd): recorded above, skipped here.
		}
		ix.Chunks = append(ix.Chunks, ci)
		pos += chunkHeaderSize + chunkLen
	}
	if !readHeader {
		return nil, ErrNotFramed
	}
	ix.TotalLen = uoff
	return ix, nil
}

// CheckSource verifies that src is the source this index was built from,
// by comparing its length and digest.
func (ix *Index) CheckSource(src []byte) error {
	if int64(len(src)) != ix.SourceLen || sourceDigest(src) != ix.Digest {
		return ErrIndexSourceMismatch
	}
	return nil
}

// ChunksForRange returns the data chunks whose decompressed output overlaps
// the range [off, off+length). Only these chunks need to be decompressed to
// serve a read of that range.
func (ix *Index) ChunksForRange(off, length int64) []ChunkInfo {
	if length <= 0 {
		return nil
	}
	end := off + length
	var out []ChunkInfo
	for _, c := range ix.Chunks {
		if !c.Data() {
			continue
		}
		if c.UncompressedOffset < end && off < c.UncompressedOffset+int64(c.UncompressedLen) {
			out = append(out, c)
		}
	}
	return out
}

// decodeChunk decompresses (or extracts) the data chunk c from src and
// verifies its CRC. It returns the full decompressed contents of the chunk.
func decodeChunk(src []byte, c ChunkInfo) ([]byte, error) {
	payload := src[c.Offset+chunkHeaderSize : c.Offset+chunkHeaderSize+int64(c.CompressedLen)]
	checksum := binary.LittleEndian.Uint32(payload[:checksumSize])
	payload = payload[checksumSize:]

	var decoded []byte
	switch c.Type {
	case chunkTypeCompressedData:
		var err error
		if decoded, err = Decode(nil, payload); err != nil {
			return nil, err
		}
	case chunkTypeUncompressedData:
		decoded = payload
	default:
		return nil, ErrCorrupt
	}
	if len(decoded) != c.UncompressedLen || crc(decoded) != checksum {
		return nil, ErrCorrupt
	}
	return decoded, nil
}

// ReadRange returns the decompressed bytes in the range [off, off+length)
// of the framed stream src, which must be the source ix was built from
// (otherwise ErrIndexSourceMismatch is returned).
//
// Only the chunks overlapping the range are decompressed, and the CRC of
// each decompressed chunk is verified. A range that extends beyond the end
// of the decompressed stream yields ErrRangeOutOfBounds.
func (ix *Index) ReadRange(src []byte, off, length int64) ([]byte, error) {
	if off < 0 || length < 0 || off+length > ix.TotalLen {
		return nil, ErrRangeOutOfBounds
	}
	if err := ix.CheckSource(src); err != nil {
		return nil, err
	}
	if length == 0 {
		return []byte{}, nil
	}
	end := off + length
	out := make([]byte, 0, length)
	for _, c := range ix.ChunksForRange(off, length) {
		decoded, err := decodeChunk(src, c)
		if err != nil {
			return nil, err
		}
		lo := off - c.UncompressedOffset
		if lo < 0 {
			lo = 0
		}
		hi := end - c.UncompressedOffset
		if hi > int64(len(decoded)) {
			hi = int64(len(decoded))
		}
		out = append(out, decoded[lo:hi]...)
	}
	return out, nil
}
