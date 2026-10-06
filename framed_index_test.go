// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// appendCompressedChunk appends a compressed-data framed chunk for p to buf.
func appendCompressedChunk(buf, p []byte) []byte {
	enc := Encode(nil, p)
	chunkLen := checksumSize + len(enc)
	buf = append(buf, chunkTypeCompressedData,
		byte(chunkLen), byte(chunkLen>>8), byte(chunkLen>>16))
	var cs [4]byte
	binary.LittleEndian.PutUint32(cs[:], crc(p))
	buf = append(buf, cs[:]...)
	return append(buf, enc...)
}

// framedTestStream builds a framed stream whose data chunks are parts.
func framedTestStream(parts ...[]byte) []byte {
	buf := append([]byte(nil), magicChunk...)
	for _, p := range parts {
		buf = appendCompressedChunk(buf, p)
	}
	return buf
}

func indexTestParts() (d1, d2, d3 []byte) {
	d1 = bytes.Repeat([]byte("alpha-"), 200) // 1200 bytes
	d2 = bytes.Repeat([]byte("BETA--"), 200) // 1200 bytes
	d3 = bytes.Repeat([]byte("gamma_"), 200) // 1200 bytes
	return d1, d2, d3
}

func TestFramedIndexMiddleOfThree(t *testing.T) {
	d1, d2, d3 := indexTestParts()
	src := framedTestStream(d1, d2, d3)

	ix, err := IndexFramedStream(src)
	if err != nil {
		t.Fatalf("IndexFramedStream: %v", err)
	}
	if got, want := len(ix.Chunks), 4; got != want {
		t.Fatalf("len(ix.Chunks) = %d, want %d", got, want)
	}
	if got, want := ix.TotalLen, int64(len(d1)+len(d2)+len(d3)); got != want {
		t.Fatalf("ix.TotalLen = %d, want %d", got, want)
	}

	// Read only the middle chunk's range.
	got, err := ix.ReadRange(src, int64(len(d1)), int64(len(d2)))
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if !bytes.Equal(got, d2) {
		t.Fatal("ReadRange of middle chunk range did not return the middle chunk bytes")
	}

	// Only the middle chunk overlaps the range.
	overlapping := ix.ChunksForRange(int64(len(d1)), int64(len(d2)))
	if got, want := len(overlapping), 1; got != want {
		t.Fatalf("len(ChunksForRange) = %d, want %d", got, want)
	}
	if overlapping[0].UncompressedOffset != int64(len(d1)) {
		t.Fatalf("overlapping chunk offset = %d, want %d",
			overlapping[0].UncompressedOffset, len(d1))
	}
}

func TestFramedIndexCrossChunkRange(t *testing.T) {
	d1, d2, d3 := indexTestParts()
	src := framedTestStream(d1, d2, d3)

	ix, err := IndexFramedStream(src)
	if err != nil {
		t.Fatalf("IndexFramedStream: %v", err)
	}

	// A range spanning from the middle of chunk 1 to the middle of chunk 3.
	off := int64(len(d1) / 2)
	end := int64(len(d1) + len(d2) + len(d3)/2)
	got, err := ix.ReadRange(src, off, end-off)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	want := append(append(append([]byte(nil), d1[len(d1)/2:]...), d2...), d3[:len(d3)/2]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("cross-chunk range mismatch: got %d bytes, want %d", len(got), len(want))
	}
	if n := len(ix.ChunksForRange(off, end-off)); n != 3 {
		t.Fatalf("len(ChunksForRange) = %d, want 3", n)
	}
}

func TestFramedIndexRejectsModifiedSource(t *testing.T) {
	d1, d2, d3 := indexTestParts()
	src := framedTestStream(d1, d2, d3)

	ix, err := IndexFramedStream(src)
	if err != nil {
		t.Fatalf("IndexFramedStream: %v", err)
	}

	// Flip one byte in a chunk the read does not even touch: the index is
	// bound to the whole source, so the old index must reject it.
	bad := append([]byte(nil), src...)
	bad[len(bad)-1] ^= 0xff
	if _, err := ix.ReadRange(bad, int64(len(d1)), int64(len(d2))); !errors.Is(err, ErrIndexSourceMismatch) {
		t.Fatalf("ReadRange with modified source: got %v, want ErrIndexSourceMismatch", err)
	}

	// A truncated source must also be rejected.
	if _, err := ix.ReadRange(src[:len(src)-1], 0, 1); !errors.Is(err, ErrIndexSourceMismatch) {
		t.Fatalf("ReadRange with truncated source: got %v, want ErrIndexSourceMismatch", err)
	}
}

func TestFramedIndexStillVerifiesCRC(t *testing.T) {
	d1, d2, d3 := indexTestParts()
	src := framedTestStream(d1, d2, d3)

	ix, err := IndexFramedStream(src)
	if err != nil {
		t.Fatalf("IndexFramedStream: %v", err)
	}

	// Corrupt a compressed payload byte inside the middle chunk, then
	// rebind an index to the corrupted source. The range read must fail
	// on the chunk CRC even though the digest matches.
	bad := append([]byte(nil), src...)
	mid := ix.Chunks[2] // chunk 0 is the stream identifier
	bad[mid.Offset+chunkHeaderSize+checksumSize] ^= 0xff
	ixBad := &Index{
		SourceLen: int64(len(bad)),
		Digest:    sourceDigest(bad),
		TotalLen:  ix.TotalLen,
		Chunks:    ix.Chunks,
	}
	if _, err := ixBad.ReadRange(bad, int64(len(d1)), int64(len(d2))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ReadRange with corrupted chunk: got %v, want ErrCorrupt", err)
	}
}

func TestFramedIndexUnskippableChunkFails(t *testing.T) {
	d1, _, _ := indexTestParts()
	src := append([]byte(nil), magicChunk...)
	// Reserved unskippable chunk type 0x02 with a 3-byte payload.
	src = append(src, 0x02, 0x03, 0x00, 0x00, 'a', 'b', 'c')
	src = appendCompressedChunk(src, d1)

	if _, err := IndexFramedStream(src); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("IndexFramedStream with unskippable chunk: got %v, want ErrUnsupported", err)
	}
}

func TestFramedIndexSkippableChunkSkipped(t *testing.T) {
	d1, d2, d3 := indexTestParts()
	src := append([]byte(nil), magicChunk...)
	src = appendCompressedChunk(src, d1)
	// Reserved skippable chunk type 0x80 with a 5-byte payload.
	src = append(src, 0x80, 0x05, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o')
	src = appendCompressedChunk(src, d2)
	// Padding chunk type 0xfe with a 2-byte payload.
	src = append(src, 0xfe, 0x02, 0x00, 0x00, 0x00, 0x00)
	src = appendCompressedChunk(src, d3)

	ix, err := IndexFramedStream(src)
	if err != nil {
		t.Fatalf("IndexFramedStream: %v", err)
	}
	if got, want := ix.TotalLen, int64(len(d1)+len(d2)+len(d3)); got != want {
		t.Fatalf("ix.TotalLen = %d, want %d", got, want)
	}
	got, err := ix.ReadRange(src, int64(len(d1)), int64(len(d2)))
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if !bytes.Equal(got, d2) {
		t.Fatal("ReadRange across skippable chunks did not return the middle chunk bytes")
	}
}

func TestFramedIndexRejectsRawBlock(t *testing.T) {
	// A raw Snappy block (the Encode/Decode format) must not be treated
	// as a framed stream.
	raw := Encode(nil, []byte("hello world, this is a raw snappy block"))
	if _, err := IndexFramedStream(raw); !errors.Is(err, ErrNotFramed) {
		t.Fatalf("IndexFramedStream(raw block): got %v, want ErrNotFramed", err)
	}
	if _, err := IndexFramedStream(nil); !errors.Is(err, ErrNotFramed) {
		t.Fatalf("IndexFramedStream(nil): got %v, want ErrNotFramed", err)
	}
}

func TestFramedIndexUncompressedChunk(t *testing.T) {
	d1, d2, _ := indexTestParts()
	src := append([]byte(nil), magicChunk...)
	src = appendCompressedChunk(src, d1)
	// Uncompressed-data chunk (type 0x01) for d2.
	chunkLen := checksumSize + len(d2)
	src = append(src, chunkTypeUncompressedData,
		byte(chunkLen), byte(chunkLen>>8), byte(chunkLen>>16))
	var cs [4]byte
	binary.LittleEndian.PutUint32(cs[:], crc(d2))
	src = append(src, cs[:]...)
	src = append(src, d2...)

	ix, err := IndexFramedStream(src)
	if err != nil {
		t.Fatalf("IndexFramedStream: %v", err)
	}
	got, err := ix.ReadRange(src, int64(len(d1)-10), int64(10+len(d2)))
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	want := append(append([]byte(nil), d1[len(d1)-10:]...), d2...)
	if !bytes.Equal(got, want) {
		t.Fatal("ReadRange over compressed+uncompressed chunks mismatch")
	}
}

func TestFramedIndexRangeOutOfBounds(t *testing.T) {
	d1, d2, d3 := indexTestParts()
	src := framedTestStream(d1, d2, d3)
	ix, err := IndexFramedStream(src)
	if err != nil {
		t.Fatalf("IndexFramedStream: %v", err)
	}
	total := ix.TotalLen
	for _, r := range [][2]int64{{-1, 1}, {0, total + 1}, {total - 1, 2}} {
		if _, err := ix.ReadRange(src, r[0], r[1]); !errors.Is(err, ErrRangeOutOfBounds) {
			t.Fatalf("ReadRange(%d, %d): got %v, want ErrRangeOutOfBounds", r[0], r[1], err)
		}
	}
	if got, err := ix.ReadRange(src, total, 0); err != nil || len(got) != 0 {
		t.Fatalf("ReadRange(total, 0) = %v, %v; want empty, nil", got, err)
	}
}

// ExampleIndexFramedStream builds a small framed stream of three chunks,
// indexes it, and reads back only the range covered by the middle chunk.
func ExampleIndexFramedStream() {
	parts := [][]byte{
		bytes.Repeat([]byte("one-"), 10),
		bytes.Repeat([]byte("two-"), 10),
		bytes.Repeat([]byte("three-"), 8),
	}
	var src []byte
	src = append(src, magicChunk...)
	for _, p := range parts {
		src = appendCompressedChunk(src, p)
	}

	ix, err := IndexFramedStream(src)
	if err != nil {
		panic(err)
	}
	fmt.Printf("source=%d digest=%016x total=%d\n", ix.SourceLen, ix.Digest, ix.TotalLen)
	for i, c := range ix.Chunks {
		fmt.Printf("chunk %d: type=0x%02x off=%d clen=%d urange=[%d,%d)\n",
			i, c.Type, c.Offset, c.CompressedLen,
			c.UncompressedOffset, c.UncompressedOffset+int64(c.UncompressedLen))
	}

	// Read only the middle chunk's decompressed range.
	off := int64(len(parts[0]))
	b, err := ix.ReadRange(src, off, int64(len(parts[1])))
	if err != nil {
		panic(err)
	}
	fmt.Printf("read [%d,%d): %q\n", off, off+int64(len(parts[1])), b[:8])

	// Output:
	// source=63 digest=cc94835d9f0bdeee total=128
	// chunk 0: type=0xff off=0 clen=6 urange=[0,0)
	// chunk 1: type=0x00 off=10 clen=13 urange=[0,40)
	// chunk 2: type=0x00 off=27 clen=13 urange=[40,80)
	// chunk 3: type=0x00 off=44 clen=15 urange=[80,128)
	// read [40,80): "two-two-"
}
