// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// makeFramed builds a framed stream with one data chunk per input block.
func makeFramed(t *testing.T, blocks ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for _, b := range blocks {
		if _, err := w.Write(b); err != nil {
			t.Fatalf("Writer.Write: %v", err)
		}
	}
	return buf.Bytes()
}

// chunkAt returns the chunk (header+payload) at the given source offset.
func chunkAt(t *testing.T, src []byte, off int64) []byte {
	t.Helper()
	if off+4 > int64(len(src)) {
		t.Fatalf("chunk offset %d out of range", off)
	}
	n := int(src[off+1]) | int(src[off+2])<<8 | int(src[off+3])<<16
	end := off + int64(4+n)
	if end > int64(len(src)) {
		t.Fatalf("chunk at %d runs past end", off)
	}
	return src[off:end]
}

// flipChecksumByte corrupts one payload byte of the data chunk at off so that
// its checksum no longer matches.
func flipChecksumByte(src []byte, off int64) {
	src[off+4] ^= 0xff
}

// threeBlockStream returns a framed stream of three distinct data blocks and
// the concatenated original bytes.
func threeBlockStream(t *testing.T) ([]byte, []byte) {
	t.Helper()
	b0 := []byte(strings.Repeat("AAAA", 3000)) // 12000 bytes
	b1 := []byte(strings.Repeat("BBBB", 4000)) // 16000 bytes
	b2 := []byte(strings.Repeat("CCCC", 1200)) // 4800 bytes
	src := makeFramed(t, b0, b1, b2)
	orig := bytes.Join([][]byte{b0, b1, b2}, nil)
	return src, orig
}

func TestNewIndexBasic(t *testing.T) {
	src, orig := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	if got, want := idx.SourceLen(), int64(len(src)); got != want {
		t.Fatalf("SourceLen = %d, want %d", got, want)
	}
	if got, want := idx.DecodedLen(), int64(len(orig)); got != want {
		t.Fatalf("DecodedLen = %d, want %d", got, want)
	}
	chunks := idx.Chunks()
	if len(chunks) != 4 { // stream identifier + three data chunks
		t.Fatalf("len(Chunks) = %d, want 4", len(chunks))
	}
	if chunks[0].Type != chunkTypeStreamIdentifier || chunks[0].Offset != 0 {
		t.Fatalf("first chunk = %+v, want stream identifier at 0", chunks[0])
	}
	for i := 1; i < 4; i++ {
		c := chunks[i]
		if c.Type != chunkTypeCompressedData {
			t.Fatalf("chunk %d type = %#x, want compressed data", i, c.Type)
		}
		if c.DataEnd <= c.DataStart {
			t.Fatalf("chunk %d has empty data range", i)
		}
		if i > 1 && c.Offset <= chunks[i-1].Offset {
			t.Fatalf("chunk offsets not increasing: %d after %d", c.Offset, chunks[i-1].Offset)
		}
	}
}

func TestReadRangeMiddleOnly(t *testing.T) {
	src, orig := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}

	// Read bytes [13000, 13100): entirely inside the middle block.
	const off, length = int64(13000), int64(100)
	got, err := idx.ReadRange(src, off, length)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if !bytes.Equal(got, orig[off:off+length]) {
		t.Fatalf("middle range mismatch: got %q..., want %q...", got[:8], orig[off:off+8])
	}
	if !bytes.Equal(got, []byte(strings.Repeat("B", int(length)))) {
		t.Fatalf("middle range content mismatch")
	}
}

func TestReadRangeCrossBlock(t *testing.T) {
	src, orig := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}

	// Boundary between the first and middle block is at 12000.
	const off, length = int64(11950), int64(150)
	got, err := idx.ReadRange(src, off, length)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if !bytes.Equal(got, orig[off:off+length]) {
		t.Fatalf("cross-block range mismatch")
	}
	if want := bytes.Join([][]byte{
		[]byte(strings.Repeat("A", 50)),
		[]byte(strings.Repeat("B", 100)),
	}, nil); !bytes.Equal(got, want) {
		t.Fatalf("cross-block stitching mismatch: got %d bytes", len(got))
	}

	// A range spanning all three blocks must reproduce the originals joined.
	full, err := idx.ReadRange(src, 0, int64(len(orig)))
	if err != nil {
		t.Fatalf("ReadRange full: %v", err)
	}
	if !bytes.Equal(full, orig) {
		t.Fatalf("full range mismatch")
	}
}

func TestReadRangeRejectsModifiedSource(t *testing.T) {
	src, _ := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}

	// Same length, different contents: the digest must reject it.
	modified := append([]byte(nil), src...)
	modified[len(modified)-1] ^= 0x01
	if _, err := idx.ReadRange(modified, 0, 10); !errors.Is(err, ErrStaleIndex) {
		t.Fatalf("digest-modified source: err = %v, want ErrStaleIndex", err)
	}

	// Different length must be rejected before hashing.
	if _, err := idx.ReadRange(src[:len(src)-1], 0, 10); !errors.Is(err, ErrStaleIndex) {
		t.Fatalf("length-modified source: err = %v, want ErrStaleIndex", err)
	}
}

func TestNewIndexRejectsBlockFormat(t *testing.T) {
	// A Snappy block (rawsnappy) starts with a varint length, not the 0xff
	// stream identifier chunk: it must not be mistaken for a framed stream.
	block := Encode(nil, []byte("this is not a framed stream"))
	if _, err := NewIndex(block); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("block format: err = %v, want ErrCorrupt", err)
	}
}

func TestUnignorableChunkMustBeUnderstood(t *testing.T) {
	src, _ := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}

	// Insert a reserved unskippable chunk (type 0x02) between the stream
	// identifier and the first data chunk.
	var bad bytes.Buffer
	bad.Write(chunkAt(t, src, 0)) // stream identifier
	bad.Write([]byte{0x02, 0x00, 0x00, 0x00})
	firstData := idx.Chunks()[1].Offset
	bad.Write(src[firstData:])

	if _, err := NewIndex(bad.Bytes()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unignorable unknown chunk: err = %v, want ErrUnsupported", err)
	}
}

func TestUnknownSkippableChunkIsSkipped(t *testing.T) {
	src, orig := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}

	// Insert a reserved skippable chunk (type 0x80) with a payload, plus a
	// padding chunk, between the stream identifier and the first data chunk.
	var withSkippable bytes.Buffer
	withSkippable.Write(chunkAt(t, src, 0))
	skippable := []byte{0x80, 0x03, 0x00, 0x00, 'x', 'y', 'z'}
	padding := []byte{chunkTypePadding, 0x02, 0x00, 0x00, 0, 0}
	withSkippable.Write(skippable)
	withSkippable.Write(padding)
	firstData := idx.Chunks()[1].Offset
	withSkippable.Write(src[firstData:])
	ext := withSkippable.Bytes()

	idx2, err := NewIndex(ext)
	if err != nil {
		t.Fatalf("NewIndex with skippable chunks: %v", err)
	}
	if got, want := len(idx2.Chunks()), len(idx.Chunks())+2; got != want {
		t.Fatalf("len(Chunks) = %d, want %d", got, want)
	}
	if got, want := idx2.DecodedLen(), idx.DecodedLen(); got != want {
		t.Fatalf("DecodedLen = %d, want %d", got, want)
	}
	// Ranged reads are unaffected by skippable chunks and stay in bounds.
	got, err := idx2.ReadRange(ext, 11950, 150)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if !bytes.Equal(got, orig[11950:12100]) {
		t.Fatalf("data mismatch with skippable chunks present")
	}
}

func TestReadRangeVerifiesCRC(t *testing.T) {
	src, _ := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}

	// Corrupt the middle data chunk; indexing still succeeds (it does not
	// decode or verify checksums), but the ranged read must fail the CRC.
	corrupt := append([]byte(nil), src...)
	middleOff := idx.Chunks()[2].Offset
	flipChecksumByte(corrupt, middleOff)
	idx2, err := NewIndex(corrupt)
	if err != nil {
		t.Fatalf("NewIndex on corrupted chunk: %v", err)
	}
	if _, err := idx2.ReadRange(corrupt, 13000, 100); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("CRC check: err = %v, want ErrCorrupt", err)
	}

	// Reading only the first (uncorrupted) block must still succeed: only the
	// chunks the range intersects are decoded, and that one verifies fine.
	good, err := idx2.ReadRange(corrupt, 0, 10)
	if err != nil {
		t.Fatalf("ReadRange of good block: %v", err)
	}
	if string(good) != strings.Repeat("A", 10) {
		t.Fatalf("good block content = %q", good)
	}
}

func TestReadRangeUncompressedAndBounds(t *testing.T) {
	// Manually build a framed stream whose data chunk is uncompressed.
	payload := []byte("0123456789")
	var buf bytes.Buffer
	buf.WriteString(magicChunk)
	hdr := []byte{chunkTypeUncompressedData, 0, 0, 0}
	var l [4]byte
	binary.LittleEndian.PutUint32(l[:], uint32(checksumSize+len(payload)))
	copy(hdr[1:4], l[:3])
	buf.Write(hdr)
	var sum [4]byte
	binary.LittleEndian.PutUint32(sum[:], crc(payload))
	buf.Write(sum[:])
	buf.Write(payload)
	src := buf.Bytes()

	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	got, err := idx.ReadRange(src, 2, 5)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if string(got) != "23456" {
		t.Fatalf("got %q, want 23456", got)
	}
	if _, err := idx.ReadRange(src, 0, 11); err == nil {
		t.Fatalf("out-of-bounds range unexpectedly succeeded")
	}
	if _, err := idx.ReadRange(src, -1, 1); err == nil {
		t.Fatalf("negative offset unexpectedly succeeded")
	}
}

func TestNewIndexTruncated(t *testing.T) {
	src, _ := threeBlockStream(t)
	// Truncate mid-header and mid-payload.
	for _, cut := range []int{3, 5, len(src) - 1} {
		if _, err := NewIndex(src[:cut]); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("truncated at %d: err = %v, want ErrCorrupt", cut, err)
		}
	}
}

func TestReadRangeAgreesWithReader(t *testing.T) {
	src, orig := threeBlockStream(t)
	idx, err := NewIndex(src)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}

	// Insert padding between data chunks: Reader and index must both cope, and
	// ranged reads must still reproduce what the (unchanged) Reader decodes.
	var withPadding bytes.Buffer
	for i, c := range idx.Chunks() {
		if i > 0 {
			withPadding.Write([]byte{chunkTypePadding, 0x04, 0x00, 0x00, 0, 0, 0, 0})
		}
		end := c.Offset + int64(chunkHeaderSize+c.Length)
		if i == len(idx.Chunks())-1 {
			end = int64(len(src))
		}
		withPadding.Write(src[c.Offset:end])
	}
	padded := withPadding.Bytes()

	// Ground truth straight from the pre-existing framed Reader.
	decodedAll, err := io.ReadAll(NewReader(bytes.NewReader(padded)))
	if err != nil {
		t.Fatalf("Reader.ReadAll: %v", err)
	}
	if !bytes.Equal(decodedAll, orig) {
		t.Fatalf("Reader output does not match originals")
	}

	pidx, err := NewIndex(padded)
	if err != nil {
		t.Fatalf("NewIndex on padded stream: %v", err)
	}
	if pidx.DecodedLen() != int64(len(orig)) {
		t.Fatalf("DecodedLen = %d, want %d", pidx.DecodedLen(), len(orig))
	}

	// Exercise many ranges, including block boundaries and all three blocks.
	for _, r := range [][2]int64{
		{0, 1},
		{11999, 2}, // straddle first/middle boundary
		{12000, 1}, // first byte of middle block
		{27999, 2}, // straddle middle/last boundary
		{10000, 20000},
		{0, int64(len(orig))},
	} {
		got, err := pidx.ReadRange(padded, r[0], r[1])
		if err != nil {
			t.Fatalf("ReadRange(%d,%d): %v", r[0], r[1], err)
		}
		if want := decodedAll[r[0] : r[0]+r[1]]; !bytes.Equal(got, want) {
			t.Fatalf("ReadRange(%d,%d) mismatch with Reader", r[0], r[1])
		}
	}
}

// ExampleIndex shows a small framed stream, the index built for it and a
// ranged read that stitches two chunks together.
func ExampleIndex() {
	// Three small strings, each written as its own data chunk.
	chunks := [][]byte{
		[]byte("Hello, "),
		[]byte("Snappy! "),
		[]byte("framed range read"),
	}
	var buf bytes.Buffer
	w := NewWriter(&buf)
	for _, c := range chunks {
		w.Write(c)
	}
	src := buf.Bytes()

	idx, err := NewIndex(src)
	if err != nil {
		fmt.Println("index error:", err)
		return
	}
	fmt.Println("decoded length:", idx.DecodedLen())
	for _, c := range idx.Chunks() {
		fmt.Printf("chunk off=%d type=%#x len=%d data=[%d,%d)\n",
			c.Offset, c.Type, c.Length, c.DataStart, c.DataEnd)
	}

	// Read "Snappy!" from the middle chunk, then a cross-chunk range:
	// "y! framed" spans the second and third chunks.
	mid, _ := idx.ReadRange(src, 7, 7)
	fmt.Println(string(mid))
	cross, _ := idx.ReadRange(src, 12, 9)
	fmt.Println(string(cross))
	// Output:
	// decoded length: 32
	// chunk off=0 type=0xff len=6 data=[0,0)
	// chunk off=10 type=0x1 len=11 data=[0,7)
	// chunk off=25 type=0x1 len=12 data=[7,15)
	// chunk off=41 type=0x1 len=21 data=[15,32)
	// Snappy!
	// y! framed
}
