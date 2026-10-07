// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// sentinelDst returns an 8-byte buffer filled with a marker byte, used to
// prove that a rejected Decode call does not touch the caller's dst.
func sentinelDst() []byte {
	return bytes.Repeat([]byte{0xab}, 8)
}

func assertSentinelUntouched(t *testing.T, dst []byte, desc string) {
	t.Helper()
	if want := bytes.Repeat([]byte{0xab}, 8); !bytes.Equal(dst, want) {
		t.Errorf("%s: dst modified by failed decode, got % x want % x", desc, dst, want)
	}
}

// TestDecodeWithOptionsTinyLegal verifies the boundary on a very small legal
// block: a declared length exactly equal to the limit is allowed, one byte
// over is rejected with ErrTooLarge, and a rejected call leaves dst alone.
func TestDecodeWithOptionsTinyLegal(t *testing.T) {
	plain := []byte("hello") // declared decoded length is exactly 5
	src := Encode(nil, plain)
	if got, err := DecodedLen(src); err != nil || got != 5 {
		t.Fatalf("DecodedLen: got (%d, %v), want (5, nil)", got, err)
	}

	// Bound exactly equal: allowed; the pre-sized dst is reused.
	dst := sentinelDst()
	out, err := DecodeWithOptions(dst, src, MaxDecodedLen(5))
	if err != nil {
		t.Fatalf("limit == declared length: unexpected error %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("limit == declared length: got %q, want %q", out, plain)
	}
	if len(out) != 5 {
		t.Fatalf("limit == declared length: len(out)=%d, want 5", len(out))
	}

	// Bound one byte too small: rejected before dst is touched.
	dst = sentinelDst()
	if out, err := DecodeWithOptions(dst, src, MaxDecodedLen(4)); err != ErrTooLarge {
		t.Fatalf("limit = declared length - 1: got (%v, %v), want (nil, ErrTooLarge)", out, err)
	}
	assertSentinelUntouched(t, dst, "limit = declared length - 1")

	// Zero limit rejects a non-empty block.
	dst = sentinelDst()
	if _, err := DecodeWithOptions(dst, src, MaxDecodedLen(0)); err != ErrTooLarge {
		t.Fatalf("limit = 0: got %v, want ErrTooLarge", err)
	}
	assertSentinelUntouched(t, dst, "limit = 0")

	// Empty block with limit zero: declared length 0 == limit, allowed.
	empty := Encode(nil, nil)
	if out, err := DecodeWithOptions(nil, empty, MaxDecodedLen(0)); err != nil || len(out) != 0 {
		t.Fatalf("empty block, limit = 0: got (len=%d, %v), want (len=0, nil)", len(out), err)
	}
}

// TestDecodeWithOptionsForgedLength forges length headers that claim a huge
// output. Neither the giant (uint32-overflowing) header nor the large but
// representable header may trigger a big allocation or touch dst.
func TestDecodeWithOptionsForgedLength(t *testing.T) {
	// Varint that decodes to 2^32 (one more than the uint32 maximum the
	// format permits). decodedLen rejects this outright as corrupt.
	overUint32 := []byte{0x80, 0x80, 0x80, 0x80, 0x10}
	if dLen, err := DecodedLen(overUint32); err != ErrCorrupt {
		t.Fatalf("over-uint32 header: DecodedLen got (%d, %v), want (0, ErrCorrupt)", dLen, err)
	}
	dst := sentinelDst()
	if out, err := DecodeWithOptions(dst, overUint32, MaxDecodedLen(64)); err != ErrCorrupt {
		t.Fatalf("over-uint32 header: got (%v, %v), want (nil, ErrCorrupt)", out, err)
	}
	assertSentinelUntouched(t, dst, "over-uint32 header")

	// Varint that legally decodes to 0x7fffffff (about 2 GiB) but carries no
	// payload. With a 64-byte limit this must be rejected as too large
	// before any allocation.
	big := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(big, 0x7fffffff)
	big = big[:n]
	if dLen, err := DecodedLen(big); err != nil || dLen != 0x7fffffff {
		t.Fatalf("large header: DecodedLen got (%d, %v), want (%d, nil)", dLen, err, 0x7fffffff)
	}
	dst = sentinelDst()
	if out, err := DecodeWithOptions(dst, big, MaxDecodedLen(64)); err != ErrTooLarge {
		t.Fatalf("large header, small limit: got (%v, %v), want (nil, ErrTooLarge)", out, err)
	}
	assertSentinelUntouched(t, dst, "large header, small limit")
}

// TestDecodeWithOptionsBadVarint feeds malformed varint length headers.
// Both the option-enabled path and the plain path must return ErrCorrupt
// without touching dst.
func TestDecodeWithOptionsBadVarint(t *testing.T) {
	bad := [][]byte{
		{0xff}, // continuation bit set, truncated
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, // overflows uint64
		{0x84, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00},             // overlong 8-byte encoding
		{}, // empty input
	}
	for i, input := range bad {
		dst := sentinelDst()
		if out, err := DecodeWithOptions(dst, input, MaxDecodedLen(64)); err != ErrCorrupt {
			t.Errorf("case %d (limited): got (%v, %v), want (nil, ErrCorrupt)", i, out, err)
		}
		assertSentinelUntouched(t, dst, "bad varint (limited)")

		dst = sentinelDst()
		if out, err := DecodeWithOptions(dst, input); err != ErrCorrupt {
			t.Errorf("case %d (no options): got (%v, %v), want (nil, ErrCorrupt)", i, out, err)
		}
		assertSentinelUntouched(t, dst, "bad varint (no options)")
	}
}

// TestDecodeWithOptionsUnlimited ensures that, when the new option is not
// enabled (no options at all, or an explicit negative bound), behavior
// matches the original Decode semantics and large legal outputs are not
// capped.
func TestDecodeWithOptionsUnlimited(t *testing.T) {
	plain := bytes.Repeat([]byte("abcdefgh"), 100) // 800 bytes
	src := Encode(nil, plain)

	for _, opts := range [][]DecodeOption{nil, {}, {MaxDecodedLen(-1)}} {
		// Smaller dst forces a fresh allocation; it must not be mutated.
		dst := sentinelDst()
		out, err := DecodeWithOptions(dst, src, opts...)
		if err != nil {
			t.Fatalf("unlimited decode: unexpected error %v", err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("unlimited decode: output mismatch (len %d)", len(out))
		}
		assertSentinelUntouched(t, dst, "unlimited decode with undersized dst")

		// Must match the original Decode API exactly.
		ref, err := Decode(nil, src)
		if err != nil {
			t.Fatalf("Decode: unexpected error %v", err)
		}
		if !bytes.Equal(out, ref) {
			t.Fatalf("DecodeWithOptions output does not match Decode output")
		}
	}
}

// TestDecodeOriginalAPICompat exercises the unchanged original API on a few
// tiny legal and illegal blocks.
func TestDecodeOriginalAPICompat(t *testing.T) {
	for _, plain := range [][]byte{nil, {}, []byte("x"), []byte("hello"), bytes.Repeat([]byte("ab"), 100)} {
		src := Encode(nil, plain)
		out, err := Decode(nil, src)
		if err != nil {
			t.Fatalf("Decode(%d-byte input): unexpected error %v", len(plain), err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("Decode(%d-byte input): output mismatch", len(plain))
		}
	}
	if _, err := Decode(nil, []byte{0xff}); err != ErrCorrupt {
		t.Fatalf("Decode(bad varint): got %v, want ErrCorrupt", err)
	}
}
