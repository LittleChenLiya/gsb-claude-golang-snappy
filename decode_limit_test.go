// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"bytes"
	"errors"
	"testing"
)

// smallValidBlock is a tiny, legal Snappy block: a varint header declaring
// 3 decoded bytes followed by a 3-byte literal ("abc").
var smallValidBlock = []byte{0x03, 0x08, 'a', 'b', 'c'}

// hugeLengthHeader declares a decoded length of 4 GiB - 1 (the largest value a
// legal 5-byte Snappy varint header may carry). No payload follows.
var hugeLengthHeader = []byte{0xff, 0xff, 0xff, 0xff, 0x0f}

// mediumLengthHeader declares a decoded length of 64 KiB but carries no
// payload. The legacy (uncapped) path allocates that buffer and then fails on
// the missing payload, proving no cap is imposed by default.
var mediumLengthHeader = []byte{0x80, 0x80, 0x04}

func sentinelDst() []byte {
	return []byte{0x5a, 0x5a, 0x5a, 0x5a}
}

// TestDecodeWithMaxOutputLenAcceptsSmallBlock exercises the boundary with a
// very small legal block: caps larger than, and exactly equal to, the declared
// length must succeed; a cap one byte smaller must be rejected with
// ErrTooLarge.
func TestDecodeWithMaxOutputLenAcceptsSmallBlock(t *testing.T) {
	for _, n := range []int{100, 3} {
		got, err := DecodeWithOptions(nil, smallValidBlock, WithMaxOutputLen(n))
		if err != nil {
			t.Fatalf("maxOutputLen=%d: unexpected error: %v", n, err)
		}
		if string(got) != "abc" {
			t.Fatalf("maxOutputLen=%d: got %q, want %q", n, got, "abc")
		}
	}

	if _, err := DecodeWithOptions(nil, smallValidBlock, WithMaxOutputLen(2)); err != ErrTooLarge {
		t.Fatalf("maxOutputLen=2: got %v, want ErrTooLarge", err)
	}
}

// TestDecodeWithMaxOutputLenRejectsHugeHeader verifies that a block whose
// header declares 4 GiB - 1 of output is refused by the header check, before
// any destination allocation can happen. The allocation count of the rejected
// call is compared against a successful call that decodes into a pre-sized
// dst (same option plumbing, no destination make): the rejected call must not
// allocate more, proving no ~4 GiB buffer is created.
func TestDecodeWithMaxOutputLenRejectsHugeHeader(t *testing.T) {
	rejectedAllocs := testing.AllocsPerRun(10, func() {
		if _, err := DecodeWithOptions(nil, hugeLengthHeader, WithMaxOutputLen(1<<20)); err != ErrTooLarge {
			t.Fatalf("got %v, want ErrTooLarge", err)
		}
	})
	dst := make([]byte, 3)
	acceptedAllocs := testing.AllocsPerRun(10, func() {
		if _, err := DecodeWithOptions(dst, smallValidBlock, WithMaxOutputLen(100)); err != nil {
			t.Fatalf("got unexpected error: %v", err)
		}
	})
	if rejectedAllocs > acceptedAllocs {
		t.Fatalf("rejected call allocated %v objects, accepted-into-dst call %v; "+
			"the huge destination buffer must not be allocated",
			rejectedAllocs, acceptedAllocs)
	}
}

// TestDecodeWithMaxOutputLenBadVarint verifies that malformed length headers
// yield ErrCorrupt, regardless of the configured cap.
func TestDecodeWithMaxOutputLenBadVarint(t *testing.T) {
	bad := [][]byte{
		// Final byte still has the continuation bit set.
		{0xff},
		// Valid as a uint64 varint but overflows uint32.
		{0x80, 0x80, 0x80, 0x80, 0x10},
		// Overlong varint: exceeds the 5-byte preamble limit.
		{0x84, 0x80, 0x80, 0x80, 0x80, 0x00},
	}
	for i, b := range bad {
		if _, err := DecodeWithOptions(nil, b, WithMaxOutputLen(1<<30)); err != ErrCorrupt {
			t.Errorf("bad header #%d: got %v, want ErrCorrupt", i, err)
		}
	}
}

// TestDecodeWithMaxOutputLenPreservesDst verifies that rejected blocks (too
// large or malformed) never touch the caller-provided dst: length, capacity
// and sentinel contents all survive.
func TestDecodeWithMaxOutputLenPreservesDst(t *testing.T) {
	cases := []struct {
		desc string
		src  []byte
		opt  DecodeOption
		want error
	}{
		{"huge header", hugeLengthHeader, WithMaxOutputLen(1 << 20), ErrTooLarge},
		{"small block but tight cap", smallValidBlock, WithMaxOutputLen(2), ErrTooLarge},
		{"bad varint", []byte{0xff}, WithMaxOutputLen(1 << 20), ErrCorrupt},
	}
	for _, tc := range cases {
		dst := sentinelDst()
		want := make([]byte, len(dst))
		copy(want, dst)
		got, err := DecodeWithOptions(dst, tc.src, tc.opt)
		if got != nil {
			t.Errorf("%s: got non-nil result %v, want nil", tc.desc, got)
		}
		if err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.desc, err, tc.want)
		}
		if len(dst) != len(want) || cap(dst) != cap(want) || !bytes.Equal(dst, want) {
			t.Errorf("%s: dst modified: got %v (len=%d cap=%d), want %v",
				tc.desc, dst, len(dst), cap(dst), want)
		}
	}
}

// TestDecodeWithMaxOutputLenZeroAndNegative covers the extreme cap values.
func TestDecodeWithMaxOutputLenZeroAndNegative(t *testing.T) {
	emptyBlock := []byte{0x00}

	// Cap zero: the empty block (declared length exactly 0) is allowed.
	if got, err := DecodeWithOptions(nil, emptyBlock, WithMaxOutputLen(0)); err != nil || len(got) != 0 {
		t.Fatalf("cap=0, empty block: got %v, %v", got, err)
	}
	// Cap zero: any non-empty declaration is rejected.
	if _, err := DecodeWithOptions(nil, smallValidBlock, WithMaxOutputLen(0)); err != ErrTooLarge {
		t.Fatalf("cap=0, 3-byte block: got %v, want ErrTooLarge", err)
	}
	// Negative cap: even the empty block is rejected.
	if _, err := DecodeWithOptions(nil, emptyBlock, WithMaxOutputLen(-1)); err != ErrTooLarge {
		t.Fatalf("cap=-1, empty block: got %v, want ErrTooLarge", err)
	}
}

// TestDecodeUnlimitedByDefault verifies that the original Decode entry point
// and DecodeWithOptions without the limit option keep the legacy semantics,
// including when no option is supplied at all.
func TestDecodeUnlimitedByDefault(t *testing.T) {
	calls := []func([]byte, []byte) ([]byte, error){
		Decode,
		func(dst, src []byte) ([]byte, error) {
			return DecodeWithOptions(dst, src)
		},
	}
	for i, decode := range calls {
		// Small legal block decodes.
		if got, err := decode(nil, smallValidBlock); err != nil || string(got) != "abc" {
			t.Fatalf("call #%d, small block: got %q, %v", i, got, err)
		}
		// A large-but-valid declared length is not size-checked by the
		// legacy path (the header itself is valid); it allocates and then
		// fails because the payload is absent, never with the option's
		// ErrTooLarge.
		if _, err := decode(nil, mediumLengthHeader); err == nil || err == ErrTooLarge {
			t.Fatalf("call #%d, medium header: got %v, want a non-ErrTooLarge error", i, err)
		}
		// Malformed headers still yield ErrCorrupt.
		if _, err := decode(nil, []byte{0xff}); err != ErrCorrupt {
			t.Fatalf("call #%d, bad varint: got %v, want ErrCorrupt", i, err)
		}
	}
}

// TestDecodeWithMaxOutputLenErrorsIs keeps errors comparable with errors.Is.
func TestDecodeWithMaxOutputLenErrorsIs(t *testing.T) {
	if _, err := DecodeWithOptions(nil, smallValidBlock, WithMaxOutputLen(1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("errors.Is(err, ErrTooLarge) = false for %v", err)
	}
}
