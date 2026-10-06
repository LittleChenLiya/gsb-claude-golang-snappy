// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/golang/snappy"
)

// streamHeader is the Snappy stream identifier chunk, as defined in
// https://github.com/google/snappy/blob/master/framing_format.txt
var streamHeader = []byte{0xff, 0x06, 0x00, 0x00, 's', 'N', 'a', 'P', 'p', 'Y'}

// twoByteWriter is an in-memory io.Writer that accepts at most 2 bytes per
// Write call.
type twoByteWriter struct {
	buf bytes.Buffer
}

func (w *twoByteWriter) Write(p []byte) (int, error) {
	if len(p) <= 2 {
		return w.buf.Write(p)
	}
	return w.buf.Write(p[:2])
}

// drainShort keeps retrying a pending WriteShort tail (with nil input) until
// it is fully sent.
func drainShort(t *testing.T, w *snappy.Writer) {
	t.Helper()
	for {
		n, err := w.WriteShort(nil)
		if err == nil {
			if n != 0 {
				t.Fatalf("retry WriteShort: n=%d, want 0", n)
			}
			return
		}
		if !errors.Is(err, snappy.ErrNoProgress) {
			t.Fatalf("retry WriteShort: %v", err)
		}
	}
}

// pseudoRandom returns a short, deterministic, incompressible byte sequence.
func pseudoRandom(n int) []byte {
	b := make([]byte, n)
	x := uint32(1)
	for i := range b {
		x = x*1103515245 + 12345
		b[i] = byte(x >> 16)
	}
	return b
}

func decodeStream(t *testing.T, encoded []byte) []byte {
	t.Helper()
	got, err := io.ReadAll(snappy.NewReader(bytes.NewReader(encoded)))
	if err != nil {
		t.Fatalf("decoding stream: %v", err)
	}
	return got
}

func TestWriteShortTwoByteWriter(t *testing.T) {
	payloads := [][]byte{
		bytes.Repeat([]byte("snappy! "), 50), // compressible: compressed-data chunk
		pseudoRandom(100),                    // incompressible: uncompressed-data chunk
	}
	dst := &twoByteWriter{}
	w := snappy.NewWriter(dst)

	var want bytes.Buffer
	for _, p := range payloads {
		n, err := w.WriteShort(p)
		if err != nil {
			t.Fatalf("WriteShort: %v", err)
		}
		if n != len(p) {
			t.Fatalf("WriteShort: n=%d, want %d", n, len(p))
		}
		want.Write(p)
	}

	encoded := dst.buf.Bytes()
	if got := bytes.Count(encoded, streamHeader); got != 1 {
		t.Fatalf("stream header count = %d, want 1", got)
	}
	if got := decodeStream(t, encoded); !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("decoded payload mismatch: got %d bytes, want %d", len(got), want.Len())
	}
}

// zeroThenTwoWriter accepts zero bytes on its first Write call (returning
// (0, nil)) and at most 2 bytes per call afterwards.
type zeroThenTwoWriter struct {
	twoByteWriter
	calls int
}

func (w *zeroThenTwoWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return 0, nil
	}
	return w.twoByteWriter.Write(p)
}

func TestWriteShortNoProgressKeepsTail(t *testing.T) {
	p := bytes.Repeat([]byte("no progress here. "), 10)
	dst := &zeroThenTwoWriter{}
	w := snappy.NewWriter(dst)

	n, err := w.WriteShort(p)
	if n != 0 || !errors.Is(err, snappy.ErrNoProgress) {
		t.Fatalf("WriteShort on (0, nil) writer = (%d, %v), want (0, ErrNoProgress)", n, err)
	}

	// The unsent tail is still pending: new input must be rejected, and the
	// pending bytes must remain retryable with nil.
	if _, err := w.WriteShort([]byte("brand new input")); err == nil {
		t.Fatal("WriteShort with new input while a tail is pending: want error, got nil")
	}
	drainShort(t, w)

	encoded := dst.buf.Bytes()
	if got := bytes.Count(encoded, streamHeader); got != 1 {
		t.Fatalf("stream header count = %d, want 1", got)
	}
	if got := decodeStream(t, encoded); !bytes.Equal(got, p) {
		t.Fatalf("decoded payload mismatch: got %d bytes, want %d", len(got), len(p))
	}
}
