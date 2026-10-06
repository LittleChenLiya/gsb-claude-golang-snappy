// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// twoByteWriter is an in-memory io.Writer that accepts at most two bytes per
// Write call, as required by the io.Writer contract (short writes are legal).
type twoByteWriter struct {
	bytes.Buffer
}

func (w *twoByteWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

// zeroWriter rejects everything on the first call, returning (0, nil), then
// behaves like a normal in-memory writer.
type zeroWriter struct {
	calls int
	buf   bytes.Buffer
}

func (w *zeroWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return 0, nil
	}
	return w.buf.Write(p)
}

// countHeaders returns how many Snappy stream-identifier chunks (magic
// headers) occur in b.
func countHeaders(b []byte) int {
	return bytes.Count(b, []byte(magicChunk))
}

// TestSendRetriesShortWrites feeds a Writer backed by a writer that only ever
// accepts two bytes at a time. The result must decode back to the original
// input and contain exactly one stream header (no duplicated header despite
// the many retried writes).
func TestSendRetriesShortWrites(t *testing.T) {
	var dst twoByteWriter
	sw := NewWriter(&dst)

	input := strings.Repeat("snappy short write ", 500)
	if err := sw.Send([]byte(input)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := dst.Bytes()
	if countHeaders(got) != 1 {
		t.Fatalf("got %d stream headers, want 1", countHeaders(got))
	}

	decoded, err := io.ReadAll(NewReader(bytes.NewReader(got)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != input {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(decoded), len(input))
	}
}

// TestSendNoProgressRetainsTail verifies that a (0, nil) answer from the
// underlying writer is reported immediately as ErrNoProgress, and that the
// unsent tail is still fully retryable afterwards: retrying produces the
// complete, uniquely-headed stream.
func TestSendNoProgressRetainsTail(t *testing.T) {
	dst := new(zeroWriter)
	sw := NewWriter(dst)

	input := strings.Repeat("retry me ", 300)
	err := sw.Send([]byte(input))
	if !errors.Is(err, ErrNoProgress) {
		t.Fatalf("first Send: got %v, want ErrNoProgress", err)
	}
	if dst.calls != 1 {
		t.Fatalf("first Send made %d underlying writes, want 1 (must stop immediately)", dst.calls)
	}
	if dst.buf.Len() != 0 {
		t.Fatalf("expected no bytes delivered before the no-progress report, got %d", dst.buf.Len())
	}

	// The tail is retained: retrying with nil sends only the remaining bytes.
	if err := sw.Send(nil); err != nil {
		t.Fatalf("retry Send: %v", err)
	}
	got := dst.buf.Bytes()
	if countHeaders(got) != 1 {
		t.Fatalf("got %d stream headers after retry, want 1", countHeaders(got))
	}
	decoded, err := io.ReadAll(NewReader(bytes.NewReader(got)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != input {
		t.Fatalf("round-trip mismatch after retry: got %d bytes, want %d", len(decoded), len(input))
	}
}

// ExampleWriter_Send shows sending one message through a Writer whose
// underlying writer may return short writes, and decoding the result.
func ExampleWriter_Send() {
	var dst bytes.Buffer
	sw := NewWriter(&dst)
	if err := sw.Send([]byte("hello, snappy")); err != nil {
		fmt.Println("send error:", err)
		return
	}
	decoded, err := io.ReadAll(NewReader(&dst))
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}
	fmt.Println(string(decoded))
	// Output: hello, snappy
}
