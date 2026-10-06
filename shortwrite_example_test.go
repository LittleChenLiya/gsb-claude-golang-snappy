// Copyright 2026 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snappy_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/golang/snappy"
)

// oneStallWriter returns (0, nil) on its first Write call and accepts all
// bytes from then on.
type oneStallWriter struct {
	stalled bool
	buf     bytes.Buffer
}

func (w *oneStallWriter) Write(p []byte) (int, error) {
	if !w.stalled {
		w.stalled = true
		return 0, nil
	}
	return w.buf.Write(p)
}

// This example shows how to send a single Snappy-framed chunk over an
// io.Writer that may report a short write or accept zero bytes. The payload
// is encoded once; retries only resend the bytes that were not accepted.
func ExampleWriter_WriteShort() {
	dst := &oneStallWriter{}
	w := snappy.NewWriter(dst)

	p := []byte("hello")
	if _, err := w.WriteShort(p); err != nil {
		if !errors.Is(err, snappy.ErrNoProgress) {
			log.Fatal(err)
		}
		// The underlying writer accepted nothing, so stop and report the
		// stalled write. When it is writable again, retry the saved tail:
		// the encoding is not regenerated.
		for {
			if _, err := w.WriteShort(nil); err == nil {
				break
			} else if !errors.Is(err, snappy.ErrNoProgress) {
				log.Fatal(err)
			}
		}
	}

	got, err := io.ReadAll(snappy.NewReader(bytes.NewReader(dst.buf.Bytes())))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", got)
	// Output: hello
}
