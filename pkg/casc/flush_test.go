// Copyright 2026 go-casclib Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casc_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-casclib/pkg/casc"
)

func TestCreateFlushRoundTrip(t *testing.T) {
	dir := t.TempDir()

	s, err := casc.CreateStorage(dir, casc.CreateOptions{})
	if err != nil {
		t.Fatalf("CreateStorage: %v", err)
	}

	files := map[string][]byte{
		"hello.txt":           []byte("Hello, CASC!"),
		"data/binary.bin":     bytes.Repeat([]byte{0xAB, 0xCD, 0xEF}, 4096),
		"long/path/readme.md": []byte("# README\n\nThis is a synthetic CASC archive.\n"),
	}

	for name, body := range files {
		if err := s.AddFile(name, body); err != nil {
			t.Fatalf("AddFile %q: %v", name, err)
		}
	}

	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify the layout looks sensible.
	if _, err := os.Stat(filepath.Join(dir, ".build.info")); err != nil {
		t.Fatalf(".build.info missing: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "Data", "data", "data.*"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no data segments: %v %v", err, matches)
	}

	// Re-open and read every file back.
	r, err := casc.OpenStorage(dir, casc.OpenOptions{})
	if err != nil {
		t.Fatalf("OpenStorage: %v", err)
	}

	defer func() { _ = r.Close() }()

	for name, want := range files {
		f, oerr := r.OpenFile(name)
		if oerr != nil {
			t.Fatalf("OpenFile %q: %v", name, oerr)
		}

		got, rerr := io.ReadAll(f)
		_ = f.Close()

		if rerr != nil {
			t.Fatalf("ReadAll %q: %v", name, rerr)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("content mismatch for %q: got %d bytes, want %d", name, len(got), len(want))
		}
	}
}

func TestFlushReadOnlyReturnsErr(t *testing.T) {
	dir := t.TempDir()
	// .build.info is missing; OpenStorage still succeeds but Flush is unsupported.
	s, err := casc.OpenStorage(dir, casc.OpenOptions{})
	if err != nil {
		t.Fatalf("OpenStorage: %v", err)
	}

	defer func() { _ = s.Close() }()

	if err := s.Flush(); !errors.Is(err, casc.ErrNotSupported) {
		t.Fatalf("Flush: want ErrNotSupported, got %v", err)
	}
}
