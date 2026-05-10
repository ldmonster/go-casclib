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

package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-casclib/internal/datafile"
	"github.com/ldmonster/go-casclib/internal/index"
)

// TestWriteThenParseV1 performs the full M6a write pipeline:
//
//  1. Encode several payloads into BLTE spans (mixed raw / zlib).
//  2. Append them via Writer into data.000 (with rollover into data.001).
//  3. Emit a V1 .idx for each bucket.
//  4. Re-parse the .idx files and decode each span via the read pipeline.
func TestWriteThenParseV1(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(dir, 600) // tiny segments, force rollover
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	type sample struct {
		name    string
		content []byte
		mode    datafile.EncodeMode
	}

	samples := []sample{
		{"raw1", bytes.Repeat([]byte("AAAA"), 100), datafile.EncodeRaw},
		{"zlib1", bytes.Repeat([]byte("Compressible "), 200), datafile.EncodeZlib},
		{"raw2", []byte("short"), datafile.EncodeRaw},
		{"zlib2", bytes.Repeat([]byte("xy"), 500), datafile.EncodeZlib},
	}

	type written struct {
		sample sample
		entry  index.EKeyEntry
	}

	var entries []written

	for _, s := range samples {
		blte, _, ekey, err := datafile.Encode(s.content, datafile.EncodeOptions{Mode: s.mode})
		if err != nil {
			t.Fatalf("Encode %s: %v", s.name, err)
		}

		entry, err := w.WriteSpan(blte, ekey)
		if err != nil {
			t.Fatalf("WriteSpan %s: %v", s.name, err)
		}

		entries = append(entries, written{s, entry})
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify rollover actually happened.
	seenArchives := map[uint32]bool{}
	for _, e := range entries {
		seenArchives[e.entry.ArchiveIndex] = true
	}

	if len(seenArchives) < 2 {
		t.Fatalf("expected segment rollover, only saw archives %v", seenArchives)
	}

	// Emit a V1 .idx for bucket 0 carrying all entries.
	idxEntries := make([]index.EKeyEntry, len(entries))
	for i, e := range entries {
		idxEntries[i] = e.entry
	}

	idxBytes, err := index.EncodeV1(idxEntries, index.WriteOptions{BucketIndex: 0})
	if err != nil {
		t.Fatalf("EncodeV1: %v", err)
	}

	idxPath := filepath.Join(dir, index.IndexFileName(0, 0))
	if err := os.WriteFile(idxPath, idxBytes, 0o644); err != nil {
		t.Fatalf("WriteFile idx: %v", err)
	}

	// Re-parse the .idx and confirm each entry decodes back to the
	// original content via the read pipeline.
	parsed, err := index.Parse(idxBytes, 0)
	if err != nil {
		t.Fatalf("index.Parse: %v", err)
	}

	if len(parsed.Entries) != len(entries) {
		t.Fatalf("parsed entry count %d, want %d", len(parsed.Entries), len(entries))
	}

	pool := NewPool(dir)
	defer pool.Close()

	// Build a map from EKey-prefix → expected sample.
	want := map[[9]byte][]byte{}

	for _, e := range entries {
		var k [9]byte

		copy(k[:], e.entry.EKey[:9])
		want[k] = e.sample.content
	}

	for _, p := range parsed.Entries {
		var k [9]byte

		copy(k[:], p.EKey[:9])

		expected, ok := want[k]
		if !ok {
			t.Fatalf("unknown EKey in parsed index: %x", k)
		}

		got, err := pool.ReadSpan(p, nil)
		if err != nil {
			t.Fatalf("ReadSpan: %v", err)
		}

		if !bytes.Equal(got, expected) {
			t.Fatalf("content mismatch for ekey %x", k)
		}
	}
}
