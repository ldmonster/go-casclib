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

package cdn

import (
	"bytes"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

func TestEncodeDownloadRoundTrip(t *testing.T) {
	entries := []DownloadEntry{
		{Priority: 1, EncodedSize: 0x1234, Flags: 0x01},
		{Priority: 2, EncodedSize: 0x5678, Flags: 0x02},
		{Priority: 0, EncodedSize: 0xAABB, Flags: 0x03},
	}
	for i := range entries {
		entries[i].EKey[0] = byte(i + 1)
	}

	tags := []DownloadTag{
		{Name: "Windows", Type: 1, Bitmap: []byte{0xFF}},
		{Name: "enUS", Type: 2, Bitmap: []byte{0x05}},
	}

	out, err := EncodeDownload(entries, tags, WriteDownloadOptions{
		Version:      3,
		FlagByteSize: 1,
	})
	if err != nil {
		t.Fatalf("EncodeDownload: %v", err)
	}

	m, err := ParseDownload(out)
	if err != nil {
		t.Fatalf("ParseDownload: %v", err)
	}

	if int(m.Header.EntryCount) != len(entries) {
		t.Fatalf("entry count: got %d want %d", m.Header.EntryCount, len(entries))
	}

	for i, e := range entries {
		got := m.Entries[i]
		if !bytes.Equal(got.EKey[:1], e.EKey[:1]) ||
			got.EncodedSize != e.EncodedSize ||
			got.Priority != e.Priority ||
			got.Flags != e.Flags {
			t.Fatalf("entry %d mismatch: got %+v want %+v", i, got, e)
		}
	}

	if len(m.Tags) != len(tags) {
		t.Fatalf("tag count: got %d want %d", len(m.Tags), len(tags))
	}

	for i, want := range tags {
		got := m.Tags[i]
		if got.Name != want.Name || got.Type != want.Type {
			t.Fatalf("tag %d header mismatch", i)
		}

		if !bytes.Equal(got.Bitmap, want.Bitmap) {
			t.Fatalf("tag %d bitmap mismatch: got %x want %x", i, got.Bitmap, want.Bitmap)
		}
	}

	_ = casc.ErrBadFormat
}

func TestEncodeDownloadV1NoFlags(t *testing.T) {
	entries := []DownloadEntry{{EncodedSize: 100, Priority: 1}}
	out, err := EncodeDownload(entries, nil, WriteDownloadOptions{Version: 1})
	if err != nil {
		t.Fatalf("EncodeDownload v1: %v", err)
	}

	m, err := ParseDownload(out)
	if err != nil {
		t.Fatalf("ParseDownload: %v", err)
	}

	if m.Header.Version != 1 || len(m.Entries) != 1 {
		t.Fatalf("bad v1 round-trip: %+v", m.Header)
	}
}
