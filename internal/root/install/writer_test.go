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

package install

import (
	"bytes"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

func TestEncodeRoundTrip(t *testing.T) {
	entries := []Entry{
		{Name: "Wow.exe", ContentSize: 1024},
		{Name: "WowError.exe", ContentSize: 2048},
		{Name: "Data/locale/enUS.txt", ContentSize: 64},
	}
	for i := range entries {
		entries[i].CKey[0] = byte(0x10 + i)
	}

	tags := []Tag{
		{Name: "Windows", Type: 1, Bitmap: []byte{0xE0}},
		{Name: "x86_64", Type: 2, Bitmap: []byte{0x80}},
	}

	out, err := Encode(entries, tags, WriteOptions{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	h, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if int(h.EntryCount) != len(entries) {
		t.Fatalf("entry count: got %d want %d", h.EntryCount, len(entries))
	}

	for _, want := range entries {
		got := h.LookupByName(want.Name)
		if got == nil {
			t.Fatalf("missing %q", want.Name)
		}

		if got.ContentSize != uint64(want.ContentSize) {
			t.Fatalf("size for %q: got %d want %d", want.Name, got.ContentSize, want.ContentSize)
		}

		if !bytes.Equal(got.CKey[:1], want.CKey[:1]) {
			t.Fatalf("ckey for %q: got %x want %x", want.Name, got.CKey, want.CKey)
		}
	}

	if int(h.TagCount) != len(tags) {
		t.Fatalf("tag count: got %d want %d", h.TagCount, len(tags))
	}

	for i, want := range tags {
		got := h.Tags[i]
		if got.Name != want.Name || got.Type != want.Type {
			t.Fatalf("tag[%d] header mismatch", i)
		}

		if !bytes.Equal(got.Bitmap[:len(want.Bitmap)], want.Bitmap) {
			t.Fatalf("tag[%d] bitmap mismatch", i)
		}
	}

	_ = casc.MagicInstall
}
