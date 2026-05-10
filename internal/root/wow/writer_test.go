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

package wow

import (
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

func TestEncodeRoundTripNoHash(t *testing.T) {
	entries := []WriteEntry{
		{FileDataID: 100},
		{FileDataID: 0},
		{FileDataID: 250},
		{FileDataID: 9999},
	}
	for i := range entries {
		entries[i].CKey[0] = byte(0x10 + i)
	}

	out, err := Encode(entries, WriteOptions{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	h, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, want := range entries {
		got := h.LookupByFileDataID(want.FileDataID)
		if got == nil {
			t.Fatalf("missing FDID %d", want.FileDataID)
		}

		if got.FileDataID != want.FileDataID {
			t.Fatalf("FDID: got %d want %d", got.FileDataID, want.FileDataID)
		}

		if got.CKey != want.CKey {
			t.Fatalf("ckey for %d mismatch", want.FileDataID)
		}
	}

	_ = casc.MagicEncoding
}

func TestEncodeRoundTripWithHash(t *testing.T) {
	entries := []WriteEntry{
		{FileDataID: 1, FileNameHash: 0xDEADBEEFCAFE0001},
		{FileDataID: 5, FileNameHash: 0xDEADBEEFCAFE0005},
		{FileDataID: 12, FileNameHash: 0xDEADBEEFCAFE000C},
	}

	out, err := Encode(entries, WriteOptions{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	h, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, want := range entries {
		got := h.LookupByFileDataID(want.FileDataID)
		if got == nil || got.FileNameHash != want.FileNameHash {
			t.Fatalf("hash for FDID %d not preserved", want.FileDataID)
		}
	}
}

func TestEncodeRejectsDuplicate(t *testing.T) {
	if _, err := Encode([]WriteEntry{{FileDataID: 1}, {FileDataID: 1}}, WriteOptions{}); err == nil {
		t.Fatal("expected error")
	}
}
