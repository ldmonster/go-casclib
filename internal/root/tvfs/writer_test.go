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

package tvfs

import (
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

func TestEncodeRoundTrip(t *testing.T) {
	entries := []WriteEntry{
		{Name: "alpha.txt", ContentSize: 100},
		{Name: "beta.bin", ContentSize: 2048},
		{Name: "gamma_long_name.dat", ContentSize: 12345},
	}
	for i := range entries {
		entries[i].EKey[0] = byte(0x10 + i)
		entries[i].EKey[8] = byte(0xA0 + i)
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
		got := h.LookupByName(want.Name)
		if got == nil {
			t.Fatalf("missing %q", want.Name)
		}

		if got.ContentSize != uint64(want.ContentSize) {
			t.Fatalf("size %q: got %d want %d", want.Name, got.ContentSize, want.ContentSize)
		}

		for j := 0; j < 9; j++ {
			if got.EKey[j] != want.EKey[j] {
				t.Fatalf("ekey[%d] for %q mismatch", j, want.Name)
			}
		}
	}

	_ = casc.MagicEncoding
}

func TestEncodeRejectsLongName(t *testing.T) {
	long := make([]byte, 0x100)
	for i := range long {
		long[i] = 'A'
	}

	if _, err := Encode([]WriteEntry{{Name: string(long)}}, WriteOptions{}); err == nil {
		t.Fatal("expected error")
	}
}
