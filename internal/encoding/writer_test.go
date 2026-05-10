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

package encoding

import (
	"bytes"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

func TestEncodeRoundTrip(t *testing.T) {
	entries := make([]CKeyEntry, 0, 64)
	for i := 0; i < 64; i++ {
		var c casc.CKey

		c[0] = byte(i)
		c[1] = byte(i * 7)

		var e1, e2 casc.EKey

		e1[0] = byte(i + 0x40)
		e2[0] = byte(i + 0x80)

		ekeys := []casc.EKey{e1}
		if i%3 == 0 {
			ekeys = append(ekeys, e2)
		}

		entries = append(entries, CKeyEntry{
			ContentSize: uint64(0x100 + i),
			CKey:        c,
			EKeys:       ekeys,
		})
	}

	out, err := Encode(entries, WriteOptions{CKeyPageSize: 1024, IncludeEKeyPages: true, EKeyPageSize: 1024})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	f, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(f.Entries) != len(entries) {
		t.Fatalf("entry count: got %d want %d", len(f.Entries), len(entries))
	}

	for _, want := range entries {
		got := f.Find(want.CKey)
		if got == nil {
			t.Fatalf("missing %x", want.CKey)
		}

		if got.ContentSize != want.ContentSize {
			t.Fatalf("content size: got %d want %d", got.ContentSize, want.ContentSize)
		}

		if len(got.EKeys) != len(want.EKeys) {
			t.Fatalf("ekey count: got %d want %d", len(got.EKeys), len(want.EKeys))
		}

		for i := range want.EKeys {
			if !bytes.Equal(got.EKeys[i][:], want.EKeys[i][:]) {
				t.Fatalf("ekey[%d] mismatch", i)
			}
		}
	}
}

func TestEncodeEmpty(t *testing.T) {
	out, err := Encode(nil, WriteOptions{})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	f, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(f.Entries) != 0 {
		t.Fatalf("expected empty, got %d entries", len(f.Entries))
	}
}
