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

package cmfkeys

import (
	"testing"

	"github.com/ldmonster/go-casclib/internal/root/overwatch"
)

func TestRegistryNotNil(t *testing.T) {
	if DefaultRegistry == nil {
		t.Fatal("DefaultRegistry must not be nil after init()")
	}
}

func TestBuiltinKeytablesPopulated(t *testing.T) {
	if len(builtinKeytables) == 0 {
		t.Fatal("builtinKeytables is empty; run tools/cmfkeygen/main.py")
	}

	if len(builtinKeytables) != builtinKeytableCount {
		t.Errorf("count mismatch: map has %d, const says %d",
			len(builtinKeytables), builtinKeytableCount)
	}

	if got, want := len(builtinKeytables), 100; got < want {
		t.Errorf("expected at least %d ported keytables, got %d", want, got)
	}
}

func TestKeyTableLookup(t *testing.T) {
	builds := KnownBuilds()
	if len(builds) == 0 {
		t.Fatal("KnownBuilds returned empty")
	}

	first := builds[0]
	tbl, ok := KeyTable(first)
	if !ok {
		t.Fatalf("KeyTable(%d) missing", first)
	}

	allZero := true
	for _, b := range tbl {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("KeyTable(%d) is all zeros", first)
	}

	if _, ok := KeyTable(0); ok {
		t.Error("KeyTable(0) should be false")
	}
}

func TestKnownBuildsSorted(t *testing.T) {
	builds := KnownBuilds()
	for i := 1; i < len(builds); i++ {
		if builds[i-1] >= builds[i] {
			t.Fatalf("KnownBuilds not strictly ascending at index %d: %d, %d",
				i, builds[i-1], builds[i])
		}
	}
}

func TestDefaultRegistryRunsGeneratedRecipes(t *testing.T) {
	builds := KnownBuilds()
	if len(builds) == 0 {
		t.Skip("no built-in builds")
	}

	// Pick a non-zero data/entry count and a deterministic digest so the
	// generated recipes have something to chew on. We don't compare
	// against fixtures; we just assert the providers run without panic
	// and produce non-zero output for at least some builds.
	hdr := overwatch.CMFHeader{
		BuildVersion: builds[0],
		DataCount:    1234,
		EntryCount:   5678,
		Magic:        0x636D6601,
	}
	var digest [20]byte
	for i := range digest {
		digest[i] = byte(i + 1)
	}

	nonZeroKey := 0
	nonZeroIV := 0
	for _, b := range builds {
		hdr.BuildVersion = b
		provider := DefaultRegistry.Find(b)
		if provider == nil {
			t.Fatalf("DefaultRegistry has no provider for known build %d", b)
		}
		key, iv, err := provider(hdr, digest)
		if err != nil {
			t.Fatalf("build %d: provider returned error: %v", b, err)
		}
		for _, x := range key {
			if x != 0 {
				nonZeroKey++
				break
			}
		}
		for _, x := range iv {
			if x != 0 {
				nonZeroIV++
				break
			}
		}
	}
	if nonZeroKey == 0 {
		t.Error("every generated Key recipe produced an all-zero key")
	}
	if nonZeroIV == 0 {
		t.Error("every generated IV recipe produced an all-zero IV")
	}
}
