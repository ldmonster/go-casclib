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

package mndx

import "testing"

// FuzzParse exercises the MNDX header / MAR-info / CKey-entry parser. The
// trie walker is not yet ported; this fuzzer guards against panics and
// wild allocations on adversarial offsets/counts.
func FuzzParse(f *testing.F) {
	f.Add(buildMinimalMNDX())
	// Truncated header.
	f.Add([]byte{'M', 'N', 'D', 'X', 1, 0, 0, 0})
	// Header with an absurd CKey count to verify bounds checks.
	bad := buildMinimalMNDX()
	if len(bad) > 32 {
		bad[32] = 0xFF
		bad[33] = 0xFF
		bad[34] = 0xFF
		bad[35] = 0x7F
	}
	f.Add(bad)

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
