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

package datafile

import "testing"

func FuzzParseHeader(f *testing.F) {
	// Seed: minimal-but-malformed inputs. Real seeds will be added by the
	// fuzzing engine itself; we only need to ensure the parser never panics.
	f.Add([]byte{})
	f.Add([]byte{0x42, 0x4C, 0x54, 0x45})                               // magic only
	f.Add([]byte{0x42, 0x4C, 0x54, 0x45, 0, 0, 0, 0, 0, 0, 0, 0})       // size=0 hdr
	f.Add([]byte{0x42, 0x4C, 0x54, 0x45, 0, 0, 0, 8, 0x0F, 0, 0, 0x01}) // bogus

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseHeader must never panic, regardless of input.
		_, _ = ParseHeader(data)
	})
}
