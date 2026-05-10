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

import "testing"

func FuzzParse(f *testing.F) {
	// Seed corpus: empty, minimal header, a valid two-entry manifest.
	f.Add([]byte{})
	f.Add([]byte{0x49, 0x4E}) // 'IN' magic only
	f.Add(make([]byte, 10))   // header-sized zero block

	// Seed with a valid manifest built by the test helper.
	t := &testing.T{}
	if data := buildInstall(t); len(data) > 0 {
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
