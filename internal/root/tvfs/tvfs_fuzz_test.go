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

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{'T', 'V', 'F', 'S'})
	// Minimum-shaped header with all-zero fields.
	hdr := make([]byte, 38)
	hdr[0], hdr[1], hdr[2], hdr[3] = 'T', 'V', 'F', 'S'
	hdr[4] = 1 // FormatVersion
	f.Add(hdr)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}
