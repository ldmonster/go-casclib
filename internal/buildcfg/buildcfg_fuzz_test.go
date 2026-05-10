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

package buildcfg

import (
	"bytes"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("# build cfg\nencoding = aabbccddeeff00112233445566778899 99887766554433221100ffeeddccbbaa\n"))
	f.Add([]byte(""))
	f.Add([]byte("name=value\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(bytes.NewReader(data))
	})
}
