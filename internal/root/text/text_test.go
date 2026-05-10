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

package text

import (
	"testing"

	"github.com/ldmonster/go-casclib/internal/root"
)

const sample = `# comment
Interface\Hello.lua|0123456789abcdef0123456789abcdef
Other\Path.bin|FEDCBA9876543210FEDCBA9876543210
`

func TestParseText(t *testing.T) {
	h, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	e := h.LookupByName("interface/HELLO.LUA")
	if e == nil {
		t.Fatal("not found")
	}
	if e.CKey[0] != 0x01 {
		t.Errorf("ckey[0] = %#x", e.CKey[0])
	}
}

func TestProbeRejectsBinary(t *testing.T) {
	_, err := Probe([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	if err == nil {
		t.Errorf("Probe accepted binary data")
	}
}

func TestProbeViaRegistry(t *testing.T) {
	h, err := root.Detect([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if h.Name() != "Text" {
		t.Errorf("got %s", h.Name())
	}
}
