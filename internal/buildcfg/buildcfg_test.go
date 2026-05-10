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
	"errors"
	"strings"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

const sample = `# Build config (sample)
build-name = WOW-12345patch9.0.5_Retail
root = 4d1d49e656e3835fe7be0d754a37ee44
encoding = 5b16b5e6c3b6a3f9da0fa5d3e58d1bf7 12345678901234567890123456789012
encoding-size = 9876543 1234567
install = aaaabbbbccccddddeeeeffff00112233 99887766554433221100ffeeddccbbaa
download = 11112222333344445555666677778888 fedcba9876543210fedcba9876543210
patch = 0123456789abcdef0123456789abcdef
size = cafebabecafebabecafebabecafebabe
`

func TestParse(t *testing.T) {
	c, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.Get("build-name") != "WOW-12345patch9.0.5_Retail" {
		t.Errorf("build-name = %q", c.Get("build-name"))
	}
	enc, err := c.LookupCKey("encoding")
	if err != nil {
		t.Fatal(err)
	}
	if !enc.HasEKey {
		t.Error("encoding should have EKey")
	}
	if enc.CKey != (casc.CKey{0x5b, 0x16, 0xb5, 0xe6, 0xc3, 0xb6, 0xa3, 0xf9, 0xda, 0x0f, 0xa5, 0xd3, 0xe5, 0x8d, 0x1b, 0xf7}) {
		t.Errorf("encoding CKey mismatch: %x", enc.CKey)
	}
	root, err := c.LookupCKey("root")
	if err != nil {
		t.Fatal(err)
	}
	if root.HasEKey {
		t.Error("root should have only CKey")
	}
}

func TestParseMissing(t *testing.T) {
	c, err := Parse(strings.NewReader("foo = bar\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LookupCKey("encoding"); !errors.Is(err, casc.ErrFileNotFound) {
		t.Errorf("expected ErrFileNotFound, got %v", err)
	}
}

func TestParseBadHex(t *testing.T) {
	_, err := Parse(strings.NewReader("encoding = ZZ\n"))
	if err != nil {
		t.Fatal(err)
	}
}
