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
	"strings"
	"testing"
)

func TestConfigEncodeRoundTrip(t *testing.T) {
	c := NewConfig()
	c.Set("build-name", "WOW-12345patch9.2.7_Retail")

	var ckey, ekey [16]byte

	for i := range ckey {
		ckey[i] = byte(i)
		ekey[i] = byte(0x80 + i)
	}

	c.SetKeyPair("encoding", ckey, ekey)
	c.SetSizePair("encoding-size", 0x1000, 0x800)
	c.SetArchives([][16]byte{ckey, ekey})

	out := c.EncodeText()

	parsed, err := Parse(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := parsed.Get("build-name"); got != "WOW-12345patch9.2.7_Retail" {
		t.Fatalf("build-name: got %q", got)
	}

	enc, err := parsed.LookupCKey("encoding")
	if err != nil {
		t.Fatalf("LookupCKey: %v", err)
	}

	if !enc.HasEKey {
		t.Fatalf("encoding missing EKey")
	}

	if [16]byte(enc.CKey) != ckey {
		t.Fatalf("ckey mismatch")
	}

	archives, err := parsed.Archives()
	if err != nil {
		t.Fatalf("Archives: %v", err)
	}

	if len(archives) != 2 {
		t.Fatalf("archives len %d", len(archives))
	}

	if !strings.Contains(string(out), "encoding-size = 4096 2048") {
		t.Fatalf("encoding-size not formatted: %s", out)
	}
}

func TestEncodeBuildInfo(t *testing.T) {
	out := EncodeBuildInfo([]BuildInfoRow{{
		Region:   "us",
		BuildKey: "deadbeef",
		Version:  "9.2.7",
	}})

	if !bytes.Contains(out, []byte("Branch!STRING:0|")) {
		t.Fatalf("missing column header: %s", out)
	}

	lines := bytes.Split(bytes.TrimRight(out, "\n"), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %s", len(lines), out)
	}

	if !bytes.Contains(lines[1], []byte("us|1|deadbeef|")) {
		t.Fatalf("row not formatted: %s", lines[1])
	}
}
