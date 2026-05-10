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

package overwatch

import (
	"strings"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

func TestOverwatchProbeAndParse(t *testing.T) {
	rootCsv := strings.Join([]string{
		"FILENAME!STRING:0|MD5!HEX:16|CHUNK_ID!DEC:4|PRIORITY!DEC:1",
		"RetailClient/RetailClient.exe.build.info|0123456789abcdef0123456789abcdef|0|0",
		"Manifest/enUS.apm|fedcba9876543210fedcba9876543210|1|0",
	}, "\n") + "\n"

	h, err := Probe([]byte(rootCsv))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if h == nil {
		t.Fatal("Probe returned nil handler")
	}
	if got := h.Name(); got != "Overwatch" {
		t.Errorf("Name=%q, want Overwatch", got)
	}

	e := h.LookupByName("Manifest/enUS.apm")
	if e == nil {
		t.Fatal("LookupByName returned nil")
	}
	if e.CKey[0] != 0xFE || e.CKey[1] != 0xDC {
		t.Errorf("CKey wrong; got %x", e.CKey[:4])
	}

	count := 0
	h.All(func(_ string, _ *casc.CKeyEntry) bool { count++; return true })
	if count != 2 {
		t.Errorf("All count=%d, want 2", count)
	}
}

func TestOverwatchProbeRejectsBinary(t *testing.T) {
	if _, err := Probe([]byte{0x00, 0x01, 0x02, 0x03, 0xFF}); err == nil {
		t.Error("expected ErrBadFormat for binary input")
	}
}

func TestOverwatchProbeRejectsMissingColumns(t *testing.T) {
	missing := "NAME|HASH\nfoo|deadbeef\n"
	if _, err := Probe([]byte(missing)); err == nil {
		t.Error("expected ErrBadFormat for missing FILENAME/MD5")
	}
}
