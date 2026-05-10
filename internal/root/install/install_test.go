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

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

func buildInstall(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	// Header.
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, casc.MagicInstall)
	buf.Write(tmp)
	buf.WriteByte(1)  // Version
	buf.WriteByte(16) // HashSize
	binary.BigEndian.PutUint16(tmp, 1)
	buf.Write(tmp) // TagCount=1
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp4, 2)
	buf.Write(tmp4) // EntryCount=2

	// One tag: name="Windows", type=1, bitmap covers 2 entries (1 byte).
	buf.WriteString("Windows")
	buf.WriteByte(0)
	binary.BigEndian.PutUint16(tmp, 1)
	buf.Write(tmp)
	buf.WriteByte(0xC0) // both entries set, MSB-first

	// Entry 1: "setup.exe" + 16 byte CKey + 4 BE size.
	var ck1, ck2 [16]byte
	for i := 0; i < 16; i++ {
		ck1[i] = 0x10 + byte(i)
		ck2[i] = 0x80 + byte(i)
	}
	buf.WriteString("setup.exe")
	buf.WriteByte(0)
	buf.Write(ck1[:])
	binary.BigEndian.PutUint32(tmp4, 1024)
	buf.Write(tmp4)

	buf.WriteString("readme.txt")
	buf.WriteByte(0)
	buf.Write(ck2[:])
	binary.BigEndian.PutUint32(tmp4, 64)
	buf.Write(tmp4)

	return buf.Bytes()
}

func TestInstallParse(t *testing.T) {
	data := buildInstall(t)
	h, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.EntryCount != 2 {
		t.Errorf("EntryCount = %d", h.EntryCount)
	}
	if len(h.Tags) != 1 || h.Tags[0].Name != "Windows" {
		t.Errorf("tags = %+v", h.Tags)
	}
	if e := h.LookupByName("setup.exe"); e == nil {
		t.Fatal("setup.exe not found")
	} else if e.ContentSize != 1024 {
		t.Errorf("setup.exe size = %d", e.ContentSize)
	}
	if e := h.LookupByName("readme.txt"); e == nil || e.ContentSize != 64 {
		t.Errorf("readme.txt = %+v", e)
	}
	count := 0
	h.All(func(name string, e *casc.CKeyEntry) bool {
		count++
		return true
	})
	if count != 2 {
		t.Errorf("All count = %d", count)
	}
}

func TestInstallProbeRejectsNonMagic(t *testing.T) {
	if _, err := Probe(make([]byte, 10)); err == nil {
		t.Fatal("expected error")
	}
}
