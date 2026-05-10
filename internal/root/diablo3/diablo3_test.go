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

package diablo3

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// buildSubdir constructs a SUBDIR_SIGNATURE blob with one asset, one
// asset-idx and two named entries.
func buildSubdir() []byte {
	var buf bytes.Buffer
	tmp := make([]byte, 4)

	binary.LittleEndian.PutUint32(tmp, subdirSignature)
	buf.Write(tmp)

	// 1 asset entry.
	binary.LittleEndian.PutUint32(tmp, 1)
	buf.Write(tmp)
	var ck1 [16]byte
	for i := range ck1 {
		ck1[i] = byte(0x10 + i)
	}
	buf.Write(ck1[:])
	binary.LittleEndian.PutUint32(tmp, 42)
	buf.Write(tmp)

	// 1 asset-idx entry.
	binary.LittleEndian.PutUint32(tmp, 1)
	buf.Write(tmp)
	var ck2 [16]byte
	for i := range ck2 {
		ck2[i] = byte(0x20 + i)
	}
	buf.Write(ck2[:])
	binary.LittleEndian.PutUint32(tmp, 7)
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 3)
	buf.Write(tmp)

	// 2 named entries.
	binary.LittleEndian.PutUint32(tmp, 2)
	buf.Write(tmp)
	var ck3 [16]byte
	for i := range ck3 {
		ck3[i] = byte(0x30 + i)
	}
	buf.Write(ck3[:])
	buf.WriteString("readme.txt")
	buf.WriteByte(0)
	var ck4 [16]byte
	for i := range ck4 {
		ck4[i] = byte(0x40 + i)
	}
	buf.Write(ck4[:])
	buf.WriteString("config.ini")
	buf.WriteByte(0)

	return buf.Bytes()
}

func TestDiablo3SubdirParse(t *testing.T) {
	data := buildSubdir()
	h, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(h.root.Assets) != 1 || h.root.Assets[0].FileIndex != 42 {
		t.Errorf("assets = %+v", h.root.Assets)
	}
	if len(h.root.AssetIdx) != 1 || h.root.AssetIdx[0].SubIndex != 3 {
		t.Errorf("assetIdx = %+v", h.root.AssetIdx)
	}
	if e := h.LookupByName("readme.txt"); e == nil {
		t.Error("readme.txt missing")
	}
	if e := h.LookupByName("config.ini"); e == nil {
		t.Error("config.ini missing")
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

// fakeLoader maps CKey -> blob.
type fakeLoader map[casc.CKey][]byte

func (f fakeLoader) ReadByCKey(ck casc.CKey) ([]byte, error) {
	if b, ok := f[ck]; ok {
		return b, nil
	}
	return nil, casc.ErrFileNotFound
}

func TestDiablo3LoadSubdirectories(t *testing.T) {
	// Build a tiny named-only subdir blob and reference it from a parent.
	subBlob := buildSubdir()
	var subCK casc.CKey
	copy(subCK[:], []byte{0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})

	// Parent: SUBDIR signature with no assets, one named entry pointing to subCK.
	var buf bytes.Buffer
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, subdirSignature)
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 0) // 0 asset entries
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 0) // 0 asset-idx entries
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 1) // 1 named
	buf.Write(tmp)
	buf.Write(subCK[:])
	buf.WriteString("Base")
	buf.WriteByte(0)

	parent, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("parent parse: %v", err)
	}
	loader := fakeLoader{subCK: subBlob}
	if err := parent.LoadSubdirectories(loader); err != nil {
		t.Fatalf("LoadSubdirectories: %v", err)
	}
	if e := parent.LookupByName("Base/readme.txt"); e == nil {
		t.Errorf("Base/readme.txt missing")
	}
	if e := parent.LookupByName("Base/Asset42"); e == nil {
		t.Errorf("Base/Asset42 missing")
	}
	if e := parent.LookupByName("Base/Asset7_3"); e == nil {
		t.Errorf("Base/Asset7_3 missing")
	}
}

func TestDiablo3ProbeRejectsNonMagic(t *testing.T) {
	if _, err := Probe([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected error")
	}
}
