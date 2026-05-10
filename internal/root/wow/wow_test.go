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

package wow

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/listfile"
)

// buildV1Group writes one group with 12-byte header.
func buildV1Group(numFiles int, locale, content uint32, fdidDeltas []uint32, ckeys [][16]byte, hashes []uint64) []byte {
	var buf bytes.Buffer
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(numFiles))
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, content)
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, locale)
	buf.Write(tmp)
	for _, d := range fdidDeltas {
		binary.LittleEndian.PutUint32(tmp, d)
		buf.Write(tmp)
	}
	for i := 0; i < numFiles; i++ {
		buf.Write(ckeys[i][:])
		var hb [8]byte
		binary.LittleEndian.PutUint64(hb[:], hashes[i])
		buf.Write(hb[:])
	}
	return buf.Bytes()
}

func TestWoWV1Parse(t *testing.T) {
	var ck1, ck2 [16]byte
	for i := 0; i < 16; i++ {
		ck1[i] = byte(i)
		ck2[i] = byte(0x80 + i)
	}
	h1 := listfile.HashFileName("interface/hello.lua")
	h2 := uint64(0)

	group := buildV1Group(2, 0x2, 0,
		[]uint32{5, 3}, // FDIDs: 5, then +1+3=9
		[][16]byte{ck1, ck2},
		[]uint64{h1, h2},
	)
	h, err := Parse(group)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.fmt != formatV1 {
		t.Errorf("format = %v, want v1", h.fmt)
	}
	if e := h.LookupByFileDataID(5); e == nil || e.CKey != ck1 {
		t.Errorf("FDID=5 lookup failed: %+v", e)
	}
	if e := h.LookupByFileDataID(9); e == nil || e.CKey != ck2 {
		t.Errorf("FDID=9 lookup failed: %+v", e)
	}
	if e := h.LookupByName("interface/hello.lua"); e == nil || e.CKey != ck1 {
		t.Errorf("name lookup failed: %+v", e)
	}
}

func TestWoWV2Parse(t *testing.T) {
	var ck1, ck2 [16]byte
	for i := 0; i < 16; i++ {
		ck1[i] = 0xAA
		ck2[i] = 0xBB
	}
	h1 := listfile.HashFileName("data/file.txt")

	// File header (v2: 12 bytes, magic + TotalFiles + FilesWithNameHash).
	var hdr bytes.Buffer
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, wowMagic)
	hdr.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 2)
	hdr.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 1) // 1 file with name hash
	hdr.Write(tmp)

	// Group header (12 bytes).
	var grp bytes.Buffer
	binary.LittleEndian.PutUint32(tmp, 2)
	grp.Write(tmp) // numFiles
	binary.LittleEndian.PutUint32(tmp, 0)
	grp.Write(tmp) // contentFlags = 0 (so name hashes are present)
	binary.LittleEndian.PutUint32(tmp, 0)
	grp.Write(tmp) // localeFlags
	// FDID deltas: 0, 1 -> FDIDs 0, 2
	binary.LittleEndian.PutUint32(tmp, 0)
	grp.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 1)
	grp.Write(tmp)
	// CKey array
	grp.Write(ck1[:])
	grp.Write(ck2[:])
	// Hash array
	var hb [8]byte
	binary.LittleEndian.PutUint64(hb[:], h1)
	grp.Write(hb[:])
	binary.LittleEndian.PutUint64(hb[:], 0)
	grp.Write(hb[:])

	all := append(hdr.Bytes(), grp.Bytes()...)
	h, err := Parse(all)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.fmt != formatV2 {
		t.Errorf("format = %v, want v2", h.fmt)
	}
	if e := h.LookupByFileDataID(0); e == nil || e.CKey != ck1 {
		t.Errorf("FDID=0 lookup failed: %+v", e)
	}
	if e := h.LookupByFileDataID(2); e == nil || e.CKey != ck2 {
		t.Errorf("FDID=2 lookup failed: %+v", e)
	}
	if e := h.LookupByName("data/file.txt"); e == nil {
		t.Error("name lookup failed")
	}
}

func TestWoWProbeRejectsNonMagic(t *testing.T) {
	if _, err := Probe([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected error")
	}
}
