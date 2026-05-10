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

package mndx

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// buildMinimalMNDX constructs a tiny MNDX root with 1 MAR entry and 2
// CKey entries. The MAR data is just 'MAR\0' followed by zeros (we don't
// parse the trie yet).
func buildMinimalMNDX() []byte {
	var buf bytes.Buffer
	tmp := make([]byte, 4)

	// Header (12 bytes, version 1).
	binary.LittleEndian.PutUint32(tmp, mndxMagic)
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 1) // HeaderVersion=1
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 2) // FormatVersion
	buf.Write(tmp)

	// Info tail (0x1C bytes).
	// Layout that follows: header (12) + info (28) + mar info (20) + mar data (4) + ckey entries (48) = 112
	const headerEnd = 12 + 28
	const marInfoOff = headerEnd
	const marInfoEnd = marInfoOff + 20
	const marDataOff = marInfoEnd
	const ckeyOff = marDataOff + 4

	binary.LittleEndian.PutUint32(tmp, marInfoOff)
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 1) // MarInfoCount=1
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 20) // MarInfoSize=20
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, ckeyOff) // CKeyEntriesOffset
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 2) // CKeyEntriesCount=2
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 2) // FileNameCount=2
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 24) // CKeyEntrySize=24
	buf.Write(tmp)

	// MAR info entry (20 bytes).
	binary.LittleEndian.PutUint32(tmp, 0) // MarIndex
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 4) // MarDataSize
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 0) // MarDataSizeHi
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, marDataOff)
	buf.Write(tmp)
	binary.LittleEndian.PutUint32(tmp, 0) // MarDataOffsetHi
	buf.Write(tmp)

	// MAR data: just the magic.
	binary.LittleEndian.PutUint32(tmp, marMagic)
	buf.Write(tmp)

	// CKey entries (2 × 24 bytes).
	// Entry 0: package=1, flags=MNDX_LAST_CKEY_ENTRY, content size 100.
	binary.LittleEndian.PutUint32(tmp, mndxLastCKey|1)
	buf.Write(tmp)
	var ck1 [16]byte
	for i := range ck1 {
		ck1[i] = byte(0x10 + i)
	}
	buf.Write(ck1[:])
	binary.LittleEndian.PutUint32(tmp, 100)
	buf.Write(tmp)

	// Entry 1: package=2, no last flag, content size 200.
	binary.LittleEndian.PutUint32(tmp, 2)
	buf.Write(tmp)
	var ck2 [16]byte
	for i := range ck2 {
		ck2[i] = byte(0x80 + i)
	}
	buf.Write(ck2[:])
	binary.LittleEndian.PutUint32(tmp, 200)
	buf.Write(tmp)

	return buf.Bytes()
}

func TestMNDXParse(t *testing.T) {
	data := buildMinimalMNDX()
	h, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.HeaderInfo().HeaderVersion != 1 {
		t.Errorf("HeaderVersion = %d", h.HeaderInfo().HeaderVersion)
	}
	if len(h.MarInfos()) != 1 {
		t.Errorf("MarInfos count = %d", len(h.MarInfos()))
	}
	if len(h.Entries()) != 2 {
		t.Fatalf("entries = %d", len(h.Entries()))
	}
	if !h.Entries()[0].IsLast {
		t.Error("entry[0] should have IsLast")
	}
	if h.Entries()[0].PackageIndex != 1 {
		t.Errorf("entry[0] package = %d", h.Entries()[0].PackageIndex)
	}
	if h.Entries()[1].ContentSize != 200 {
		t.Errorf("entry[1] size = %d", h.Entries()[1].ContentSize)
	}
}

func TestMNDXLookupByFileDataID(t *testing.T) {
	h, err := Parse(buildMinimalMNDX())
	if err != nil {
		t.Fatal(err)
	}
	if e := h.LookupByFileDataID(0); e == nil || e.ContentSize != 100 {
		t.Errorf("FDID=0 lookup = %+v", e)
	}
	if e := h.LookupByFileDataID(1); e == nil || e.ContentSize != 200 {
		t.Errorf("FDID=1 lookup = %+v", e)
	}
	if e := h.LookupByFileDataID(99); e != nil {
		t.Errorf("FDID=99 should be nil, got %+v", e)
	}
}

func TestMNDXAll(t *testing.T) {
	h, err := Parse(buildMinimalMNDX())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	h.All(func(name string, e *casc.CKeyEntry) bool {
		count++
		return true
	})
	if count != 2 {
		t.Errorf("All count = %d, want 2", count)
	}
}

func TestMNDXProbeRejectsNonMagic(t *testing.T) {
	if _, err := Probe(make([]byte, 16)); err == nil {
		t.Fatal("expected error")
	}
}

func TestMNDXLookupByNameUnsupported(t *testing.T) {
	h, err := Parse(buildMinimalMNDX())
	if err != nil {
		t.Fatal(err)
	}
	// LookupByName isn't implemented for the trie yet; should return nil.
	if e := h.LookupByName("anything"); e != nil {
		t.Errorf("expected nil, got %+v", e)
	}
}
