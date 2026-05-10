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

// Package mndx implements the MNDX (Heroes of the Storm legacy) root
// handler.
//
// MNDX root files store filenames in a heavily compressed Patricia trie
// with three "MAR" sub-files (PackageNames, StrippedNames, FullNames). The
// file body is laid out as:
//
//	[12]   FILE_MNDX_HEADER
//	         [4 LE] Signature ('MNDX')
//	         [4 LE] HeaderVersion (1 or 2)
//	         [4 LE] FormatVersion
//	[8?]   field_1C/field_20 (only if HeaderVersion==2)
//	[0x1C] FILE_MNDX_INFO tail
//	         [4 LE] MarInfoOffset
//	         [4 LE] MarInfoCount
//	         [4 LE] MarInfoSize (== 0x14)
//	         [4 LE] CKeyEntriesOffset
//	         [4 LE] CKeyEntriesCount
//	         [4 LE] FileNameCount
//	         [4 LE] CKeyEntrySize (== 0x18 == 4 + 16 + 4)
//	-- referenced regions --
//	  MarInfoOffset .. : MarInfoCount × FILE_MAR_INFO (5 DWORDs, 0x14 bytes)
//	  CKeyEntriesOffset .. : CKeyEntriesCount × MNDX_CKEY_ENTRY
//	         [4 LE] Flags (high 8 bits = flags incl. MNDX_LAST_CKEY_ENTRY,
//	                       low 24 bits = package index)
//	         [16]   CKey
//	         [4 LE] ContentSize
//
// This Go implementation parses the header, the MNDX_INFO tail, the MAR
// info table, and the flat CKey entries array. Filename resolution via the
// Patricia trie (the bulk of the upstream C++ code, ~2900 LOC) is **not**
// yet implemented; LookupByName therefore returns nil for all queries.
// File enumeration via All / LookupByFileDataID still works using package
// index + sequential ordinal as a synthetic identifier.
//
// C++ reference: CascRootFile_MNDX.cpp.
package mndx

import (
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/root"
)

const (
	mndxMagic       uint32 = 0x58444E4D // 'MNDX'
	marMagic        uint32 = 0x0052414D // 'MAR\0'
	mndxCKeyEntrySz        = 24         // 4 Flags + 16 CKey + 4 ContentSize
	mndxMarInfoSz          = 20         // 5 × DWORD
	mndxLastCKey    uint32 = 0x80000000 // MNDX_LAST_CKEY_ENTRY in C++
)

// Info captures the FILE_MNDX_HEADER + FILE_MNDX_INFO tail.
type Info struct {
	HeaderVersion     uint32
	FormatVersion     uint32
	Field1C           uint32
	Field20           uint32
	MarInfoOffset     uint32
	MarInfoCount      uint32
	MarInfoSize       uint32
	CKeyEntriesOffset uint32
	CKeyEntriesCount  uint32
	FileNameCount     uint32
	CKeyEntrySize     uint32
}

// MarInfo locates one MAR sub-file inside the MNDX root blob.
type MarInfo struct {
	MarIndex        uint32
	MarDataSize     uint32
	MarDataSizeHi   uint32
	MarDataOffset   uint32
	MarDataOffsetHi uint32
}

// CKeyEntry is one row of the flat CKey entry table.
type CKeyEntry struct {
	Flags        uint32 // high 8 bits = flags, low 24 bits = package index
	CKey         casc.CKey
	ContentSize  uint32
	IsLast       bool
	PackageIndex uint32
}

// Handler is the in-memory MNDX root index.
type Handler struct {
	info     Info
	mars     []MarInfo
	entries  []CKeyEntry
	marFiles []*marFile // index 0..MAR_COUNT-1
	packages []string   // index → package file name
	// fileNameIdxToEntry[i] = index into entries[] for the first CKey entry
	// of file-name group i. fileNameIdxToEntry[FileNameCount] = len(entries).
	fileNameIdxToEntry []uint32
	// names is the materialised name → entry map for fast lookup.
	names map[string]int // value: index into entries[]
	// orderedNames preserves enumeration order for All().
	orderedNames []string
}

const (
	marPackageNames  = 0
	marStrippedNames = 1
	marFullNames     = 2
	marCount         = 3
)

func init() { root.Register(Probe) }

// Probe accepts data starting with 'MNDX'.
func Probe(data []byte) (root.Handler, error) {
	if len(data) < 12 {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint32(data[0:4]) != mndxMagic {
		return nil, casc.ErrBadFormat
	}

	return Parse(data)
}

// Parse parses an in-memory MNDX root file (header + flat tables).
func Parse(data []byte) (*Handler, error) {
	if len(data) < 12 {
		return nil, casc.ErrBadFormat
	}

	sig := binary.LittleEndian.Uint32(data[0:4])
	if sig != mndxMagic {
		return nil, fmt.Errorf("%w: MNDX signature %#x", casc.ErrBadFormat, sig)
	}

	headerVersion := binary.LittleEndian.Uint32(data[4:8])
	formatVersion := binary.LittleEndian.Uint32(data[8:12])

	if headerVersion < 1 || headerVersion > 2 {
		return nil, fmt.Errorf("%w: MNDX HeaderVersion %d", casc.ErrNotSupported, headerVersion)
	}

	off := 12

	info := Info{HeaderVersion: headerVersion, FormatVersion: formatVersion}
	if headerVersion == 2 {
		if off+8 > len(data) {
			return nil, casc.ErrBadFormat
		}

		info.Field1C = binary.LittleEndian.Uint32(data[off : off+4])
		info.Field20 = binary.LittleEndian.Uint32(data[off+4 : off+8])
		off += 8
	}

	if off+0x1C > len(data) {
		return nil, fmt.Errorf("%w: MNDX info truncated", casc.ErrBadFormat)
	}

	info.MarInfoOffset = binary.LittleEndian.Uint32(data[off+0 : off+4])
	info.MarInfoCount = binary.LittleEndian.Uint32(data[off+4 : off+8])
	info.MarInfoSize = binary.LittleEndian.Uint32(data[off+8 : off+12])
	info.CKeyEntriesOffset = binary.LittleEndian.Uint32(data[off+12 : off+16])
	info.CKeyEntriesCount = binary.LittleEndian.Uint32(data[off+16 : off+20])
	info.FileNameCount = binary.LittleEndian.Uint32(data[off+20 : off+24])
	info.CKeyEntrySize = binary.LittleEndian.Uint32(data[off+24 : off+28])

	if info.MarInfoSize != mndxMarInfoSz {
		return nil, fmt.Errorf("%w: MNDX MarInfoSize %d", casc.ErrBadFormat, info.MarInfoSize)
	}

	if info.CKeyEntrySize != mndxCKeyEntrySz {
		return nil, fmt.Errorf("%w: MNDX CKeyEntrySize %d", casc.ErrBadFormat, info.CKeyEntrySize)
	}

	if info.MarInfoCount > 8 { // MAR_COUNT in C++ is 3, allow some slack
		return nil, fmt.Errorf("%w: MNDX MarInfoCount %d", casc.ErrBadFormat, info.MarInfoCount)
	}

	h := &Handler{info: info}

	// MAR info table.
	marStart := int(info.MarInfoOffset)
	if marStart+int(info.MarInfoCount)*mndxMarInfoSz > len(data) {
		return nil, fmt.Errorf("%w: MNDX MAR info truncated", casc.ErrBadFormat)
	}

	h.mars = make([]MarInfo, info.MarInfoCount)
	for i := uint32(0); i < info.MarInfoCount; i++ {
		o := marStart + int(i)*mndxMarInfoSz
		h.mars[i] = MarInfo{
			MarIndex:        binary.LittleEndian.Uint32(data[o+0 : o+4]),
			MarDataSize:     binary.LittleEndian.Uint32(data[o+4 : o+8]),
			MarDataSizeHi:   binary.LittleEndian.Uint32(data[o+8 : o+12]),
			MarDataOffset:   binary.LittleEndian.Uint32(data[o+12 : o+16]),
			MarDataOffsetHi: binary.LittleEndian.Uint32(data[o+16 : o+20]),
		}
		// Sanity check: MAR file must start with 'MAR\0' magic.
		mo := int(h.mars[i].MarDataOffset)
		if mo+4 <= len(data) && binary.LittleEndian.Uint32(data[mo:mo+4]) != marMagic {
			return nil, fmt.Errorf("%w: MNDX MAR[%d] missing 'MAR\\0' magic", casc.ErrBadFormat, i)
		}
	}

	// CKey entries.
	keStart := int(info.CKeyEntriesOffset)

	keEnd := keStart + int(info.CKeyEntriesCount)*mndxCKeyEntrySz
	if keEnd > len(data) {
		return nil, fmt.Errorf("%w: MNDX CKey entries truncated", casc.ErrBadFormat)
	}

	h.entries = make([]CKeyEntry, info.CKeyEntriesCount)
	for i := uint32(0); i < info.CKeyEntriesCount; i++ {
		o := keStart + int(i)*mndxCKeyEntrySz
		flags := binary.LittleEndian.Uint32(data[o : o+4])

		var ck casc.CKey
		copy(ck[:], data[o+4:o+20])
		size := binary.LittleEndian.Uint32(data[o+20 : o+24])
		h.entries[i] = CKeyEntry{
			Flags:        flags,
			CKey:         ck,
			ContentSize:  size,
			IsLast:       flags&mndxLastCKey != 0,
			PackageIndex: flags & 0x00FFFFFF,
		}
	}

	// Load and parse all MAR files (best-effort: trie issues are
	// non-fatal; the flat CKey array remains usable as a fallback).
	h.marFiles = make([]*marFile, marCount)
	for i, mi := range h.mars {
		if i >= marCount {
			break
		}

		off := int(mi.MarDataOffset)

		end := off + int(mi.MarDataSize)
		if off < 0 || end > len(data) || off > end {
			continue
		}

		mf := &marFile{}
		if err := mf.load(data[off:end]); err == nil {
			h.marFiles[mi.MarIndex] = mf
		}
	}

	h.buildNameIndex()

	return h, nil
}

// buildNameIndex enumerates package names + stripped names and produces
// a fully-qualified "<package>/<file>" → entry mapping.
func (h *Handler) buildNameIndex() {
	// Cap FileNameCount to the actual number of CKey entries. Adversarial
	// input may claim a huge count; letting it drive allocations causes OOM.
	nEntries := uint32(len(h.entries))

	fileNameCap := h.info.FileNameCount + 1
	if fileNameCap > nEntries+1 {
		fileNameCap = nEntries + 1
	}

	// Build fileNameIdxToEntry: walk entries, recording boundaries on
	// MNDX_LAST_CKEY_ENTRY. The first entry always begins a group.
	h.fileNameIdxToEntry = make([]uint32, 0, fileNameCap)
	if len(h.entries) > 0 {
		h.fileNameIdxToEntry = append(h.fileNameIdxToEntry, 0)
		for i, e := range h.entries {
			if e.IsLast {
				h.fileNameIdxToEntry = append(h.fileNameIdxToEntry, uint32(i+1))
			}
		}
	}

	// Enumerate packages.
	if pkg := h.marFiles[marPackageNames]; pkg != nil {
		count := pkg.fileNameCount()
		if count > nEntries {
			count = nEntries
		}

		h.packages = make([]string, count)

		pkg.enumerate(func(name []byte, idx uint32) bool {
			if idx < uint32(len(h.packages)) {
				h.packages[idx] = string(name)
			}

			return true
		})
	}

	// Enumerate stripped names and join with packages.
	stripped := h.marFiles[marStrippedNames]
	if stripped == nil || len(h.packages) == 0 {
		return
	}

	nameCap := h.info.FileNameCount
	if nameCap > nEntries {
		nameCap = nEntries
	}

	h.names = make(map[string]int, nameCap)

	stripped.enumerate(func(name []byte, idx uint32) bool {
		if idx >= uint32(len(h.fileNameIdxToEntry))-1 {
			return true
		}

		start := h.fileNameIdxToEntry[idx]

		end := uint32(len(h.entries))
		if idx+1 < uint32(len(h.fileNameIdxToEntry)) {
			end = h.fileNameIdxToEntry[idx+1]
		}

		for i := start; i < end; i++ {
			pkgIdx := h.entries[i].PackageIndex
			if pkgIdx >= uint32(len(h.packages)) {
				continue
			}

			full := h.packages[pkgIdx] + "/" + string(name)
			if _, dup := h.names[full]; !dup {
				h.names[full] = int(i)
				h.orderedNames = append(h.orderedNames, full)
			}
		}

		return true
	})
}

// Name implements root.Handler.
func (h *Handler) Name() string { return "MNDX" }

// LookupByName implements root.Handler.
func (h *Handler) LookupByName(name string) *casc.CKeyEntry {
	if idx, ok := h.names[name]; ok {
		e := h.entries[idx]

		return &casc.CKeyEntry{
			CKey:        e.CKey,
			ContentSize: uint64(e.ContentSize),
			FileDataID:  uint32(idx),
			Flags:       casc.CEFlagHasCKey,
		}
	}

	return nil
}

// LookupByFileDataID treats the synthetic FDID as an ordinal into the
// flat CKey entries table.
func (h *Handler) LookupByFileDataID(id uint32) *casc.CKeyEntry {
	if id >= uint32(len(h.entries)) {
		return nil
	}

	e := h.entries[id]

	return &casc.CKeyEntry{
		CKey:        e.CKey,
		ContentSize: uint64(e.ContentSize),
		FileDataID:  id,
		Flags:       casc.CEFlagHasCKey,
	}
}

// All iterates entries. If the trie loaded successfully, real names are
// returned; otherwise falls back to synthetic "FileDataID:N" labels.
func (h *Handler) All(yield func(name string, entry *casc.CKeyEntry) bool) {
	if len(h.orderedNames) > 0 {
		for _, n := range h.orderedNames {
			i := h.names[n]
			e := h.entries[i]

			out := casc.CKeyEntry{
				CKey:        e.CKey,
				ContentSize: uint64(e.ContentSize),
				FileDataID:  uint32(i),
				Flags:       casc.CEFlagHasCKey,
			}
			if !yield(n, &out) {
				return
			}
		}

		return
	}

	for i := range h.entries {
		e := h.entries[i]

		out := casc.CKeyEntry{
			CKey:        e.CKey,
			ContentSize: uint64(e.ContentSize),
			FileDataID:  uint32(i),
			Flags:       casc.CEFlagHasCKey,
		}
		if !yield(fmt.Sprintf("FileDataID:%d", i), &out) {
			return
		}
	}
}

// Features implements root.Handler.
func (h *Handler) Features() uint32 {
	return casc.FeatureFileDataIDs | casc.FeatureRootCKey
}

// Entries returns the parsed flat CKey table. Useful for tests/inspection.
func (h *Handler) Entries() []CKeyEntry { return h.entries }

// MarInfos returns the parsed MAR info table.
func (h *Handler) MarInfos() []MarInfo { return h.mars }

// HeaderInfo returns the parsed header/info struct.
func (h *Handler) HeaderInfo() Info { return h.info }
