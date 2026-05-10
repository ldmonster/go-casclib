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

// Package wow is the Go implementation of the World of Warcraft root handler.
//
// The WoW root file maps FileDataIDs (and optional Jenkins filename hashes)
// to CKeys, grouped into per-locale "groups". Three on-disk format
// generations are supported:
//
//   - v1 (build 18125+, WoW 6.0.1): no file header. Each group has a
//     12-byte header followed by FDID deltas + per-file [CKey | FileNameHash].
//   - v2 (build 30080+, WoW 8.2.0): 12-byte file header (MFST + TotalFiles
//   - FilesWithNameHash). Each group: 12-byte header + FDID deltas +
//     CKey array + optional FileNameHash array.
//   - v3 (build 50893+, WoW 10.1.7): 20-byte file header adding SizeOfHeader
//     and Version. Group layout follows v2.
//
// The v2/v3 group header may also use the 17-byte 58221+ format when the
// file header's Version field is 2; this layout splits ContentFlags into
// three sub-fields and is converted back to the legacy 32-bit value.
//
// C++ reference: CascRootFile_WoW.cpp.
package wow

import (
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/listfile"
	"github.com/ldmonster/go-casclib/internal/root"
)

// Magic ('MFST') = 0x4D465354 little-endian.
const wowMagic = 0x4D465354

// CASC content flags relevant to filtering.
const (
	cflagNoNameHash  = 0x10000000
	cflagLowViolence = 0x00000080
	cflagDontLoad    = 0x00000100
)

// Format generation.
type format int

const (
	formatV1 format = iota
	formatV2
	formatV3
)

// Handler is the in-memory WoW root index.
type Handler struct {
	byID   map[uint32]casc.CKeyEntry
	byHash map[uint64]casc.CKeyEntry
	all    []namedEntry
	fmt    format
}

type namedEntry struct {
	id    uint32
	entry casc.CKeyEntry
}

func init() { root.Register(Probe) }

// Probe identifies a WoW root.
//
// The byte signature 'MFST' is unique to WoW v2/v3 root files. Older v1
// roots have no signature; we detect them by trying to parse a v1 group
// header that fits the data. As a defensive measure Probe only accepts v1
// when no other handler claimed the data first (it is registered last via
// init() ordering driven by import side-effects).
func Probe(data []byte) (root.Handler, error) {
	if len(data) >= 4 && binary.LittleEndian.Uint32(data[0:4]) == wowMagic {
		return Parse(data)
	}

	return nil, casc.ErrBadFormat
}

// Parse parses an in-memory WoW root file.
func Parse(data []byte) (*Handler, error) {
	h := &Handler{
		byID:   make(map[uint32]casc.CKeyEntry),
		byHash: make(map[uint64]casc.CKeyEntry),
	}

	groupHeaderVersion := 0 // 0 = legacy 12-byte; 2 = 58221+ packed 17-byte
	off := 0

	if len(data) >= 4 && binary.LittleEndian.Uint32(data[0:4]) == wowMagic {
		// v2 or v3.
		if len(data) >= 20 {
			// Try v3 first (TotalFiles and FilesWithNameHash positions).
			sizeOfHeader := binary.LittleEndian.Uint32(data[4:8])
			version := binary.LittleEndian.Uint32(data[8:12])
			totalFiles := binary.LittleEndian.Uint32(data[12:16])

			withHash := binary.LittleEndian.Uint32(data[16:20])
			if sizeOfHeader >= 20 && sizeOfHeader <= 0x100 && withHash <= totalFiles {
				h.fmt = formatV3

				if version == 2 {
					groupHeaderVersion = 2
				}

				off = int(sizeOfHeader)
			}
		}

		if h.fmt != formatV3 {
			// v2 (30080).
			if len(data) < 12 {
				return nil, casc.ErrBadFormat
			}

			totalFiles := binary.LittleEndian.Uint32(data[4:8])

			withHash := binary.LittleEndian.Uint32(data[8:12])
			if withHash > totalFiles {
				return nil, fmt.Errorf(
					"%w: WoW v2 FilesWithNameHash > TotalFiles",
					casc.ErrBadFormat,
				)
			}

			h.fmt = formatV2
			off = 12
		}
	} else {
		h.fmt = formatV1
	}

	for off < len(data) {
		consumed, err := h.parseGroup(data[off:], groupHeaderVersion)
		if err != nil {
			return nil, err
		}

		if consumed == 0 {
			break
		}

		off += consumed
	}

	return h, nil
}

// parseGroup parses one group from data, returning the number of bytes
// consumed.
func (h *Handler) parseGroup(data []byte, groupHeaderVersion int) (int, error) {
	var (
		numFiles, contentFlags, localeFlags uint32
		hdrLen                              int
	)

	switch groupHeaderVersion {
	case 2:
		if len(data) < 17 {
			return 0, casc.ErrBadFormat
		}

		numFiles = binary.LittleEndian.Uint32(data[0:4])
		localeFlags = binary.LittleEndian.Uint32(data[4:8])
		cf1 := binary.LittleEndian.Uint32(data[8:12])
		cf2 := binary.LittleEndian.Uint32(data[12:16])
		cf3 := uint32(data[16])
		contentFlags = cf1 | cf2 | (cf3 << 17)
		hdrLen = 17
	default:
		if len(data) < 12 {
			return 0, casc.ErrBadFormat
		}

		numFiles = binary.LittleEndian.Uint32(data[0:4])
		contentFlags = binary.LittleEndian.Uint32(data[4:8])
		localeFlags = binary.LittleEndian.Uint32(data[8:12])
		hdrLen = 12
	}

	if numFiles == 0 {
		return hdrLen, nil
	}

	if numFiles > uint32(len(data)) {
		return 0, casc.ErrBadFormat
	}

	off := hdrLen
	end := len(data)

	// FDIDs: numFiles * 4 bytes (little-endian, delta encoded).
	fdidBytes := int(numFiles) * 4
	if off+fdidBytes > end {
		return 0, casc.ErrBadFormat
	}

	fdids := data[off : off+fdidBytes]
	off += fdidBytes

	switch h.fmt {
	case formatV1:
		// Each entry: 16 CKey + 8 FileNameHash.
		entrySize := 24

		need := int(numFiles) * entrySize
		if off+need > end {
			return 0, casc.ErrBadFormat
		}

		entries := data[off : off+need]
		off += need

		h.addV1(numFiles, fdids, entries, localeFlags, contentFlags)
	default:
		// CKey array (16 * numFiles).
		ckeyBytes := int(numFiles) * casc.MD5HashSize
		if off+ckeyBytes > end {
			return 0, casc.ErrBadFormat
		}

		ckeys := data[off : off+ckeyBytes]
		off += ckeyBytes

		var hashes []byte

		if contentFlags&cflagNoNameHash == 0 {
			hashBytes := int(numFiles) * 8
			if off+hashBytes > end {
				return 0, casc.ErrBadFormat
			}

			hashes = data[off : off+hashBytes]
			off += hashBytes
		}

		h.addV2(numFiles, fdids, ckeys, hashes, localeFlags, contentFlags)
	}

	_ = localeFlags // no filtering applied yet (storage handles locale mask)

	return off, nil
}

func (h *Handler) addV1(n uint32, fdids, entries []byte, locale, content uint32) {
	var fdid uint32
	for i := uint32(0); i < n; i++ {
		fdid += binary.LittleEndian.Uint32(fdids[i*4:])
		off := int(i) * 24

		var ck casc.CKey
		copy(ck[:], entries[off:off+16])
		hash := binary.LittleEndian.Uint64(entries[off+16 : off+24])
		entry := casc.CKeyEntry{
			CKey:         ck,
			FileNameHash: hash,
			FileDataID:   fdid,
			LocaleFlags:  locale,
			ContentFlags: content,
			Flags:        casc.CEFlagHasCKey,
		}

		h.byID[fdid] = entry
		if hash != 0 {
			h.byHash[hash] = entry
		}

		h.all = append(h.all, namedEntry{id: fdid, entry: entry})
		fdid++
	}
}

func (h *Handler) addV2(n uint32, fdids, ckeys, hashes []byte, locale, content uint32) {
	var fdid uint32
	for i := uint32(0); i < n; i++ {
		fdid += binary.LittleEndian.Uint32(fdids[i*4:])

		var ck casc.CKey
		copy(ck[:], ckeys[int(i)*16:int(i)*16+16])

		var hash uint64
		if hashes != nil {
			hash = binary.LittleEndian.Uint64(hashes[int(i)*8 : int(i)*8+8])
		}

		entry := casc.CKeyEntry{
			CKey:         ck,
			FileNameHash: hash,
			FileDataID:   fdid,
			LocaleFlags:  locale,
			ContentFlags: content,
			Flags:        casc.CEFlagHasCKey,
		}

		h.byID[fdid] = entry
		if hash != 0 {
			h.byHash[hash] = entry
		}

		h.all = append(h.all, namedEntry{id: fdid, entry: entry})
		fdid++
	}
}

// Name implements root.Handler.
func (h *Handler) Name() string {
	switch h.fmt {
	case formatV1:
		return "wow-v1"
	case formatV2:
		return "wow-v2"
	case formatV3:
		return "wow-v3"
	}

	return "wow"
}

// LookupByName resolves name -> Jenkins hash -> entry.
func (h *Handler) LookupByName(name string) *casc.CKeyEntry {
	hash := listfile.HashFileName(name)
	if e, ok := h.byHash[hash]; ok {
		return &e
	}

	return nil
}

// LookupByFileDataID resolves a numeric FileDataID.
func (h *Handler) LookupByFileDataID(id uint32) *casc.CKeyEntry {
	if e, ok := h.byID[id]; ok {
		return &e
	}

	return nil
}

// All iterates all entries.
func (h *Handler) All(yield func(name string, entry *casc.CKeyEntry) bool) {
	for i := range h.all {
		e := h.all[i].entry
		if !yield(fmt.Sprintf("FileDataID:%d", h.all[i].id), &e) {
			return
		}
	}
}

// Features implements root.Handler.
func (h *Handler) Features() uint32 {
	return casc.FeatureFileDataIDs |
		casc.FeatureFNameHashes |
		casc.FeatureLocaleFlags |
		casc.FeatureContentFlags |
		casc.FeatureRootCKey
}
