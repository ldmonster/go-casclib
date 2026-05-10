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

// WoW root writer.
//
// Emits a v2 (MFST) WoW root containing a single group whose locale
// covers all locales and whose content flags carry no name-hash. This is
// sufficient for synthetic storages produced by pkg/casc.CreateStorage
// and other tooling that needs an FDID-addressable root.
//
// More elaborate emitters (multiple groups, locale-partitioned, v3 with
// SizeOfHeader/Version, packed group header) can be layered on top of
// this primitive.
//
// C++ reference: CascRootFile_WoW.cpp.

package wow

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// WriteEntry is one (FileDataID, CKey, optional FileNameHash) record.
type WriteEntry struct {
	FileDataID   uint32
	CKey         casc.CKey
	FileNameHash uint64 // 0 means none
}

// WriteOptions controls Encode.
type WriteOptions struct {
	// LocaleFlags applies to the single emitted group. Defaults to all
	// locales (0xFFFFFFFF).
	LocaleFlags uint32
	// ContentFlags applies to the single emitted group. NoNameHash
	// (0x10000000) is set automatically when no entry carries a hash.
	ContentFlags uint32
}

// Encode emits a v2 WoW root containing all entries in a single group.
//
// Entries are sorted by FileDataID; duplicates are an error.
func Encode(entries []WriteEntry, opts WriteOptions) ([]byte, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: no entries", casc.ErrInvalidParameter)
	}

	if opts.LocaleFlags == 0 {
		opts.LocaleFlags = 0xFFFFFFFF
	}

	cp := make([]WriteEntry, len(entries))
	copy(cp, entries)
	sort.Slice(cp, func(i, j int) bool { return cp[i].FileDataID < cp[j].FileDataID })

	for i := 1; i < len(cp); i++ {
		if cp[i].FileDataID == cp[i-1].FileDataID {
			return nil, fmt.Errorf("%w: duplicate FDID %d",
				casc.ErrInvalidParameter, cp[i].FileDataID)
		}
	}

	hasHash := false

	for _, e := range cp {
		if e.FileNameHash != 0 {
			hasHash = true
			break
		}
	}

	contentFlags := opts.ContentFlags

	if !hasHash {
		contentFlags |= cflagNoNameHash
	} else {
		contentFlags &^= cflagNoNameHash
	}

	totalFiles := uint32(len(cp))

	withHash := uint32(0)
	if hasHash {
		withHash = totalFiles
	}

	// File header (v2 layout): 'MFST' + TotalFiles + FilesWithNameHash.
	const fileHdrSize = 12
	// Group header (12 bytes): NumFiles + ContentFlags + LocaleFlags.
	const groupHdrSize = 12

	fdidBytes := int(totalFiles) * 4
	ckeyBytes := int(totalFiles) * casc.MD5HashSize

	hashBytes := 0
	if hasHash {
		hashBytes = int(totalFiles) * 8
	}

	total := fileHdrSize + groupHdrSize + fdidBytes + ckeyBytes + hashBytes
	out := make([]byte, total)

	binary.LittleEndian.PutUint32(out[0:4], wowMagic)
	binary.LittleEndian.PutUint32(out[4:8], totalFiles)
	binary.LittleEndian.PutUint32(out[8:12], withHash)

	groupOff := fileHdrSize
	binary.LittleEndian.PutUint32(out[groupOff:groupOff+4], totalFiles)
	binary.LittleEndian.PutUint32(out[groupOff+4:groupOff+8], contentFlags)
	binary.LittleEndian.PutUint32(out[groupOff+8:groupOff+12], opts.LocaleFlags)

	// FDID deltas. Reader: fdid += delta_i; then fdid++.
	// Want fdid_i after the += step. With prevPost = (wantedFdid_{i-1}+1) and
	// initial prevPost = 0, delta_i = wantedFdid_i - prevPost.
	fdidOff := groupOff + groupHdrSize

	var prevPost uint32
	for i, e := range cp {
		delta := e.FileDataID - prevPost
		binary.LittleEndian.PutUint32(out[fdidOff+i*4:fdidOff+i*4+4], delta)

		prevPost = e.FileDataID + 1
	}

	// CKey array.
	ckeyOff := fdidOff + fdidBytes
	for i, e := range cp {
		copy(out[ckeyOff+i*16:ckeyOff+(i+1)*16], e.CKey[:])
	}

	// FileNameHash array (only when hasHash).
	if hasHash {
		hashOff := ckeyOff + ckeyBytes
		for i, e := range cp {
			binary.LittleEndian.PutUint64(out[hashOff+i*8:hashOff+(i+1)*8], e.FileNameHash)
		}
	}

	return out, nil
}
