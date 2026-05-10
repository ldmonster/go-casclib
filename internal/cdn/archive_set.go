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

package cdn

import (
	"encoding/hex"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// ArchiveLocation pinpoints a single span inside one CDN archive.
type ArchiveLocation struct {
	// ArchiveHashHex is the lowercased hex MD5 of the archive blob, used to
	// build the CDN URL (e.g. "data/aa/bb/<hash>").
	ArchiveHashHex string
	// Offset is the byte offset within the archive blob where the span starts.
	Offset uint64
	// EncodedSize is the on-CDN size of the span.
	EncodedSize uint64
}

// ArchiveSet is the merged map of (EKey -> ArchiveLocation) across all
// archive-index files referenced by the cdn-config's `archives` field.
//
// Lookup is O(1) on the trimmed (first 9 bytes) form of the EKey.
type ArchiveSet struct {
	byEKey map[archiveKey]ArchiveLocation
}

type archiveKey [casc.EKeySize]byte

// NewArchiveSet returns an empty set.
func NewArchiveSet() *ArchiveSet {
	return &ArchiveSet{byEKey: make(map[archiveKey]ArchiveLocation)}
}

// Add merges an archive-index into the set. archiveHash is the binary
// 16-byte MD5 of the archive blob (the value listed in cdn-config's
// `archives` field).
func (s *ArchiveSet) Add(archiveHash [casc.MD5HashSize]byte, idx *ArchiveIndex) {
	hexHash := hex.EncodeToString(archiveHash[:])

	for _, e := range idx.Entries {
		var k archiveKey
		copy(k[:], e.EKey[:casc.EKeySize])

		if _, exists := s.byEKey[k]; exists {
			continue
		}

		s.byEKey[k] = ArchiveLocation{
			ArchiveHashHex: hexHash,
			Offset:         e.Offset,
			EncodedSize:    e.EncodedSize,
		}
	}
}

// Lookup returns the archive location of the given EKey, or false if absent.
func (s *ArchiveSet) Lookup(e casc.EKey) (ArchiveLocation, bool) {
	if s == nil || len(s.byEKey) == 0 {
		return ArchiveLocation{}, false
	}

	var k archiveKey
	copy(k[:], e[:casc.EKeySize])
	loc, ok := s.byEKey[k]

	return loc, ok
}

// Len reports the number of distinct EKeys in the set.
func (s *ArchiveSet) Len() int {
	if s == nil {
		return 0
	}

	return len(s.byEKey)
}
