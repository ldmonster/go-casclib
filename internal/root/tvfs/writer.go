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

// TVFS root writer.
//
// Emits a minimal TVFS image: one flat root folder containing N files,
// each backed by a single span (no patches, no checksums, no nested
// directories). Sufficient for synthetic storages produced by
// pkg/casc.CreateStorage; also useful as a building block for richer
// trees in the future.
//
// C++ reference: CascRootFile_TVFS.cpp.

package tvfs

import (
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// WriteEntry is one (name, EKey, content size) record.
type WriteEntry struct {
	Name        string
	EKey        casc.EKey
	ContentSize uint32
}

// WriteOptions controls Encode.
type WriteOptions struct {
	// Lowercase mirrors FlagLowercaseManifest. Names in the manifest are
	// stored as-is; consumers receive them lowercased on lookup.
	Lowercase bool
}

// Encode serialises a TVFS root containing the given top-level files.
//
// All files are placed in the root directory; no nesting is performed.
// Slashes in names are emitted verbatim as part of the name string,
// matching how upstream CascLib treats flat layouts in the simplest case.
func Encode(entries []WriteEntry, opts WriteOptions) ([]byte, error) {
	for _, e := range entries {
		if len(e.Name) == 0 || len(e.Name) > 0xFE {
			return nil, fmt.Errorf("%w: tvfs name length %d", casc.ErrInvalidParameter, len(e.Name))
		}
	}

	const headerSize = 38

	// Path table body: per entry = 1 (nameLen) + nameLen + 5 (NodeValue).
	pathBodySize := 0
	for _, e := range entries {
		pathBodySize += 1 + len(e.Name) + 5
	}

	// Folder wrapper at start of path table = 5 bytes (0xFF + BE u32 size).
	pathTableSize := 5 + pathBodySize

	cftTableSize := 9 * len(entries)
	cftOffsSize := offsetFieldSize(uint32(cftTableSize))

	// VFS table: per entry = 1 (spanCount) + 4 (ContentOffset) + 4 (ContentSize) + cftOffsSize (CFTOffset).
	vfsItemSize := 1 + 4 + 4 + cftOffsSize
	vfsTableSize := vfsItemSize * len(entries)

	// Layout offsets.
	pathTableOffset := uint32(headerSize)
	vfsTableOffset := pathTableOffset + uint32(pathTableSize)
	cftTableOffset := vfsTableOffset + uint32(vfsTableSize)

	totalSize := int(cftTableOffset) + cftTableSize

	out := make([]byte, totalSize)

	// Header.
	binary.LittleEndian.PutUint32(out[0:4], tvfsMagic)
	out[4] = 1 // formatVersion
	out[5] = headerSize
	out[6] = 9 // ekeySize
	out[7] = 9 // patchKeySize

	var flags uint32
	if opts.Lowercase {
		flags |= FlagLowercaseManifest
	}

	binary.LittleEndian.PutUint32(out[8:12], flags)
	putBE32w(out[12:16], pathTableOffset)
	putBE32w(out[16:20], uint32(pathTableSize))
	putBE32w(out[20:24], vfsTableOffset)
	putBE32w(out[24:28], uint32(vfsTableSize))
	putBE32w(out[28:32], cftTableOffset)
	putBE32w(out[32:36], uint32(cftTableSize))
	binary.BigEndian.PutUint16(out[36:38], 1) // maxDepth

	// Path table folder wrapper.
	pt := out[pathTableOffset:][:pathTableSize]
	pt[0] = 0xFF
	// folder size = 4 (the BE32 itself) + body size
	putBE32w(pt[1:5], folderNodeBit|uint32(4+pathBodySize))

	// Path entries: name + NodeValue(vfsOffset).
	off := 5

	for i, e := range entries {
		pt[off] = byte(len(e.Name))
		off++
		copy(pt[off:off+len(e.Name)], e.Name)
		off += len(e.Name)
		pt[off] = 0xFF
		putBE32w(pt[off+1:off+5], uint32(i*vfsItemSize))
		off += 5
	}

	// VFS table.
	vt := out[vfsTableOffset:][:vfsTableSize]

	for i, e := range entries {
		base := i * vfsItemSize
		vt[base] = 1 // spanCount
		// ContentOffset = 0
		putBE32w(vt[base+5:base+9], e.ContentSize)
		writeVarBE(vt[base+9:base+9+cftOffsSize], uint32(i*9), cftOffsSize)
	}

	// CFT table.
	ct := out[cftTableOffset:][:cftTableSize]
	for i, e := range entries {
		copy(ct[i*9:(i+1)*9], e.EKey[:9])
	}

	return out, nil
}

func putBE32w(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func writeVarBE(b []byte, v uint32, n int) {
	for i := 0; i < n; i++ {
		b[n-1-i] = byte(v >> (8 * uint(i)))
	}
}
