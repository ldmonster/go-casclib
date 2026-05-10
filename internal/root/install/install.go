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

// Package install implements the INSTALL manifest root handler.
//
// The INSTALL manifest is a small flat file mapping installer / launcher
// filenames directly to CKey hashes. It carries optional "tags" that are
// per-entry boolean flags grouped into bitmaps -- typically used to mark
// platform-specific files (Windows / OSX / x86_64 / locale).
//
// On-disk layout (version 1):
//
//	[2] Magic = 'IN' (0x494E)
//	[1] Version = 1
//	[1] HashSize (typically 16; named "EKeyLength" in CascLib for legacy
//	    reasons but the values are CKeys)
//	[2 BE] TagCount
//	[4 BE] EntryCount
//	-- header end --
//	for each tag:
//	  [zero-terminated] tag name
//	  [2 BE] tag type
//	  [ceil(EntryCount/8)] entry bitmap
//	for each entry:
//	  [zero-terminated] filename
//	  [HashSize] CKey
//	  [4 BE] file size
//
// C++ reference: CascRootFile_Install.cpp.
package install

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/listfile"
	"github.com/ldmonster/go-casclib/internal/root"
)

const fileInstallHeaderSize = 10

// Tag is one named tag and the entries it covers.
type Tag struct {
	Name string
	Type uint16
	// Bitmap is one bit per entry, MSB first within each byte.
	Bitmap []byte
}

// Handler holds the parsed manifest.
type Handler struct {
	Version    byte
	HashSize   byte
	TagCount   uint16
	EntryCount uint32

	Tags   []Tag
	files  map[string]casc.CKeyEntry
	byHash map[uint64]casc.CKeyEntry
	all    []namedEntry
}

type namedEntry struct {
	name  string
	entry casc.CKeyEntry
}

func init() { root.Register(Probe) }

// Probe accepts data starting with 'IN' magic.
func Probe(data []byte) (root.Handler, error) {
	if len(data) < fileInstallHeaderSize {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint16(data[0:2]) != casc.MagicInstall {
		return nil, casc.ErrBadFormat
	}

	return Parse(data)
}

// Parse parses an in-memory INSTALL manifest.
func Parse(data []byte) (*Handler, error) {
	if len(data) < fileInstallHeaderSize {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint16(data[0:2]) != casc.MagicInstall {
		return nil, casc.ErrBadFormat
	}

	if data[2] != 1 {
		return nil, fmt.Errorf("%w: INSTALL version %d", casc.ErrNotSupported, data[2])
	}

	hashSize := data[3]
	if hashSize == 0 || hashSize > casc.MD5HashSize {
		return nil, fmt.Errorf("%w: INSTALL HashSize %d", casc.ErrBadFormat, hashSize)
	}

	tagCount := casc.BEUint16(data[4:6])
	entryCount := casc.BEUint32(data[6:10])

	h := &Handler{
		Version:    1,
		HashSize:   hashSize,
		TagCount:   tagCount,
		EntryCount: entryCount,
		files:      make(map[string]casc.CKeyEntry, entryCount),
		byHash:     make(map[uint64]casc.CKeyEntry, entryCount),
	}

	off := fileInstallHeaderSize
	bitmapLen := int((entryCount + 7) / 8)

	// Parse tags.
	for i := uint16(0); i < tagCount; i++ {
		nameEnd := bytes.IndexByte(data[off:], 0)
		if nameEnd < 0 {
			return nil, fmt.Errorf("%w: INSTALL tag name unterminated", casc.ErrBadFormat)
		}

		name := string(data[off : off+nameEnd])

		off += nameEnd + 1
		if off+2+bitmapLen > len(data) {
			return nil, fmt.Errorf("%w: INSTALL tag truncated", casc.ErrBadFormat)
		}

		tagType := casc.BEUint16(data[off : off+2])
		off += 2
		bm := make([]byte, bitmapLen)
		copy(bm, data[off:off+bitmapLen])
		off += bitmapLen

		h.Tags = append(h.Tags, Tag{Name: name, Type: tagType, Bitmap: bm})
	}

	// Parse entries.
	for i := uint32(0); i < entryCount && off < len(data); i++ {
		nameEnd := bytes.IndexByte(data[off:], 0)
		if nameEnd < 0 {
			return nil, fmt.Errorf("%w: INSTALL entry name unterminated", casc.ErrBadFormat)
		}

		name := string(data[off : off+nameEnd])

		off += nameEnd + 1
		if off+int(hashSize)+4 > len(data) {
			return nil, fmt.Errorf("%w: INSTALL entry truncated", casc.ErrBadFormat)
		}

		var ck casc.CKey
		copy(ck[:hashSize], data[off:off+int(hashSize)])
		off += int(hashSize)
		size := casc.BEUint32(data[off : off+4])
		off += 4

		hash := listfile.HashFileName(name)
		entry := casc.CKeyEntry{
			CKey:         ck,
			FileNameHash: hash,
			ContentSize:  uint64(size),
			FileDataID:   casc.InvalidID,
			Flags:        casc.CEFlagHasCKey,
		}
		h.files[name] = entry
		h.byHash[hash] = entry
		h.all = append(h.all, namedEntry{name: name, entry: entry})
	}

	return h, nil
}

// Name implements root.Handler.
func (h *Handler) Name() string { return "Install" }

// LookupByName implements root.Handler.
func (h *Handler) LookupByName(name string) *casc.CKeyEntry {
	if e, ok := h.files[name]; ok {
		return &e
	}

	if e, ok := h.byHash[listfile.HashFileName(name)]; ok {
		return &e
	}

	return nil
}

// LookupByFileDataID implements root.Handler. INSTALL doesn't carry FDIDs.
func (h *Handler) LookupByFileDataID(uint32) *casc.CKeyEntry { return nil }

// All implements root.Handler.
func (h *Handler) All(yield func(name string, entry *casc.CKeyEntry) bool) {
	for i := range h.all {
		e := h.all[i].entry
		if !yield(h.all[i].name, &e) {
			return
		}
	}
}

// Features implements root.Handler.
func (h *Handler) Features() uint32 {
	return casc.FeatureFileNames | casc.FeatureRootCKey | casc.FeatureTags
}
