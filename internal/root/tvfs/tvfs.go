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

// Package tvfs is the Go implementation of the TVFS root handler used by
// WoW 8.2+, StarCraft II, Heroes of the Storm, and most post-2018 Blizzard
// products.
//
// C++ reference: CascRootFile_TVFS.cpp.
package tvfs

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/root"
)

// TVFS magic is 'TVFS' = 0x53465654 little-endian.
const tvfsMagic = 0x53465654

// Flag bits.
const (
	FlagIncludeCKey       = 0x0001
	FlagWriteSupport      = 0x0002
	FlagPatchSupport      = 0x0004
	FlagLowercaseManifest = 0x0008
)

// Path-table-entry flags (in-memory).
const (
	pteSepPre    = 0x01
	pteSepPost   = 0x02
	pteNodeValue = 0x04
)

// Folder node flag in NodeValue.
const (
	folderNodeBit  = 0x80000000
	folderSizeMask = 0x7FFFFFFF
)

// header is the parsed TVFS_DIRECTORY_HEADER.
type header struct {
	formatVersion   byte
	ekeySize        byte
	patchKeySize    byte
	headerSize      byte
	flags           uint32
	pathTableOffset uint32
	pathTableSize   uint32
	vfsTableOffset  uint32
	vfsTableSize    uint32
	cftTableOffset  uint32
	cftTableSize    uint32
	maxDepth        uint16
	estTableOffset  uint32
	estTableSize    uint32
	cftOffsSize     int
	estOffsSize     int
}

// Handler is the parsed TVFS file -> EKey map.
type Handler struct {
	hdr   header
	files map[string]casc.CKeyEntry
	all   []namedEntry
}

type namedEntry struct {
	name  string
	entry casc.CKeyEntry
}

func init() { root.Register(Probe) }

// Probe identifies a TVFS root and parses it.
func Probe(data []byte) (root.Handler, error) {
	if len(data) < 4 {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint32(data[0:4]) != tvfsMagic {
		return nil, casc.ErrBadFormat
	}

	return Parse(data)
}

// Parse parses an in-memory TVFS root file.
func Parse(data []byte) (*Handler, error) {
	hdr, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		hdr:   *hdr,
		files: make(map[string]casc.CKeyEntry),
	}
	if err := h.parseRoot(data); err != nil {
		return nil, err
	}

	return h, nil
}

func parseHeader(data []byte) (*header, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("%w: TVFS header too small", casc.ErrBadFormat)
	}

	if binary.LittleEndian.Uint32(data[0:4]) != tvfsMagic {
		return nil, casc.ErrBadFormat
	}

	h := &header{
		formatVersion: data[4],
		headerSize:    data[5],
		ekeySize:      data[6],
		patchKeySize:  data[7],
	}
	if h.formatVersion != 1 || h.ekeySize != 9 || h.patchKeySize != 9 {
		return nil, fmt.Errorf("%w: TVFS unsupported sizes (v=%d ek=%d pk=%d)",
			casc.ErrNotSupported, h.formatVersion, h.ekeySize, h.patchKeySize)
	}

	h.flags = binary.LittleEndian.Uint32(data[8:12])
	h.pathTableOffset = casc.BEUint32(data[12:16])
	h.pathTableSize = casc.BEUint32(data[16:20])
	h.vfsTableOffset = casc.BEUint32(data[20:24])
	h.vfsTableSize = casc.BEUint32(data[24:28])
	h.cftTableOffset = casc.BEUint32(data[28:32])
	h.cftTableSize = casc.BEUint32(data[32:36])

	h.maxDepth = casc.BEUint16(data[36:38])
	if h.flags&FlagWriteSupport != 0 && len(data) >= 46 {
		h.estTableOffset = casc.BEUint32(data[38:42])
		h.estTableSize = casc.BEUint32(data[42:46])
	}

	h.cftOffsSize = offsetFieldSize(h.cftTableSize)
	h.estOffsSize = offsetFieldSize(h.estTableSize)

	if int(h.pathTableOffset)+int(h.pathTableSize) > len(data) ||
		int(h.vfsTableOffset)+int(h.vfsTableSize) > len(data) ||
		int(h.cftTableOffset)+int(h.cftTableSize) > len(data) {
		return nil, fmt.Errorf("%w: TVFS table out of bounds", casc.ErrBadFormat)
	}

	return h, nil
}

func offsetFieldSize(tableSize uint32) int {
	switch {
	case tableSize > 0xFFFFFF:
		return 4
	case tableSize > 0xFFFF:
		return 3
	case tableSize > 0xFF:
		return 2
	default:
		return 1
	}
}

// parseRoot dispatches to the recursive directory parser at the path table.
func (h *Handler) parseRoot(data []byte) error {
	pt := data[h.hdr.pathTableOffset : h.hdr.pathTableOffset+h.hdr.pathTableSize]

	body := pt
	if len(body) >= 5 && body[0] == 0xFF {
		nv := casc.BEUint32(body[1:5])
		if nv&folderNodeBit == 0 {
			return fmt.Errorf("%w: TVFS root NodeValue lacks folder bit", casc.ErrBadFormat)
		}

		size := int(nv & folderSizeMask)
		if size < 4 || 1+size > len(pt) {
			return fmt.Errorf("%w: TVFS root size %d out of range", casc.ErrBadFormat, size)
		}

		body = body[5 : 1+size]
	}

	return h.walk(data, body, "")
}

func (h *Handler) walk(data, region []byte, prefix string) error {
	for len(region) > 0 {
		entry, rest, err := parsePathEntry(region)
		if err != nil {
			return err
		}

		region = rest

		path := prefix
		if entry.flags&pteSepPre != 0 {
			path += "/"
		}

		path += entry.name
		if entry.flags&pteSepPost != 0 {
			path += "/"
		}

		if entry.flags&pteNodeValue == 0 {
			continue
		}

		if entry.value&folderNodeBit != 0 {
			subSize := int(entry.value&folderSizeMask) - 4
			if subSize < 0 || subSize > len(region) {
				return fmt.Errorf(
					"%w: TVFS sub-dir size %d out of range",
					casc.ErrBadFormat,
					subSize,
				)
			}

			if err := h.walk(data, region[:subSize], path); err != nil {
				return err
			}

			region = region[subSize:]

			continue
		}

		ckey, err := h.resolveVfs(data, entry.value)
		if err != nil {
			continue
		}

		final := path
		if h.hdr.flags&FlagLowercaseManifest != 0 {
			final = strings.ToLower(final)
		}

		h.files[final] = ckey
		h.all = append(h.all, namedEntry{name: final, entry: ckey})
	}

	return nil
}

type pathEntry struct {
	name  string
	flags byte
	value uint32
}

func parsePathEntry(buf []byte) (pathEntry, []byte, error) {
	var pe pathEntry
	if len(buf) == 0 {
		return pe, nil, fmt.Errorf("%w: empty path entry", casc.ErrBadFormat)
	}

	if buf[0] == 0x00 {
		pe.flags |= pteSepPre
		buf = buf[1:]
	}

	if len(buf) > 0 && buf[0] != 0xFF {
		nLen := int(buf[0])

		buf = buf[1:]
		if nLen > len(buf) {
			return pe, nil, fmt.Errorf(
				"%w: TVFS name length %d > %d",
				casc.ErrBadFormat,
				nLen,
				len(buf),
			)
		}

		pe.name = string(buf[:nLen])
		buf = buf[nLen:]
	}

	if len(buf) > 0 && buf[0] == 0x00 {
		pe.flags |= pteSepPost
		buf = buf[1:]
	}

	if len(buf) > 0 {
		if buf[0] == 0xFF {
			if len(buf) < 5 {
				return pe, nil, fmt.Errorf("%w: TVFS NodeValue truncated", casc.ErrBadFormat)
			}

			pe.value = casc.BEUint32(buf[1:5])
			pe.flags |= pteNodeValue
			buf = buf[5:]
		} else {
			pe.flags |= pteSepPost
		}
	}

	return pe, buf, nil
}

// resolveVfs returns the first-span CKeyEntry for a VFS offset.
func (h *Handler) resolveVfs(data []byte, vfsOffset uint32) (casc.CKeyEntry, error) {
	if int(vfsOffset) >= int(h.hdr.vfsTableSize) {
		return casc.CKeyEntry{}, fmt.Errorf("%w: VFS offset %d", casc.ErrBadFormat, vfsOffset)
	}

	vfs := data[h.hdr.vfsTableOffset:][vfsOffset:]
	if len(vfs) == 0 {
		return casc.CKeyEntry{}, casc.ErrBadFormat
	}

	spanCount := int(vfs[0])
	if spanCount < 1 || spanCount > 224 {
		return casc.CKeyEntry{}, fmt.Errorf("%w: TVFS span count %d", casc.ErrBadFormat, spanCount)
	}

	vfs = vfs[1:]

	itemSize := 4 + 4 + h.hdr.cftOffsSize
	if len(vfs) < itemSize {
		return casc.CKeyEntry{}, casc.ErrBadFormat
	}

	contentSize := casc.BEUint32(vfs[4:8])
	cftOff := readVarBE(vfs[8:8+h.hdr.cftOffsSize], h.hdr.cftOffsSize)

	if int(cftOff) >= int(h.hdr.cftTableSize) {
		return casc.CKeyEntry{}, casc.ErrBadFormat
	}

	cft := data[h.hdr.cftTableOffset:][cftOff:]
	if len(cft) < int(h.hdr.ekeySize) {
		return casc.CKeyEntry{}, casc.ErrBadFormat
	}

	var ek casc.EKey
	copy(ek[:h.hdr.ekeySize], cft[:h.hdr.ekeySize])

	return casc.CKeyEntry{
		EKey:        ek,
		ContentSize: uint64(contentSize),
		FileDataID:  casc.InvalidID,
		Flags:       casc.CEFlagHasEKey,
		SpanCount:   uint16(spanCount),
	}, nil
}

func readVarBE(b []byte, n int) uint32 {
	var v uint32
	for i := 0; i < n; i++ {
		v = (v << 8) | uint32(b[i])
	}

	return v
}

// Name implements root.Handler.
func (h *Handler) Name() string { return "tvfs" }

// LookupByName implements root.Handler.
func (h *Handler) LookupByName(name string) *casc.CKeyEntry {
	if h.hdr.flags&FlagLowercaseManifest != 0 {
		name = strings.ToLower(name)
	}

	if e, ok := h.files[name]; ok {
		return &e
	}

	return nil
}

// LookupByFileDataID implements root.Handler. TVFS does not encode FDIDs.
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
func (h *Handler) Features() uint32 { return casc.FeatureFileNames }
