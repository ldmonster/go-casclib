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

// Package diablo3 implements the Diablo III root directory file handler.
//
// Diablo III's root structure is a tree of "directory" files (each itself
// a CASC file). The top-level root file lists *named* sub-directory entries
// like "Base", "X1" and "FlagSet". Those names point to CKeys whose
// referenced files are themselves directory blobs (signature
// DIABLO3_SUBDIR_SIGNATURE = 0xEAF1FE87) containing:
//
//  1. asset entries     ([16] CKey + [4 LE] FileIndex)
//  2. asset-idx entries ([16] CKey + [4 LE] FileIndex + [4 LE] SubIndex)
//  3. named entries     ([16] CKey + zero-terminated name)
//
// Translating asset entries into human-readable names (e.g.
// "Actor/0001.acr") additionally requires loading the named "CoreToc.dat"
// and "Packages.dat" files from the storage. The current implementation
// covers parsing of one directory blob (root or subdir) and returning its
// named entries; recursive subdirectory traversal and asset-name synthesis
// require a storage-driven Loader callback, which is exposed via
// LoadSubdirectories.
//
// C++ reference: CascRootFile_Diablo3.cpp.
package diablo3

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/listfile"
	"github.com/ldmonster/go-casclib/internal/root"
)

const (
	rootSignature   uint32 = 0x8007D0C4
	subdirSignature uint32 = 0xEAF1FE87
)

// AssetEntry corresponds to DIABLO3_ASSET_ENTRY.
type AssetEntry struct {
	CKey      casc.CKey
	FileIndex uint32
}

// AssetIdxEntry corresponds to DIABLO3_ASSETIDX_ENTRY.
type AssetIdxEntry struct {
	CKey      casc.CKey
	FileIndex uint32
	SubIndex  uint32
}

// NamedEntry corresponds to DIABLO3_NAMED_ENTRY.
type NamedEntry struct {
	CKey casc.CKey
	Name string
}

// Directory is one parsed directory blob.
type Directory struct {
	Signature uint32
	Assets    []AssetEntry
	AssetIdx  []AssetIdxEntry
	Named     []NamedEntry
}

// Loader resolves a CKey to the bytes of the file referenced by it. Used
// by LoadSubdirectories to walk into nested directory blobs.
type Loader interface {
	ReadByCKey(ck casc.CKey) ([]byte, error)
}

// Handler is the in-memory Diablo III root index. It contains the
// flattened named entries discovered while walking the directory tree.
type Handler struct {
	root   *Directory
	files  map[string]casc.CKeyEntry
	byHash map[uint64]casc.CKeyEntry
	all    []namedEntry
}

type namedEntry struct {
	name  string
	entry casc.CKeyEntry
}

func init() { root.Register(Probe) }

// Probe accepts data starting with the Diablo III root signature.
func Probe(data []byte) (root.Handler, error) {
	if len(data) < 4 {
		return nil, casc.ErrBadFormat
	}

	sig := binary.LittleEndian.Uint32(data[0:4])
	if sig != rootSignature && sig != subdirSignature {
		return nil, casc.ErrBadFormat
	}

	return Parse(data)
}

// Parse parses one directory blob.
func Parse(data []byte) (*Handler, error) {
	dir, err := parseDirectory(data)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		root:   dir,
		files:  make(map[string]casc.CKeyEntry),
		byHash: make(map[uint64]casc.CKeyEntry),
	}
	for _, ne := range dir.Named {
		h.add(ne.Name, ne.CKey)
	}

	return h, nil
}

// LoadSubdirectories descends into named entries that themselves point to
// subdirectory blobs, prefixing entry names with the parent name.
//
// Errors from the loader are tolerated (treated as "not present"); a
// non-directory blob (wrong signature) is also silently skipped.
func (h *Handler) LoadSubdirectories(loader Loader) error {
	if h.root == nil || loader == nil {
		return nil
	}

	for _, ne := range h.root.Named {
		blob, err := loader.ReadByCKey(ne.CKey)
		if err != nil || len(blob) < 4 {
			continue
		}

		sig := binary.LittleEndian.Uint32(blob[0:4])
		if sig != subdirSignature && sig != rootSignature {
			continue
		}

		sub, err := parseDirectory(blob)
		if err != nil {
			continue
		}

		for _, child := range sub.Named {
			full := ne.Name + "/" + child.Name
			h.add(full, child.CKey)
		}
		// Asset names are synthesised as "<parent>/<index>".
		for _, a := range sub.Assets {
			full := fmt.Sprintf("%s/Asset%d", ne.Name, a.FileIndex)
			h.add(full, a.CKey)
		}

		for _, a := range sub.AssetIdx {
			full := fmt.Sprintf("%s/Asset%d_%d", ne.Name, a.FileIndex, a.SubIndex)
			h.add(full, a.CKey)
		}
	}

	return nil
}

func (h *Handler) add(name string, ck casc.CKey) {
	hash := listfile.HashFileName(name)
	entry := casc.CKeyEntry{
		CKey:         ck,
		FileNameHash: hash,
		FileDataID:   casc.InvalidID,
		Flags:        casc.CEFlagHasCKey,
	}
	h.files[name] = entry
	h.byHash[hash] = entry
	h.all = append(h.all, namedEntry{name: name, entry: entry})
}

func parseDirectory(data []byte) (*Directory, error) {
	if len(data) < 4 {
		return nil, casc.ErrBadFormat
	}

	sig := binary.LittleEndian.Uint32(data[0:4])
	if sig != rootSignature && sig != subdirSignature {
		return nil, fmt.Errorf("%w: Diablo3 directory signature %#x", casc.ErrBadFormat, sig)
	}

	d := &Directory{Signature: sig}
	off := 4

	if sig == subdirSignature {
		// Asset entries (16 + 4).
		if off+4 > len(data) {
			return nil, casc.ErrBadFormat
		}

		n := int(binary.LittleEndian.Uint32(data[off : off+4]))
		off += 4

		entrySize := 16 + 4
		if off+n*entrySize > len(data) {
			return nil, fmt.Errorf("%w: D3 asset entries truncated", casc.ErrBadFormat)
		}

		d.Assets = make([]AssetEntry, n)
		for i := 0; i < n; i++ {
			copy(d.Assets[i].CKey[:], data[off:off+16])
			d.Assets[i].FileIndex = binary.LittleEndian.Uint32(data[off+16 : off+20])
			off += entrySize
		}

		// Asset-idx entries (16 + 4 + 4).
		if off+4 > len(data) {
			return nil, casc.ErrBadFormat
		}

		n = int(binary.LittleEndian.Uint32(data[off : off+4]))
		off += 4

		entrySize = 16 + 4 + 4
		if off+n*entrySize > len(data) {
			return nil, fmt.Errorf("%w: D3 asset-idx entries truncated", casc.ErrBadFormat)
		}

		d.AssetIdx = make([]AssetIdxEntry, n)
		for i := 0; i < n; i++ {
			copy(d.AssetIdx[i].CKey[:], data[off:off+16])
			d.AssetIdx[i].FileIndex = binary.LittleEndian.Uint32(data[off+16 : off+20])
			d.AssetIdx[i].SubIndex = binary.LittleEndian.Uint32(data[off+20 : off+24])
			off += entrySize
		}
	}

	// Named entries: count followed by an array of (16 CKey + cstr name).
	if off+4 > len(data) {
		return nil, casc.ErrBadFormat
	}

	n := int(binary.LittleEndian.Uint32(data[off : off+4]))
	off += 4

	d.Named = make([]NamedEntry, 0, n)
	for i := 0; i < n; i++ {
		if off+16 > len(data) {
			return nil, fmt.Errorf("%w: D3 named entry CKey truncated", casc.ErrBadFormat)
		}

		var ck casc.CKey
		copy(ck[:], data[off:off+16])
		off += 16

		end := bytes.IndexByte(data[off:], 0)
		if end < 0 {
			return nil, fmt.Errorf("%w: D3 named entry filename unterminated", casc.ErrBadFormat)
		}

		name := string(data[off : off+end])
		off += end + 1

		d.Named = append(d.Named, NamedEntry{CKey: ck, Name: name})
	}

	return d, nil
}

// Name implements root.Handler.
func (h *Handler) Name() string { return "Diablo3" }

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

// LookupByFileDataID implements root.Handler. Diablo III root has no FDIDs.
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
	return casc.FeatureFileNames | casc.FeatureRootCKey
}
