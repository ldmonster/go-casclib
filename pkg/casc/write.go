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

package casc

import (
	"path/filepath"
	"strings"
)

// Write-side CASC API.
//
// CascLib's CascCreateStorage / CascAddFileToStorage produce a brand-new
// CASC archive: build-config, CDN-config, ENCODING manifest, ROOT
// manifest, DOWNLOAD manifest, INSTALL manifest, .build.info, and BLTE-
// framed data segments — substantial work orthogonal to the read pipeline
// and tracked as a long-running item in rewriting_plan.md §6.2.
//
// In the meantime go-casclib offers a useful subset:
//
//   - AddFile / RemoveFile / RenameFile work on an in-memory overlay
//     that OpenFile and FindFiles consult before the underlying read-only
//     storage. This lets callers compose virtual files for testing or
//     repackaging workflows.
//   - CreateStorage returns an empty in-memory-only Storage. OpenFile
//     and FindFiles work; the resulting handle has no on-disk backing.
//   - Flush returns ErrNotSupported until the on-disk pipeline lands.
//
// C++ reference: CascCreateStorage / CascAddFileToStorage in CascLib.h.

// CreateOptions controls CreateStorage.
type CreateOptions struct {
	// LocaleMask is the default locale mask to embed in manifests once
	// on-disk creation is implemented. Currently advisory.
	LocaleMask uint32

	// MaxFileCount is a hint for initial table sizing (analogous to the
	// upstream dwMaxFileCount). 0 picks a sensible default.
	MaxFileCount uint32
}

// CreateStorage creates an empty in-memory-only storage. The dir
// argument is currently ignored; on-disk persistence requires the full
// manifest builder (see Flush).
//
// Use AddFile / OpenFile / FindFiles to populate and read it. Useful for
// tests and tooling that compose synthetic file trees.
func CreateStorage(dir string, _ CreateOptions) (*Storage, error) {
	return &Storage{
		overlay:   map[string][]byte{},
		removed:   map[string]bool{},
		createDir: dir,
	}, nil
}

// AddFile registers a new file in the storage's in-memory overlay. The
// name uses forward-slash separators; lookups are case-insensitive to
// match upstream FindFiles semantics. Returns ErrAlreadyExists if a file
// with the same (case-folded) name is already in the overlay.
func (s *Storage) AddFile(name string, data []byte) error {
	name = normalizeOverlayName(name)
	if name == "" {
		return ErrInvalidParameter
	}

	s.overlayMu.Lock()
	defer s.overlayMu.Unlock()

	if s.overlay == nil {
		s.overlay = map[string][]byte{}
	}

	if s.removed == nil {
		s.removed = map[string]bool{}
	}

	if _, exists := s.overlay[name]; exists {
		return ErrAlreadyExists
	}

	cp := make([]byte, len(data))
	copy(cp, data)
	s.overlay[name] = cp
	delete(s.removed, name)

	return nil
}

// RemoveFile shadows a file in the overlay so OpenFile/FindFiles report
// it as missing. Works for both overlay-added files and files that exist
// in the underlying read-only storage.
func (s *Storage) RemoveFile(name string) error {
	name = normalizeOverlayName(name)
	if name == "" {
		return ErrInvalidParameter
	}

	s.overlayMu.Lock()
	defer s.overlayMu.Unlock()

	delete(s.overlay, name)

	if s.removed == nil {
		s.removed = map[string]bool{}
	}

	s.removed[name] = true

	return nil
}

// RenameFile renames a file. If the source lives only in the underlying
// read-only storage, an overlay entry is added with the destination name
// and the source is shadowed.
func (s *Storage) RenameFile(oldName, newName string) error {
	oldName = normalizeOverlayName(oldName)
	newName = normalizeOverlayName(newName)

	if oldName == "" || newName == "" {
		return ErrInvalidParameter
	}

	if oldName == newName {
		return nil
	}

	s.overlayMu.Lock()

	if s.overlay == nil {
		s.overlay = map[string][]byte{}
	}

	if s.removed == nil {
		s.removed = map[string]bool{}
	}

	if data, ok := s.overlay[oldName]; ok {
		if _, dstExists := s.overlay[newName]; dstExists {
			s.overlayMu.Unlock()
			return ErrAlreadyExists
		}

		s.overlay[newName] = data
		delete(s.overlay, oldName)
		delete(s.removed, newName)
		s.removed[oldName] = true
		s.overlayMu.Unlock()

		return nil
	}

	// Source lives in the underlying storage. Release the lock to call
	// OpenFile (which itself takes a read lock on overlayMu).
	s.overlayMu.Unlock()

	f, err := s.OpenFile(oldName)
	if err != nil {
		return err
	}

	data := f.content
	_ = f.Close()

	s.overlayMu.Lock()
	defer s.overlayMu.Unlock()

	if _, dstExists := s.overlay[newName]; dstExists {
		return ErrAlreadyExists
	}

	s.overlay[newName] = data
	s.removed[oldName] = true

	return nil
}

// overlayLookup checks the overlay. Returns:
//
//	(data, true,  false) if the overlay has it,
//	(nil,  false, true)  if the overlay marks it as removed,
//	(nil,  false, false) otherwise.
func (s *Storage) overlayLookup(name string) ([]byte, bool, bool) {
	if s == nil {
		return nil, false, false
	}

	key := normalizeOverlayName(name)

	s.overlayMu.RLock()
	defer s.overlayMu.RUnlock()

	if s.removed[key] {
		return nil, false, true
	}

	if data, ok := s.overlay[key]; ok {
		return data, true, false
	}

	return nil, false, false
}

// iterOverlay invokes fn for each overlay entry whose name matches the
// pattern (or all entries when pattern is empty).
func (s *Storage) iterOverlay(pattern string, fn func(name string, info FileInfo) bool) error {
	if s == nil {
		return nil
	}

	patternLower := strings.ToLower(pattern)

	s.overlayMu.RLock()

	type ent struct {
		name string
		size int
	}

	snap := make([]ent, 0, len(s.overlay))
	for k, v := range s.overlay {
		snap = append(snap, ent{name: k, size: len(v)})
	}

	s.overlayMu.RUnlock()

	for _, e := range snap {
		if patternLower != "" && patternLower != "*" {
			ok, err := filepath.Match(patternLower, e.name)
			if err != nil {
				return err
			}

			if !ok {
				continue
			}
		}

		info := FileInfo{
			FileName:    e.name,
			ContentSize: uint64(e.size),
		}

		if !fn(e.name, info) {
			break
		}
	}

	return nil
}

// findOverlayOnly is the FindFiles fallback when there's no underlying root.
func (s *Storage) findOverlayOnly(pattern string, fn func(name string, info FileInfo) bool) error {
	if s == nil {
		return ErrNotSupported
	}

	if s.overlay == nil {
		return ErrNotSupported
	}

	return s.iterOverlay(pattern, fn)
}

// normalizeOverlayName lower-cases and forward-slashes a file name to
// match the case-insensitive lookup semantics used by FindFiles.
func normalizeOverlayName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimSpace(name)

	return strings.ToLower(name)
}
