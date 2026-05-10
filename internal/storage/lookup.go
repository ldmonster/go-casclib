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

package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ldmonster/go-casclib/internal/archive"
	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/encoding"
	"github.com/ldmonster/go-casclib/internal/index"
	"github.com/ldmonster/go-casclib/internal/root"
)

// EKeyKey is the trimmed (first 9 bytes of an EKey) lookup key. Local
// indexes store EKeys at this width.
type EKeyKey [casc.EKeySize]byte

// EKeyOf returns the trimmed lookup key from a full EKey.
func EKeyOf(e casc.EKey) EKeyKey {
	var k EKeyKey
	copy(k[:], e[:casc.EKeySize])

	return k
}

// buildEKeyMap merges all parsed indexes into a single trimmed-EKey -> entry
// map. When the same EKey appears in multiple buckets, the entry from the
// most-recent (largest version / first-seen) bucket wins; ties go to the
// first occurrence.
func (s *Storage) buildEKeyMap() {
	if len(s.Indexes) == 0 {
		s.ekeys = nil
		return
	}

	estimated := 0
	for _, idx := range s.Indexes {
		estimated += len(idx.Entries)
	}

	m := make(map[EKeyKey]index.EKeyEntry, estimated)

	for _, idx := range s.Indexes {
		for _, e := range idx.Entries {
			k := EKeyOf(e.EKey)
			if _, exists := m[k]; !exists {
				m[k] = e
			}
		}
	}

	s.ekeys = m
}

// FindByEKey returns the index entry whose first 9 EKey bytes match e.
func (s *Storage) FindByEKey(e casc.EKey) (index.EKeyEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ekeys == nil {
		return index.EKeyEntry{}, false
	}

	entry, ok := s.ekeys[EKeyOf(e)]

	return entry, ok
}

// ReadByEKey resolves the EKey to an archive span and returns the decoded
// content bytes. Equivalent to ReadByEKeyContext with context.Background().
func (s *Storage) ReadByEKey(e casc.EKey) ([]byte, error) {
	return s.ReadByEKeyContext(context.Background(), e)
}

// ReadByEKeyContext resolves the EKey to an archive span and returns the
// decoded content bytes, honouring ctx for any CDN-backed HTTP fetches.
//
// Lookup order:
//  1. Local indexes — fast path, used by every offline install.
//  2. CDN client — only consulted when Options.Online was set at Open time
//     and the .build.info contained CDN hosts.
func (s *Storage) ReadByEKeyContext(ctx context.Context, e casc.EKey) ([]byte, error) {
	entry, ok := s.FindByEKey(e)
	if ok {
		pool, err := s.archivePool()
		if err == nil {
			return pool.ReadSpanWithOptions(entry, s.Keys, archive.DecodeOptions{
				OvercomeEncrypted: s.opts.OvercomeEncrypted,
			})
		}
	}
	// CDN fallback (only if Online mode wired up an http client).
	if s.CDN != nil {
		return s.fetchByEKey(ctx, e)
	}

	return nil, casc.ErrFileNotFound
}

// fetchByEKey downloads an EKey blob from the CDN and BLTE-decodes it.
// Tries the archive-index map first (if loaded) before falling back to a
// flat per-EKey CDN GET.
func (s *Storage) fetchByEKey(ctx context.Context, e casc.EKey) ([]byte, error) {
	return s.fetchByEKeyViaArchives(ctx, e)
}

// archivePool returns the lazily-initialized archive pool rooted at the
// storage's data directory.
func (s *Storage) archivePool() (*archive.Pool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pool != nil {
		return s.pool, nil
	}

	dir, err := locateDataDir(s.Path)
	if err != nil {
		return nil, err
	}

	s.pool = archive.NewPool(dir)
	s.dataDir = dir

	return s.pool, nil
}

// locateDataDir returns the directory holding "data.NNN" segments.
func locateDataDir(root string) (string, error) {
	candidates := []string{
		filepath.Join(root, "Data", "data"),
		filepath.Join(root, "data"),
		root,
	}
	for _, p := range candidates {
		// Probe for at least data.000 or any data.NNN.
		matches, err := filepath.Glob(filepath.Join(p, "data.[0-9][0-9][0-9]"))
		if err == nil && len(matches) > 0 {
			return p, nil
		}
	}

	return "", fmt.Errorf("%w: no data.NNN segments under %s", casc.ErrFileNotFound, root)
}

// LoadEncodingFromCKey reads the ENCODING manifest by following the
// EncodingCKey from the build config (which carries both CKey and EKey).
//
// The encoding file is stored under its EKey (since the file is encrypted
// onto disk by EKey, not by CKey). Therefore this method routes through
// FindByEKey, not via an ENCODING lookup.
func (s *Storage) LoadEncoding() error {
	if s.EncodingCKey == nil || !s.EncodingCKey.HasEKey {
		return fmt.Errorf("%w: no encoding EKey in build config", casc.ErrFileNotFound)
	}

	data, err := s.ReadByEKey(s.EncodingCKey.EKey)
	if err != nil {
		return fmt.Errorf("read encoding span: %w", err)
	}

	enc, err := encoding.Parse(data)
	if err != nil {
		return fmt.Errorf("parse encoding: %w", err)
	}

	s.SetEncoding(enc)

	return nil
}

// LoadRoot reads the ROOT file via ENCODING (root config carries the CKey;
// the EKey is looked up in the encoding map) and detects a handler.
func (s *Storage) LoadRoot() error {
	if s.RootCKey == nil {
		return fmt.Errorf("%w: no root CKey in build config", casc.ErrFileNotFound)
	}

	if s.Encoding == nil {
		return fmt.Errorf("%w: encoding not loaded", casc.ErrFileNotFound)
	}

	encEntry := s.Encoding.Find(s.RootCKey.CKey)
	if encEntry == nil || len(encEntry.EKeys) == 0 {
		return fmt.Errorf("%w: root CKey not in encoding", casc.ErrFileNotFound)
	}

	data, err := s.ReadByEKey(encEntry.EKeys[0])
	if err != nil {
		return fmt.Errorf("read root span: %w", err)
	}

	h, err := root.Detect(data)
	if err != nil {
		return fmt.Errorf("detect root: %w", err)
	}

	s.SetRoot(h)

	return nil
}

// LoadAll wires LoadEncoding + LoadRoot. Errors are returned with context
// about which step failed; partial state is preserved on the Storage.
func (s *Storage) LoadAll() error {
	if err := s.LoadEncoding(); err != nil {
		return err
	}

	if err := s.LoadRoot(); err != nil && !errors.Is(err, casc.ErrNotSupported) {
		return err
	}

	return nil
}

// Init is a test/setup helper: rebuilds the EKey lookup map and runs LoadAll.
// Callers that construct a Storage directly (bypassing Open) use this to
// finalize state.
func (s *Storage) Init() error {
	s.buildEKeyMap()
	return s.LoadAll()
}
