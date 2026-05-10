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

// Package storage is the orchestration layer that ties indexes, encoding,
// data files and root handlers together. The current implementation is a
// skeleton: it can parse a .build.info, load index files, and parse an
// ENCODING manifest from already-decoded bytes. Reading actual file content
// from a fully-fledged local install requires the build/CDN config files,
// which is the next milestone.
package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ldmonster/go-casclib/internal/archive"
	"github.com/ldmonster/go-casclib/internal/buildcfg"
	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/cdn"
	"github.com/ldmonster/go-casclib/internal/csv"
	"github.com/ldmonster/go-casclib/internal/decrypt"
	"github.com/ldmonster/go-casclib/internal/encoding"
	"github.com/ldmonster/go-casclib/internal/index"
	"github.com/ldmonster/go-casclib/internal/listfile"
	"github.com/ldmonster/go-casclib/internal/root"
)

// Storage represents a mounted CASC archive.
type Storage struct {
	mu sync.RWMutex

	// Path is the root directory of the local install (where .build.info lives).
	Path string

	// BuildInfo is the parsed .build.info file (if found).
	BuildInfo *csv.File

	// Indexes holds parsed local index files (one per bucket).
	Indexes []*index.IndexFile

	// Encoding is the parsed ENCODING manifest, if loaded.
	Encoding *encoding.File

	// Root is the active root handler.
	Root root.Handler

	// Listfile, if set, maps filename hashes to their canonical names.
	Listfile *listfile.List

	// Keys is the encryption-key registry.
	Keys *decrypt.KeyRegistry

	// BuildConfig is the parsed build config (resolves CKeys for ENCODING / ROOT / INSTALL / DOWNLOAD).
	BuildConfig *buildcfg.Config

	// CDNConfig is the parsed CDN config (archives, archive-group, ...).
	CDNConfig *buildcfg.Config

	// CDN, if non-nil, is the HTTP CDN client used as a fallback when an
	// EKey is not found in any local index. Only populated when
	// Options.Online is true and the .build.info contained CDN hosts.
	CDN *cdn.Client

	// CDNArchives, if non-nil, is the merged set of archive-index entries
	// loaded from the cdn-config's `archives` field. Online lookups consult
	// it before falling back to a flat per-EKey CDN GET.
	CDNArchives *cdn.ArchiveSet

	// EncodingCKey, RootCKey, InstallCKey, DownloadCKey, SizeCKey are
	// resolved from the BuildConfig if available.
	EncodingCKey *buildcfg.CKeyEntry
	RootCKey     *buildcfg.CKeyEntry
	InstallCKey  *buildcfg.CKeyEntry
	DownloadCKey *buildcfg.CKeyEntry
	SizeCKey     *buildcfg.CKeyEntry

	// Options at open time.
	opts Options

	// dataDir is the resolved directory holding data.NNN segments.
	dataDir string

	// pool is the lazily-initialized archive reader pool.
	pool *archive.Pool

	// ekeys is the merged trimmed-EKey -> entry map across all indexes.
	ekeys map[EKeyKey]index.EKeyEntry
}

// Options controls Open behavior.
type Options struct {
	// LocaleMask filters root entries by locale. 0 = all.
	LocaleMask uint32

	// ListfileReader, if set, supplies filenames to attach to root entries.
	ListfileReader io.Reader

	// Online, if true, allows the storage to fetch from CDN as a fallback
	// when an EKey is not present in any local index.
	Online bool

	// CacheDir, if non-empty, enables a write-through cache for CDN-fetched
	// raw blobs. Each EKey blob is stored at <CacheDir>/<aa>/<bb>/<hex>
	// after a successful CDN fetch and consulted on subsequent reads,
	// effectively making the next open offline. Mirrors CascLib's
	// CASC_FEATURE_FORCE_DOWNLOAD with a writable target.
	CacheDir string

	// OvercomeEncrypted mirrors CascLib's CASC_OVERCOME_ENCRYPTED: when
	// set, BLTE frames whose encryption key is missing from the registry
	// are replaced with zero-filled buffers and the read succeeds. When
	// unset, missing-key frames surface as casc.ErrEncrypted.
	OvercomeEncrypted bool
}

// Open mounts a CASC storage rooted at dir. It searches for .build.info in
// dir or its parent. If no usable build info is found it still returns a
// Storage object so callers can inspect what was discovered.
func Open(dir string, opts Options) (*Storage, error) {
	s := &Storage{
		Path: dir,
		Keys: decrypt.NewKeyRegistry(),
		opts: opts,
	}

	// Sanity-check: dir must exist. Anything else (.build.info, indexes)
	// is best-effort and non-fatal.
	if st, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("storage open %q: %w", dir, err)
	} else if !st.IsDir() {
		return nil, fmt.Errorf("storage open %q: not a directory", dir)
	}

	if opts.ListfileReader != nil {
		l, err := listfile.Load(opts.ListfileReader)
		if err != nil {
			return nil, fmt.Errorf("listfile: %w", err)
		}

		s.Listfile = l
	}

	bi, err := loadBuildInfo(dir)
	if err == nil {
		s.BuildInfo = bi
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	idxs, err := loadLocalIndexes(dir)
	if err != nil {
		return nil, err
	}

	s.Indexes = idxs
	s.buildEKeyMap()

	if s.BuildInfo != nil {
		s.loadConfigs(dir)
	}

	// Best-effort: chain ENCODING + ROOT loading. Failures are non-fatal
	// (the storage is still usable for inspection / direct EKey reads).
	_ = s.LoadAll()

	return s, nil
}

// loadConfigs reads the Build Key and CDN Key from .build.info and parses
// the corresponding files under <dir>/Data/config/<2>/<2>/<full hex>.
// All errors are non-fatal: the storage remains usable without configs.
func (s *Storage) loadConfigs(dir string) {
	if s.BuildInfo == nil {
		return
	}

	bk := firstColumnValue(s.BuildInfo, "Build Key")
	ck := firstColumnValue(s.BuildInfo, "CDN Key")

	if bk != "" {
		if cfg, err := readConfigFile(dir, bk); err == nil {
			s.BuildConfig = cfg
			s.EncodingCKey, _ = cfg.LookupCKey("encoding")
			s.RootCKey, _ = cfg.LookupCKey("root")
			s.InstallCKey, _ = cfg.LookupCKey("install")
			s.DownloadCKey, _ = cfg.LookupCKey("download")
			s.SizeCKey, _ = cfg.LookupCKey("size")
		}
	}

	if ck != "" {
		if cfg, err := readConfigFile(dir, ck); err == nil {
			s.CDNConfig = cfg
		}
	}

	if s.opts.Online {
		s.initCDNClient()

		if s.CDN != nil && s.CDNConfig != nil {
			_ = s.loadCDNArchiveIndexes()
		}
	}
}

// initCDNClient builds an HTTP CDN client from the .build.info "CDN Hosts"
// and "CDN Path" columns. No-op when those columns are missing.
func (s *Storage) initCDNClient() {
	hosts := firstColumnValue(s.BuildInfo, "CDN Hosts")

	path := firstColumnValue(s.BuildInfo, "CDN Path")
	if hosts == "" || path == "" {
		return
	}

	parts := strings.Fields(hosts)
	if len(parts) == 0 {
		return
	}

	s.CDN = cdn.NewClient(parts, path)
}

func firstColumnValue(f *csv.File, name string) string {
	if f == nil {
		return ""
	}

	for row := 0; row < len(f.Rows); row++ {
		if v := f.Get(row, name); v != "" {
			return v
		}
	}

	return ""
}

// readConfigFile loads <root>/Data/config/<aa>/<bb>/<hash> where hash is
// the full hex key. CASC also caches at <root>/data/config in some installs.
func readConfigFile(root, hash string) (*buildcfg.Config, error) {
	if len(hash) < 4 {
		return nil, fmt.Errorf("buildcfg: hash too short: %q", hash)
	}

	rel := filepath.Join("config", hash[:2], hash[2:4], hash)

	candidates := []string{
		filepath.Join(root, "Data", rel),
		filepath.Join(root, "data", rel),
		filepath.Join(filepath.Dir(root), "Data", rel),
	}
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()

		return buildcfg.Parse(f)
	}

	return nil, os.ErrNotExist
}

// Close releases any resources held by the storage.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error

	if s.pool != nil {
		if err := s.pool.Close(); err != nil {
			firstErr = err
		}

		s.pool = nil
	}

	s.Indexes = nil
	s.Encoding = nil
	s.Root = nil
	s.ekeys = nil

	return firstErr
}

// AddEncryptionKey registers a key by 64-bit name.
func (s *Storage) AddEncryptionKey(name uint64, key []byte) error {
	return s.Keys.Add(name, key)
}

// SetRoot replaces the active root handler. Used after the storage layer
// decodes the root file via the BLTE pipeline (not yet wired end-to-end).
func (s *Storage) SetRoot(r root.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Root = r
}

// SetEncoding replaces the active encoding manifest.
func (s *Storage) SetEncoding(e *encoding.File) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Encoding = e
}

// FindByName looks up a file by logical name. Requires both Root and
// Encoding to have been set.
func (s *Storage) FindByName(name string) (*casc.CKeyEntry, error) {
	s.mu.RLock()
	r := s.Root
	enc := s.Encoding
	s.mu.RUnlock()

	if r == nil {
		return nil, fmt.Errorf("%w: no root handler loaded", casc.ErrNotSupported)
	}

	rEntry := r.LookupByName(name)
	if rEntry == nil {
		return nil, casc.ErrFileNotFound
	}

	if enc == nil {
		// Without encoding we can still return what the root knows.
		return rEntry, nil
	}

	encEntry := enc.Find(rEntry.CKey)
	if encEntry == nil {
		return rEntry, nil
	}

	out := *rEntry

	out.ContentSize = encEntry.ContentSize
	if len(encEntry.EKeys) > 0 {
		out.EKey = encEntry.EKeys[0]
		out.Flags |= casc.CEFlagHasEKey
	}

	return &out, nil
}

// loadBuildInfo locates and parses the .build.info file.
func loadBuildInfo(dir string) (*csv.File, error) {
	candidates := []string{
		filepath.Join(dir, ".build.info"),
		filepath.Join(filepath.Dir(dir), ".build.info"),
	}
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return nil, err
		}
		defer f.Close()

		return csv.Parse(f)
	}

	return nil, os.ErrNotExist
}

// loadLocalIndexes reads all data.### / ##########.idx files from
// <dir>/Data/data and parses them.
func loadLocalIndexes(dir string) ([]*index.IndexFile, error) {
	candidates := []string{
		filepath.Join(dir, "Data", "data"),
		filepath.Join(dir, "Data", "indices"),
		filepath.Join(dir, "data"),
	}
	for _, p := range candidates {
		entries, err := os.ReadDir(p)
		if err != nil {
			continue
		}

		var idxs []*index.IndexFile

		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".idx" {
				continue
			}

			data, err := os.ReadFile(filepath.Join(p, e.Name()))
			if err != nil {
				return nil, err
			}
			// Bucket index = first byte of hex filename.
			var bucket byte
			if _, err := fmt.Sscanf(e.Name(), "%2x", &bucket); err != nil {
				continue
			}

			idx, err := index.Parse(data, bucket)
			if err != nil {
				continue // skip unparseable
			}

			idxs = append(idxs, idx)
		}

		if len(idxs) > 0 {
			return idxs, nil
		}
	}

	return nil, nil
}
