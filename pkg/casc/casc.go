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

// Package casc is the public Go API for go-casclib. It mirrors the
// high-level surface of the upstream C/C++ CascLib (CascOpenStorage,
// CascOpenFile, CascReadFile, CascCloseFile, CascFindFirstFile, etc.) and
// follows the layout pattern established by github.com/ldmonster/go-stormlib.
//
// The current implementation provides the API skeleton, basic storage
// discovery, and the building blocks (BLTE decoding, ENCODING parsing,
// Salsa20 decryption). End-to-end reading of WoW / D3 / Overwatch storages
// is in progress; see internal/root/* and internal/cdn for what's pending.
package casc

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	internalcasc "github.com/ldmonster/go-casclib/internal/casc"
	// Side-effect imports register root probes.
	_ "github.com/ldmonster/go-casclib/internal/root/diablo3"
	_ "github.com/ldmonster/go-casclib/internal/root/install"
	_ "github.com/ldmonster/go-casclib/internal/root/mndx"
	_ "github.com/ldmonster/go-casclib/internal/root/overwatch"
	_ "github.com/ldmonster/go-casclib/internal/root/text"
	_ "github.com/ldmonster/go-casclib/internal/root/tvfs"
	_ "github.com/ldmonster/go-casclib/internal/root/wow"
	"github.com/ldmonster/go-casclib/internal/storage"
)

// Re-export the canonical sentinel errors so callers don't have to import
// the internal package.
var (
	ErrFileNotFound       = internalcasc.ErrFileNotFound
	ErrInvalidParameter   = internalcasc.ErrInvalidParameter
	ErrInvalidHandle      = internalcasc.ErrInvalidHandle
	ErrBadFormat          = internalcasc.ErrBadFormat
	ErrFileCorrupt        = internalcasc.ErrFileCorrupt
	ErrNotSupported       = internalcasc.ErrNotSupported
	ErrEncrypted          = internalcasc.ErrEncrypted
	ErrAlreadyExists      = internalcasc.ErrAlreadyExists
	ErrInsufficientBuffer = internalcasc.ErrInsufficientBuffer
	ErrCancelled          = internalcasc.ErrCancelled
	ErrEndOfFile          = internalcasc.ErrEndOfFile
)

// Locale flags re-exported.
const (
	LocaleAll  uint32 = internalcasc.LocaleAll
	LocaleNone uint32 = internalcasc.LocaleNone
	LocaleEnUS uint32 = internalcasc.LocaleEnUS
	LocaleKoKR uint32 = internalcasc.LocaleKoKR
	LocaleFrFR uint32 = internalcasc.LocaleFrFR
	LocaleDeDE uint32 = internalcasc.LocaleDeDE
	LocaleZhCN uint32 = internalcasc.LocaleZhCN
	LocaleEsES uint32 = internalcasc.LocaleEsES
	LocaleZhTW uint32 = internalcasc.LocaleZhTW
	LocaleEnGB uint32 = internalcasc.LocaleEnGB
	LocaleEnTW uint32 = internalcasc.LocaleEnTW
	LocaleEsMX uint32 = internalcasc.LocaleEsMX
	LocaleRuRU uint32 = internalcasc.LocaleRuRU
	LocalePtBR uint32 = internalcasc.LocalePtBR
	LocaleItIT uint32 = internalcasc.LocaleItIT
	LocalePtPT uint32 = internalcasc.LocalePtPT
)

// OpenOptions controls how a Storage is opened. It is the rough Go
// equivalent of CASC_OPEN_STORAGE_ARGS.
type OpenOptions struct {
	// LocaleMask filters by locale bits. 0 means all locales.
	LocaleMask uint32

	// ListfileReader is an optional listfile to attach to the root.
	ListfileReader io.Reader

	// ListfilePath, if set and ListfileReader is nil, names a file on disk
	// to open and read as the listfile. The file is closed before
	// OpenStorage returns. Convenience for callers that don't want to
	// manage a reader themselves.
	ListfilePath string

	// Online enables CDN downloads. Not yet implemented.
	Online bool

	// CacheDir, if non-empty, enables a write-through cache for CDN
	// fetches under this directory. Mirrors CascLib's
	// CASC_FEATURE_FORCE_DOWNLOAD with a writable target.
	CacheDir string

	// OvercomeEncrypted mirrors CascLib's CASC_OVERCOME_ENCRYPTED flag:
	// BLTE frames whose Salsa20 key is missing from the key registry
	// are returned as zero-filled buffers (instead of surfacing
	// ErrEncrypted), allowing the rest of the file to read through.
	OvercomeEncrypted bool
}

// FileInfo is the public projection of the upstream CASC_FILE_FULL_INFO.
type FileInfo struct {
	FileName     string
	PlainName    string
	ContentKey   [16]byte
	EncodedKey   [16]byte
	ContentSize  uint64
	EncodedSize  uint64
	FileDataID   uint32
	LocaleFlags  uint32
	ContentFlags uint32
	TagBitMask   uint64
	SpanCount    uint32
	// Available reports whether the file's encoded data was located in a
	// local index. False means the file is referenced by the root/encoding
	// manifests but its archive span is not on disk (a CDN fetch would be
	// required). Mirrors CASC_FIND_DATA::bFileAvailable.
	Available bool
	// NameType reports how FileName was synthesized: real path, FileDataID
	// stub, or content/encoded key fallback. Mirrors CASC_NAME_TYPE.
	NameType NameType
}

// NameType mirrors CascLib's CASC_NAME_TYPE.
type NameType int

const (
	// NameTypeFull means FileName is a real (listfile or root-resolved) path.
	NameTypeFull NameType = iota
	// NameTypeDataID means FileName was synthesized from a FileDataID.
	NameTypeDataID
	// NameTypeCKey means FileName was synthesized from a content key.
	NameTypeCKey
	// NameTypeEKey means FileName was synthesized from an encoded key.
	NameTypeEKey
)

// String renders the NameType for debugging output.
func (n NameType) String() string {
	switch n {
	case NameTypeFull:
		return "Full"
	case NameTypeDataID:
		return "DataID"
	case NameTypeCKey:
		return "CKey"
	case NameTypeEKey:
		return "EKey"
	default:
		return "Unknown"
	}
}

// StorageInfo is a snapshot of storage-level metadata.
type StorageInfo struct {
	// Path is the on-disk root of the storage.
	Path string

	// RootType is the short name of the active root handler (e.g. "WoW", "TVFS").
	// Empty if no root handler was detected.
	RootType string

	// FileCount is the number of entries exported by the root handler.
	// 0 if no root is loaded.
	FileCount int

	// BuildVersion is the build number from .build.info (e.g. "10.0.2.46479").
	// Empty if not available.
	BuildVersion string

	// CDNPath is the CDN path prefix from .build.info.
	// Empty if not available.
	CDNPath string

	// Product is the build product code from .build.info (e.g. "wow", "wow_classic").
	Product string

	// Region is the active region from .build.info (e.g. "us", "eu").
	Region string

	// InstalledLocales is the bitwise OR of locale flags advertised in
	// .build.info ("Tags" / "Install Tags") that intersect the standard
	// locale set. 0 when no locale tags are present.
	InstalledLocales uint32

	// Tags lists the install tags from .build.info ("Tags" column).
	// Useful for build-feature gating.
	Tags []string

	// Features bit-flags. See StorageFeature*.
	Features uint32
}

// Storage feature bit flags reported by StorageInfo.Features. Mirrors
// CascLib's CASC_FEATURE_* constants where they map cleanly.
const (
	// StorageFeatureLocale is set when the storage exposes per-file locale flags.
	StorageFeatureLocale uint32 = 1 << iota
	// StorageFeatureFileDataIDs is set when the root indexes files by FileDataID.
	StorageFeatureFileDataIDs
	// StorageFeatureRootCKey is set when the root indexes files by CKey directly.
	StorageFeatureRootCKey
	// StorageFeatureTags is set when the build.info advertises install tags.
	StorageFeatureTags
	// StorageFeatureOnline is set when the storage was opened in online (CDN) mode.
	StorageFeatureOnline
)

// Storage is a mounted CASC archive. It is safe for concurrent use.
type Storage struct {
	inner *storage.Storage

	// Write-overlay state. The on-disk write pipeline is not implemented
	// (CascCreateStorage / CascAddFileToStorage produce a brand-new
	// CASC archive with full ENCODING/ROOT/INSTALL/DOWNLOAD manifests —
	// substantial work tracked in rewriting_plan.md §6.2). Until then,
	// AddFile / RemoveFile / RenameFile manipulate an in-memory overlay
	// that OpenFile and FindFiles consult before the underlying storage.
	// Flush still returns ErrNotSupported.
	overlayMu sync.RWMutex
	overlay   map[string][]byte
	removed   map[string]bool

	// createDir, when non-empty, is the on-disk directory that Flush
	// should populate with manifests + .idx + data.NNN segments.
	// Set by CreateStorage.
	createDir string
}

// OpenStorage opens a local CASC storage rooted at dir.
//
// The dir is typically the install root (the parent of the "Data" folder).
// If a .build.info file exists in dir or its parent, it is parsed.
func OpenStorage(dir string, opts OpenOptions) (*Storage, error) {
	reader := opts.ListfileReader

	if reader == nil && opts.ListfilePath != "" {
		f, err := os.Open(opts.ListfilePath)
		if err != nil {
			return nil, fmt.Errorf("listfile %q: %w", opts.ListfilePath, err)
		}
		defer f.Close()

		reader = f
	}

	inner, err := storage.Open(dir, storage.Options{
		LocaleMask:        opts.LocaleMask,
		ListfileReader:    reader,
		Online:            opts.Online,
		CacheDir:          opts.CacheDir,
		OvercomeEncrypted: opts.OvercomeEncrypted,
	})
	if err != nil {
		return nil, err
	}

	return &Storage{inner: inner}, nil
}

// Close releases storage resources.
func (s *Storage) Close() error {
	if s.inner == nil {
		return nil
	}

	return s.inner.Close()
}

// AddEncryptionKey registers a 16-byte decryption key for the given 64-bit
// KeyName. Multiple keys can be added.
func (s *Storage) AddEncryptionKey(name uint64, key []byte) error {
	return s.inner.AddEncryptionKey(name, key)
}

// OpenFile returns a reader for the file with the given logical name.
//
// Requires the storage to have a loaded root handler and ENCODING manifest
// (set automatically when OpenStorage finds a usable .build.info + configs).
func (s *Storage) OpenFile(name string) (*File, error) {
	return s.openFile(context.Background(), name)
}

func (s *Storage) openFile(ctx context.Context, name string) (*File, error) {
	// Consult the in-memory write overlay first.
	if data, ok, removed := s.overlayLookup(name); removed {
		return nil, ErrFileNotFound
	} else if ok {
		return &File{
			content: data,
			info:    FileInfo{FileName: name, ContentSize: uint64(len(data))},
		}, nil
	}

	entry, err := s.inner.FindByName(name)
	if err != nil {
		return nil, err
	}

	data, err := s.inner.ReadByEKeyContext(ctx, entry.EKey)
	if err != nil {
		return nil, err
	}

	info := FileInfo{
		FileName:     name,
		ContentKey:   entry.CKey,
		EncodedKey:   entry.EKey,
		ContentSize:  entry.ContentSize,
		EncodedSize:  entry.EncodedSize,
		FileDataID:   entry.FileDataID,
		LocaleFlags:  entry.LocaleFlags,
		ContentFlags: entry.ContentFlags,
	}

	return &File{content: data, info: info}, nil
}

// OpenFileByCKey returns a reader for the file with the given content key.
func (s *Storage) OpenFileByCKey(ckey [16]byte) (*File, error) {
	return s.openFileByCKey(context.Background(), ckey)
}

func (s *Storage) openFileByCKey(ctx context.Context, ckey [16]byte) (*File, error) {
	enc := s.inner.Encoding
	if enc == nil {
		return nil, ErrNotSupported
	}

	encEntry := enc.Find(ckey)
	if encEntry == nil || len(encEntry.EKeys) == 0 {
		return nil, ErrFileNotFound
	}

	ekey := encEntry.EKeys[0]

	data, err := s.inner.ReadByEKeyContext(ctx, ekey)
	if err != nil {
		return nil, err
	}

	info := FileInfo{
		ContentKey:  ckey,
		EncodedKey:  ekey,
		ContentSize: encEntry.ContentSize,
	}

	return &File{content: data, info: info}, nil
}

// OpenFileByEKey returns a reader for the file with the given encoded key.
func (s *Storage) OpenFileByEKey(ekey [16]byte) (*File, error) {
	return s.openFileByEKey(context.Background(), ekey)
}

func (s *Storage) openFileByEKey(ctx context.Context, ekey [16]byte) (*File, error) {
	data, err := s.inner.ReadByEKeyContext(ctx, ekey)
	if err != nil {
		return nil, err
	}

	info := FileInfo{
		EncodedKey: ekey,
	}

	return &File{content: data, info: info}, nil
}

// OpenFileByID returns a reader for the file with the given FileDataID
// (WoW / games with FDID indexing). Returns ErrNotSupported for storages
// that don't use FileDataIDs.
func (s *Storage) OpenFileByID(fileDataID uint32) (*File, error) {
	return s.openFileByID(context.Background(), fileDataID)
}

func (s *Storage) openFileByID(ctx context.Context, fileDataID uint32) (*File, error) {
	if s.inner.Root == nil {
		return nil, ErrNotSupported
	}

	entry := s.inner.Root.LookupByFileDataID(fileDataID)
	if entry == nil {
		return nil, ErrFileNotFound
	}

	data, err := s.inner.ReadByEKeyContext(ctx, entry.EKey)
	if err != nil {
		return nil, err
	}

	info := FileInfo{
		ContentKey:   entry.CKey,
		EncodedKey:   entry.EKey,
		ContentSize:  entry.ContentSize,
		EncodedSize:  entry.EncodedSize,
		FileDataID:   entry.FileDataID,
		LocaleFlags:  entry.LocaleFlags,
		ContentFlags: entry.ContentFlags,
	}

	return &File{content: data, info: info}, nil
}

// GetInfo returns metadata about the storage.
func (s *Storage) GetInfo() StorageInfo {
	inner := s.inner

	si := StorageInfo{
		Path: inner.Path,
	}

	if inner.Root != nil {
		si.RootType = inner.Root.Name()
		// Count entries.
		n := 0

		inner.Root.All(func(_ string, _ *internalcasc.CKeyEntry) bool {
			n++
			return true
		})

		si.FileCount = n

		feats := inner.Root.Features()
		// Map internal root features to public StorageFeature flags.
		if feats&internalcasc.FeatureFileDataIDs != 0 {
			si.Features |= StorageFeatureFileDataIDs
		}

		if feats&internalcasc.FeatureRootCKey != 0 {
			si.Features |= StorageFeatureRootCKey
		}

		if feats&internalcasc.FeatureLocaleFlags != 0 {
			si.Features |= StorageFeatureLocale
		}
	}

	if inner.BuildInfo != nil {
		si.BuildVersion = inner.BuildInfo.Get(0, "Version")
		if si.BuildVersion == "" {
			si.BuildVersion = inner.BuildInfo.Get(0, "Build Version")
		}

		si.CDNPath = inner.BuildInfo.Get(0, "CDN Path")
		si.Product = inner.BuildInfo.Get(0, "Product")

		si.Region = inner.BuildInfo.Get(0, "Region")
		if si.Region == "" {
			// Older / synthesised .build.info files stash the region under
			// the "Branch" column instead. Treat them as equivalent.
			si.Region = inner.BuildInfo.Get(0, "Branch")
		}

		tagsCol := inner.BuildInfo.Get(0, "Tags")
		if tagsCol == "" {
			tagsCol = inner.BuildInfo.Get(0, "Install Tags")
		}

		if tagsCol != "" {
			si.Tags = parseTagList(tagsCol)
			si.InstalledLocales = inferInstalledLocales(si.Tags)
			si.Features |= StorageFeatureTags
		}
	}

	if inner.CDN != nil {
		si.Features |= StorageFeatureOnline
	}

	return si
}

// parseTagList splits a Blizzard "tag" string into individual labels.
// .build.info packs tags either as space-separated tokens or as a "?" /
// ":"-separated tag-pair list. Splitting on the union of common
// separators is sufficient for the cases we care about.
func parseTagList(s string) []string {
	out := make([]string, 0, 4)

	cur := strings.Builder{}
	flush := func() {
		t := strings.TrimSpace(cur.String())
		cur.Reset()

		if t == "" {
			return
		}

		out = append(out, t)
	}

	for _, r := range s {
		switch r {
		case '?', ':', ' ', '\t', ',', ';', '|':
			flush()
		default:
			cur.WriteRune(r)
		}
	}

	flush()

	return out
}

// localeTagToFlag maps Blizzard locale tags to LocaleEnUS-style bitmasks.
var localeTagToFlag = map[string]uint32{
	"enus": LocaleEnUS, "kokr": LocaleKoKR, "frfr": LocaleFrFR, "dede": LocaleDeDE,
	"zhcn": LocaleZhCN, "eses": LocaleEsES, "zhtw": LocaleZhTW, "engb": LocaleEnGB,
	"entw": LocaleEnTW, "esmx": LocaleEsMX, "ruru": LocaleRuRU, "ptbr": LocalePtBR,
	"itit": LocaleItIT, "ptpt": LocalePtPT,
}

func inferInstalledLocales(tags []string) uint32 {
	var mask uint32

	for _, t := range tags {
		key := strings.ToLower(strings.TrimPrefix(t, "text?"))
		key = strings.TrimPrefix(key, "speech?")
		// Drop trailing locale-pair markers like "enUS:0".
		if i := strings.IndexAny(key, ":-"); i > 0 {
			key = key[:i]
		}

		if f, ok := localeTagToFlag[key]; ok {
			mask |= f
		}
	}

	return mask
}

// File is an opened file handle. It implements io.ReadSeekCloser.
type File struct {
	// content holds decoded bytes.
	content []byte
	pos     int64
	// info carries file metadata populated at open time.
	info FileInfo
}

// GetInfo returns metadata populated when the file was opened.
func (f *File) GetInfo() FileInfo { return f.info }

// Read reads up to len(p) bytes.
func (f *File) Read(p []byte) (int, error) {
	if f.pos >= int64(len(f.content)) {
		return 0, io.EOF
	}

	n := copy(p, f.content[f.pos:])
	f.pos += int64(n)

	return n, nil
}

// Seek implements io.Seeker.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	var abs int64

	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = f.pos + offset
	case io.SeekEnd:
		abs = int64(len(f.content)) + offset
	default:
		return 0, ErrInvalidParameter
	}

	if abs < 0 {
		return 0, ErrInvalidParameter
	}

	f.pos = abs

	return abs, nil
}

// Close releases handle resources.
func (f *File) Close() error {
	f.content = nil
	return nil
}

// Size returns the (decoded) file size, if known.
func (f *File) Size() int64 { return int64(len(f.content)) }

// FindFiles iterates all files in the storage, invoking fn for each. If fn
// returns false the iteration stops. Filenames are taken from the active
// root handler (text, TVFS, INSTALL, Diablo III, etc.). Roots that only
// expose FileDataIDs (WoW v1+) yield synthetic "FileDataID:N" names.
//
// If pattern is non-empty, only filenames matching the simple shell glob
// (path/filepath.Match semantics, case-insensitive) are yielded.
//
// FindFiles is a Go-flavored replacement for the upstream
// CascFindFirstFile / CascFindNextFile loop.
func (s *Storage) FindFiles(pattern string, fn func(name string, info FileInfo) bool) error {
	if s.inner == nil || s.inner.Root == nil {
		// Even with no underlying root we may still have an overlay to
		// iterate. Fall through.
		return s.findOverlayOnly(pattern, fn)
	}

	patternLower := strings.ToLower(pattern)

	var iterErr error

	enc := s.inner.Encoding
	lf := s.inner.Listfile
	s.inner.Root.All(func(name string, e *internalcasc.CKeyEntry) bool {
		// Upgrade synthetic "FileDataID:N" names via the external
		// listfile when available and the entry carries a name hash.
		if lf != nil && e.FileNameHash != 0 {
			if real := lf.Lookup(e.FileNameHash); real != "" {
				name = real
			}
		}
		// Skip entries shadowed by an overlay removal or replacement.
		if _, ok, removed := s.overlayLookup(name); ok || removed {
			return true
		}

		if patternLower != "" {
			ok, err := filepath.Match(patternLower, strings.ToLower(name))
			if err != nil {
				iterErr = err
				return false
			}

			if !ok {
				return true
			}
		}
		// Enrich with encoding data when available.
		ek := e.EKey

		contentSize := e.ContentSize
		if enc != nil {
			if encEntry := enc.Find(e.CKey); encEntry != nil {
				contentSize = encEntry.ContentSize
				if len(encEntry.EKeys) > 0 {
					ek = encEntry.EKeys[0]
				}
			}
		}

		info := FileInfo{
			FileName:     name,
			PlainName:    plainName(name),
			ContentKey:   e.CKey,
			EncodedKey:   ek,
			ContentSize:  contentSize,
			EncodedSize:  e.EncodedSize,
			FileDataID:   e.FileDataID,
			LocaleFlags:  e.LocaleFlags,
			ContentFlags: e.ContentFlags,
			NameType:     classifyName(name),
			Available:    s.isAvailable(ek),
		}

		return fn(name, info)
	})

	if iterErr != nil {
		return iterErr
	}

	// Append overlay entries that match the pattern.
	return s.iterOverlay(pattern, fn)
}

// plainName returns the trailing path component of a fully qualified file
// name. It mirrors CascFindFile's PlainName helper.
func plainName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		return name[i+1:]
	}

	return name
}

// classifyName inspects a synthesised root-handler name and returns the
// matching NameType. WoW v1 / Diablo III roots without a listfile yield
// "FileDataID:N" stubs; OW / TVFS yield real paths.
func classifyName(name string) NameType {
	switch {
	case strings.HasPrefix(name, "FileDataID:"):
		return NameTypeDataID
	case strings.HasPrefix(name, "CKey:"):
		return NameTypeCKey
	case strings.HasPrefix(name, "EKey:"):
		return NameTypeEKey
	default:
		return NameTypeFull
	}
}

// isAvailable reports whether the encoded key resolves to a local index
// entry. It does not consult the CDN: a missing entry on a strictly-
// offline storage means the file is not on disk.
func (s *Storage) isAvailable(ek [16]byte) bool {
	if s == nil || s.inner == nil {
		return false
	}

	_, ok := s.inner.FindByEKey(ek)

	return ok
}

// ReadByCKey resolves a content key to its first encoded key (via the
// ENCODING manifest) and returns the decoded bytes. Useful for callers
// that already hold a CKey from a manifest walk and want to avoid the
// OpenFile/Read/Close dance.
func (s *Storage) ReadByCKey(ckey [16]byte) ([]byte, error) {
	return s.readByCKey(context.Background(), ckey)
}

// ReadByCKeyContext is ReadByCKey with explicit cancellation.
func (s *Storage) ReadByCKeyContext(ctx context.Context, ckey [16]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return s.readByCKey(ctx, ckey)
}

func (s *Storage) readByCKey(ctx context.Context, ckey [16]byte) ([]byte, error) {
	if s.inner == nil {
		return nil, ErrInvalidHandle
	}

	enc := s.inner.Encoding
	if enc == nil {
		return nil, ErrNotSupported
	}

	encEntry := enc.Find(ckey)
	if encEntry == nil || len(encEntry.EKeys) == 0 {
		return nil, ErrFileNotFound
	}

	return s.inner.ReadByEKeyContext(ctx, encEntry.EKeys[0])
}

// ReadByEKey returns the decoded bytes for the given encoded key. Useful
// when the caller already has an EKey (from a CDN archive index, a parity
// drift report, etc.) and wants to bypass the encoding lookup.
func (s *Storage) ReadByEKey(ekey [16]byte) ([]byte, error) {
	if s.inner == nil {
		return nil, ErrInvalidHandle
	}

	return s.inner.ReadByEKey(ekey)
}

// ReadByEKeyContext is ReadByEKey with explicit cancellation.
func (s *Storage) ReadByEKeyContext(ctx context.Context, ekey [16]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if s.inner == nil {
		return nil, ErrInvalidHandle
	}

	return s.inner.ReadByEKeyContext(ctx, ekey)
}

// FullInfo populates a FileInfo with as much detail as the storage can
// supply for the given file. It is the rough Go equivalent of
// CascGetFileInfo(CascFileFullInfo).
func (f *File) FullInfo() FileInfo { return f.info }

// ContentKey returns the file's CKey.
func (f *File) ContentKey() [16]byte { return f.info.ContentKey }

// EncodedKey returns the file's first EKey.
func (f *File) EncodedKey() [16]byte { return f.info.EncodedKey }
