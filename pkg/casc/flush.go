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

// Flush implementation for write-side CASC.
//
// CreateStorage(dir, ...) records an on-disk target. AddFile populates an
// in-memory overlay. Flush walks that overlay, BLTE-encodes each file,
// writes them into data.NNN segments via internal/archive.Writer, then
// emits the supporting manifests:
//
//   - INSTALL manifest (acts as the synthetic root: name -> CKey)
//   - ENCODING manifest (CKey -> EKey for every span, including INSTALL)
//   - V1 .idx (one bucket-0 file containing every span entry)
//   - build / CDN config text files (under Data/config/<aa>/<bb>/<hex>)
//   - .build.info CSV referencing the build/CDN config hashes
//
// The output is round-trippable: OpenStorage can re-open the directory
// and serve files by name.

package casc

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/ldmonster/go-casclib/internal/archive"
	"github.com/ldmonster/go-casclib/internal/buildcfg"
	internalcasc "github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/cdn"
	"github.com/ldmonster/go-casclib/internal/datafile"
	"github.com/ldmonster/go-casclib/internal/encoding"
	"github.com/ldmonster/go-casclib/internal/index"
	"github.com/ldmonster/go-casclib/internal/root/install"
)

// Flush persists the overlay to the directory recorded by CreateStorage.
// Returns ErrNotSupported when the storage was opened via OpenStorage
// (read-only) rather than CreateStorage.
func (s *Storage) Flush() error {
	if s.createDir == "" {
		return ErrNotSupported
	}

	dataDir := filepath.Join(s.createDir, "Data", "data")
	configRoot := filepath.Join(s.createDir, "Data", "config")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}

	if err := os.MkdirAll(configRoot, 0o755); err != nil {
		return err
	}

	// 1. Snapshot overlay (sorted for determinism).
	s.overlayMu.RLock()

	type fileEntry struct {
		name string
		data []byte
	}

	files := make([]fileEntry, 0, len(s.overlay))
	for k, v := range s.overlay {
		files = append(files, fileEntry{name: k, data: v})
	}

	s.overlayMu.RUnlock()

	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	// 2. Open archive writer.
	w, err := archive.NewWriter(dataDir, archive.DefaultSegmentSize)
	if err != nil {
		return err
	}

	defer func() { _ = w.Close() }()

	type spanRecord struct {
		ckey        internalcasc.CKey
		ekey        internalcasc.EKey
		contentSize uint64
	}

	idxEntries := make([]index.EKeyEntry, 0, len(files)+2)
	encEntries := make([]encoding.CKeyEntry, 0, len(files)+1)
	installEntries := make([]install.Entry, 0, len(files))

	writeSpan := func(content []byte) (spanRecord, error) {
		blte, ckey, ekey, eerr := datafile.Encode(
			content,
			datafile.EncodeOptions{Mode: datafile.EncodeRaw},
		)
		if eerr != nil {
			return spanRecord{}, eerr
		}

		idxEntry, werr := w.WriteSpan(blte, ekey)
		if werr != nil {
			return spanRecord{}, werr
		}

		idxEntries = append(idxEntries, idxEntry)

		return spanRecord{
			ckey:        internalcasc.CKey(ckey),
			ekey:        internalcasc.EKey(ekey),
			contentSize: uint64(len(content)),
		}, nil
	}

	// 3. Write user files.
	for _, f := range files {
		rec, werr := writeSpan(f.data)
		if werr != nil {
			return werr
		}

		encEntries = append(encEntries, encoding.CKeyEntry{
			ContentSize: rec.contentSize,
			CKey:        rec.ckey,
			EKeys:       []internalcasc.EKey{rec.ekey},
		})

		if size32 := rec.contentSize; size32 <= 0xFFFFFFFF {
			installEntries = append(installEntries, install.Entry{
				Name:        f.name,
				CKey:        rec.ckey,
				ContentSize: uint32(size32),
			})
		}
	}

	// 4. Encode + write INSTALL manifest.
	installBytes, err := install.Encode(installEntries, nil, install.WriteOptions{})
	if err != nil {
		return err
	}

	installRec, err := writeSpan(installBytes)
	if err != nil {
		return err
	}

	encEntries = append(encEntries, encoding.CKeyEntry{
		ContentSize: installRec.contentSize,
		CKey:        installRec.ckey,
		EKeys:       []internalcasc.EKey{installRec.ekey},
	})

	// 4b. Encode + write a minimal DOWNLOAD manifest. CascLib's
	// LoadDownloadManifest treats a missing manifest as an error during
	// CascOpenStorage, so we always emit an empty v3 manifest.
	dlBytes, err := cdn.EncodeDownload(nil, nil, cdn.WriteDownloadOptions{Version: 3})
	if err != nil {
		return err
	}

	dlRec, err := writeSpan(dlBytes)
	if err != nil {
		return err
	}

	encEntries = append(encEntries, encoding.CKeyEntry{
		ContentSize: dlRec.contentSize,
		CKey:        dlRec.ckey,
		EKeys:       []internalcasc.EKey{dlRec.ekey},
	})

	// 5. Encode + write ENCODING manifest.
	encBytes, err := encoding.Encode(encEntries, encoding.WriteOptions{})
	if err != nil {
		return err
	}

	encRec, err := writeSpan(encBytes)
	if err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	// 6. Write a single bucket-0 .idx file containing every span.
	idxBytes, err := index.EncodeV1(idxEntries, index.WriteOptions{
		BucketIndex: 0,
		SegmentSize: archive.DefaultSegmentSize,
	})
	if err != nil {
		return err
	}

	idxPath := filepath.Join(dataDir, index.IndexFileName(0, 0))
	if err := os.WriteFile(idxPath, idxBytes, 0o644); err != nil { //nolint:gosec
		return err
	}

	// 7. Build config: encoding/install/root + their sizes.
	buildCfg := buildcfg.NewConfig()
	buildCfg.Set("build-name", "go-casclib-synthetic")
	buildCfg.SetKeyPair("encoding", encRec.ckey, encRec.ekey)
	buildCfg.SetSizePair("encoding-size", encRec.contentSize, encRec.contentSize)
	buildCfg.SetKeyPair("install", installRec.ckey, installRec.ekey)
	buildCfg.SetSizePair("install-size", installRec.contentSize, installRec.contentSize)
	buildCfg.SetKeyPair("download", dlRec.ckey, dlRec.ekey)
	buildCfg.SetSizePair("download-size", dlRec.contentSize, dlRec.contentSize)
	buildCfg.SetKeyPair("root", installRec.ckey, installRec.ekey)

	buildCfgBytes := buildCfg.EncodeText()

	buildKey := md5.Sum(buildCfgBytes)
	if err := writeConfigFile(configRoot, buildKey, buildCfgBytes); err != nil {
		return err
	}

	// 8. CDN config: empty archives list (this is a fully-local archive).
	cdnCfg := buildcfg.NewConfig()
	cdnCfg.Set("archives")
	cdnCfg.Set("archive-group")
	cdnCfgBytes := cdnCfg.EncodeText()

	cdnKey := md5.Sum(cdnCfgBytes)
	if err := writeConfigFile(configRoot, cdnKey, cdnCfgBytes); err != nil {
		return err
	}

	// 9. .build.info CSV.
	buildInfo := buildcfg.EncodeBuildInfo([]buildcfg.BuildInfoRow{{
		Region:        "us",
		BuildKey:      hex.EncodeToString(buildKey[:]),
		CDNKey:        hex.EncodeToString(cdnKey[:]),
		IMSize:        strconv.Itoa(len(installBytes)),
		Version:       "0.0.0.1",
		BuildComplete: "1",
		Product:       "go-casclib",
	}})

	buildInfoPath := filepath.Join(s.createDir, ".build.info")
	if err := os.WriteFile(buildInfoPath, buildInfo, 0o644); err != nil { //nolint:gosec
		return err
	}

	return nil
}

func writeConfigFile(configRoot string, key [16]byte, body []byte) error {
	hexKey := hex.EncodeToString(key[:])
	dir := filepath.Join(configRoot, hexKey[0:2], hexKey[2:4])

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dir, hexKey), body, 0o644) //nolint:gosec
}

// Used to satisfy the import of fmt when building debug-trace versions.
var _ = fmt.Sprintf
