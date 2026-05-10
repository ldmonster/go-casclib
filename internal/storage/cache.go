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

// CDN write-through cache for EKey blobs.
//
// When Options.CacheDir is non-empty, every successful CDN fetch is written
// to <CacheDir>/<aa>/<bb>/<hex> and consulted before re-issuing the fetch.
// This implements a Go-idiomatic version of CascLib's
// CASC_FEATURE_FORCE_DOWNLOAD with a writable cache target.

package storage

import (
	"os"
	"path/filepath"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// cachePath returns <root>/<aa>/<bb>/<hex> for a given EKey/CKey hex string.
func cachePath(root, hexKey string) string {
	if len(hexKey) < 4 {
		return filepath.Join(root, hexKey)
	}

	return filepath.Join(root, hexKey[:2], hexKey[2:4], hexKey)
}

// cacheRead returns the cached blob for hexKey, or os.ErrNotExist.
func (s *Storage) cacheRead(hexKey string) ([]byte, error) {
	if s.opts.CacheDir == "" {
		return nil, os.ErrNotExist
	}

	p := cachePath(s.opts.CacheDir, hexKey)

	return os.ReadFile(p) //nolint:gosec // path derived from EKey hex
}

// cacheWrite atomically writes blob to the cache at hexKey.
func (s *Storage) cacheWrite(hexKey string, blob []byte) error {
	if s.opts.CacheDir == "" {
		return nil
	}

	p := cachePath(s.opts.CacheDir, hexKey)

	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(p), ".cache-*")
	if err != nil {
		return err
	}

	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())

		return err
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}

	return os.Rename(tmp.Name(), p)
}

// hexKey returns the hex string for an EKey.
func ekeyHex(e casc.EKey) string {
	const hexdigits = "0123456789abcdef"

	out := make([]byte, len(e)*2)
	for i, b := range e {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0F]
	}

	return string(out)
}
