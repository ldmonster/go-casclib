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
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/ldmonster/go-casclib/internal/archive"
	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/cdn"
)

// loadCDNArchiveIndexes fetches every "<archive>.index" file referenced by
// the cdn-config's `archives` field and merges them into s.CDNArchives.
//
// Errors on individual archives are non-fatal: archive-index loading is
// best-effort and a partial set is still useful (most online EKey lookups
// hit a small subset of archives anyway).
//
// Concurrency: archive-indexes are fetched in parallel (up to 8 at a time).
func (s *Storage) loadCDNArchiveIndexes() error {
	if s.CDN == nil || s.CDNConfig == nil {
		return nil
	}

	hashes, err := s.CDNConfig.Archives()
	if err != nil {
		return fmt.Errorf("cdn archives: %w", err)
	}

	if len(hashes) == 0 {
		return nil
	}

	set := cdn.NewArchiveSet()
	if err := fetchAndMergeArchiveIndexes(context.Background(), s.CDN, hashes, set, 8); err != nil {
		return err
	}

	s.mu.Lock()
	s.CDNArchives = set
	s.mu.Unlock()

	return nil
}

func fetchAndMergeArchiveIndexes(
	ctx context.Context,
	c *cdn.Client,
	hashes [][casc.MD5HashSize]byte,
	set *cdn.ArchiveSet,
	parallelism int,
) error {
	type result struct {
		hash [casc.MD5HashSize]byte
		idx  *cdn.ArchiveIndex
		err  error
	}

	if parallelism <= 0 {
		parallelism = 1
	}

	results := make(chan result, len(hashes))

	work := make(chan int, len(hashes))
	for i := range hashes {
		work <- i
	}

	close(work)

	var wg sync.WaitGroup
	for w := 0; w < parallelism; w++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range work {
				h := hashes[i]

				blob, err := c.Fetch(ctx, "data", hex.EncodeToString(h[:])+".index")
				if err != nil {
					results <- result{hash: h, err: err}
					continue
				}

				idx, err := cdn.ParseArchiveIndex(blob)
				results <- result{hash: h, idx: idx, err: err}
			}
		}()
	}

	wg.Wait()
	close(results)

	var firstErr error

	for r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}

			continue
		}

		set.Add(r.hash, r.idx)
	}
	// Surface the first error only if nothing succeeded; otherwise treat
	// the partial result as success.
	if set.Len() == 0 && firstErr != nil {
		return fmt.Errorf("load cdn archives: %w", firstErr)
	}

	return nil
}

// fetchByEKeyViaArchives tries the archive set first, then falls back to a
// flat per-EKey CDN GET. Both paths terminate in archive.DecodeSpan.
//
// When Options.CacheDir is set, the raw archive blob (or per-EKey blob) is
// cached locally on first fetch and re-used on subsequent reads.
func (s *Storage) fetchByEKeyViaArchives(ctx context.Context, e casc.EKey) ([]byte, error) {
	s.mu.RLock()
	archives := s.CDNArchives
	c := s.CDN
	s.mu.RUnlock()

	if c == nil {
		return nil, casc.ErrFileNotFound
	}

	if archives != nil {
		if loc, ok := archives.Lookup(e); ok {
			body, err := c.FetchRange(ctx,
				"data", loc.ArchiveHashHex,
				int64(loc.Offset), int64(loc.EncodedSize))
			if err != nil {
				return nil, fmt.Errorf("cdn archive %s @ %d+%d: %w",
					loc.ArchiveHashHex, loc.Offset, loc.EncodedSize, err)
			}

			return archive.DecodeSpanWithOptions(body, s.Keys, archive.DecodeOptions{
				OvercomeEncrypted: s.opts.OvercomeEncrypted,
			})
		}
	}

	hexKey := ekeyHex(e)

	decOpts := archive.DecodeOptions{OvercomeEncrypted: s.opts.OvercomeEncrypted}

	// Try local cache first.
	if cached, err := s.cacheRead(hexKey); err == nil {
		return archive.DecodeSpanWithOptions(cached, s.Keys, decOpts)
	}

	body, err := c.Fetch(ctx, "data", hexKey)
	if err != nil {
		return nil, fmt.Errorf("cdn fetch %s: %w", hexKey, err)
	}

	// Best-effort cache write — failure to cache is non-fatal.
	_ = s.cacheWrite(hexKey, body)

	return archive.DecodeSpanWithOptions(body, s.Keys, decOpts)
}
