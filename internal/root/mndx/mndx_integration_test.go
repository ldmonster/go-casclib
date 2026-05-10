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

// MNDX live-storage cross-validation.
//
// This test is skipped unless CASC_TEST_STORAGE_HOTS is set to a directory
// containing a Heroes of the Storm CASC install (the legacy MNDX root).
// When set, it opens the storage via the public API, asserts the root
// handler is MNDX, walks every entry, and spot-reads files to confirm
// the trie name index and the BLTE pipeline both work end-to-end.
//
// A real fixture is the only way to exercise the Patricia trie thoroughly,
// so this is the recommended parity check for MNDX (per
// rewriting_plan.md §6.1).

package mndx_test

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
	pcasc "github.com/ldmonster/go-casclib/pkg/casc"
)

func storagePath(t *testing.T) string {
	t.Helper()

	dir := os.Getenv("CASC_TEST_STORAGE_HOTS")
	if dir == "" {
		t.Skip("set CASC_TEST_STORAGE_HOTS to a Heroes of the Storm install to run MNDX integration tests")
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("CASC_TEST_STORAGE_HOTS not accessible: %v", err)
	}

	return dir
}

func TestIntegrationMNDXOpenAndIterate(t *testing.T) {
	dir := storagePath(t)

	st, err := pcasc.OpenStorage(dir, pcasc.OpenOptions{LocaleMask: pcasc.LocaleAll})
	if err != nil {
		t.Fatalf("OpenStorage(%q): %v", dir, err)
	}
	defer st.Close()

	info := st.GetInfo()
	if info.RootType != "MNDX" {
		t.Skipf("storage root is %q, not MNDX (skipping MNDX-specific checks)", info.RootType)
	}

	if info.FileCount == 0 {
		t.Fatal("storage reports zero files")
	}

	t.Logf("MNDX storage: %d files, build %s", info.FileCount, info.BuildVersion)

	var (
		seen      int
		samples   []string
		maxSample = 16
	)

	if err := st.FindFiles("*", func(name string, _ pcasc.FileInfo) bool {
		seen++

		if len(samples) < maxSample && name != "" {
			samples = append(samples, name)
		}

		return true
	}); err != nil {
		t.Fatalf("FindFiles: %v", err)
	}

	if seen != info.FileCount {
		t.Errorf("FindFiles yielded %d names; storage info reports %d", seen, info.FileCount)
	}

	for _, name := range samples {
		f, err := st.OpenFile(name)
		if errors.Is(err, casc.ErrFileNotFound) {
			continue
		}

		if err != nil {
			t.Errorf("OpenFile(%q): %v", name, err)

			continue
		}

		buf := make([]byte, 4096)
		if _, err := f.Read(buf); err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("Read(%q): %v", name, err)
		}

		_ = f.Close()
	}
}
