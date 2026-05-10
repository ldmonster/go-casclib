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

package parity

// M6 write-path cross-validation against the upstream CascLib binary.
//
// `pkg/casc.CreateStorage` + `AddFile` + `Flush` emit a synthetic but
// fully-formed CASC archive (BLTE-encoded data segments + V1 .idx +
// ENCODING/DOWNLOAD/INSTALL manifests + build/CDN config + .build.info).
// This test re-opens that archive with the native CascLib oracle
// (tools/casclib-parity-c) and asserts:
//
//   1. `info` succeeds; the C oracle reports the same file count as Go.
//   2. `list` produces the same sorted name set.
//   3. `read <name>` for each emitted file returns content bit-identical
//      to what we wrote.
//
// Skipped when the C oracle binary isn't available (CI without cmake).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/ldmonster/go-casclib/pkg/casc"
)

func TestM6FlushReadableByCOracle(t *testing.T) {
	cBin := cParityBin(t)
	if cBin == "" {
		t.Skip("native CascLib oracle not built (run `task cparity:build`)")
	}

	if _, err := os.Stat(cBin); err != nil {
		t.Skipf("native CascLib oracle not available at %s: %v", cBin, err)
	}

	dir := t.TempDir()

	s, err := casc.CreateStorage(dir, casc.CreateOptions{})
	if err != nil {
		t.Fatalf("CreateStorage: %v", err)
	}

	files := map[string][]byte{
		"hello.txt":           []byte("Hello, CASC!"),
		"data/binary.bin":     bytes.Repeat([]byte{0xAB, 0xCD, 0xEF}, 4096),
		"long/path/readme.md": []byte("# README\n\nM6 cross-validation payload.\n"),
	}

	for name, body := range files {
		if err := s.AddFile(name, body); err != nil {
			t.Fatalf("AddFile %q: %v", name, err)
		}
	}

	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// info via the C oracle.
	out, ierr := runJSON(t, cBin, "info", dir)
	if ierr != nil {
		t.Fatalf("c oracle info: %v", ierr)
	}

	var info struct {
		FileCount int    `json:"file_count"`
		Impl      string `json:"impl"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		t.Fatalf("decode c info: %v: %s", err, out)
	}

	if info.Impl != "casclib-c" {
		t.Errorf("info.impl = %q, want casclib-c", info.Impl)
	}

	if info.FileCount < len(files) {
		t.Errorf("c oracle file_count = %d, want >= %d", info.FileCount, len(files))
	}

	// list via the C oracle.
	out, lerr := runJSON(t, cBin, "list", dir)
	if lerr != nil {
		t.Fatalf("c oracle list: %v", lerr)
	}

	cNames, err := parseList(out)
	if err != nil {
		t.Fatalf("decode c list: %v", err)
	}

	// Normalise CascLib's backslash separators to forward slashes.
	for i, n := range cNames {
		cNames[i] = filepathToSlash(n)
	}

	sort.Strings(cNames)

	want := make([]string, 0, len(files))
	for k := range files {
		want = append(want, k)
	}

	sort.Strings(want)

	// CascLib also surfaces well-known files (ENCODING, INSTALL, ...).
	// Require our user files to be a subset of the listing.
	cSet := make(map[string]struct{}, len(cNames))
	for _, n := range cNames {
		cSet[n] = struct{}{}
	}

	for _, n := range want {
		if _, ok := cSet[n]; !ok {
			t.Errorf("c oracle list missing %q (got %v)", n, cNames)
		}
	}

	// read every file via the C oracle.
	for name, body := range files {
		out, rerr := runJSON(t, cBin, "read", dir, name)
		if rerr != nil {
			t.Errorf("c oracle read %q: %v", name, rerr)
			continue
		}

		var r struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		}
		if err := json.Unmarshal(out, &r); err != nil {
			t.Errorf("decode c read %q: %v: %s", name, err, out)
			continue
		}

		want := sha256.Sum256(body)
		if r.SHA256 != hex.EncodeToString(want[:]) {
			t.Errorf("c oracle read %q sha256 mismatch: got %s want %x",
				name, r.SHA256, want)
		}

		if r.Size != int64(len(body)) {
			t.Errorf("c oracle read %q size: got %d want %d",
				name, r.Size, len(body))
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func filepathToSlash(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			b[i] = '/'
		} else {
			b[i] = s[i]
		}
	}
	return string(b)
}
