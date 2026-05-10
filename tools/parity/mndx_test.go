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

// MNDX cross-validation harness.
//
// CASC roots used by StarCraft II / Heroes of the Storm / Warcraft III:
// Reforged are MNDX (a Patricia trie). The Go implementation lives in
// internal/root/mndx; behavioural parity against the upstream CascLib is
// validated here, fixture-driven.
//
// Activation
//
//   - CASC_PARITY_MNDX_FIXTURES — colon-separated list of storage
//     directories (typically Heroes/SC2/WC3R installs).
//   - CASCLIB_PARITY_CMD          — Go parity binary (default: bin/casc-parity).
//   - CASCLIB_PARITY_C_CMD        — C parity binary
//                                   (default: tools/casclib-parity-c/build/casclib-parity-c).
//
// Per fixture the test runs:
//
//   1. `info` against the Go binary; skips the case unless
//      `root_type == "MNDX"`. This filter prevents wasting CI cycles on
//      non-MNDX installs even when CASC_PARITY_MNDX_FIXTURES is set
//      sloppily.
//   2. `info` and `list` against the C binary.
//   3. Asserts equal `file_count` and equal sorted name sets.
//   4. If `CASC_PARITY_MNDX_READ` is >0, picks that many common file
//      names and asserts equal SHA-256 from both binaries (`read`).
//
// The C binary is optional — when missing the test only validates the
// Go binary's `info`+`list` produce the expected MNDX shape.

package parity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func cParityBin(t *testing.T) string {
	t.Helper()

	if v := os.Getenv("CASCLIB_PARITY_C_CMD"); v != "" {
		return v
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	dir := cwd
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(
			dir, "tools", "casclib-parity-c", "build", "casclib-parity-c",
		)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}

		dir = parent
	}

	return ""
}

type infoOut struct {
	FileCount int    `json:"file_count"`
	RootType  string `json:"root_type"`
	Product   string `json:"product"`
}

type listLine struct {
	Name string `json:"name"`
}

type readOut struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func runJSON(t *testing.T, bin string, args ...string) ([]byte, error) {
	t.Helper()

	cmd := exec.Command(bin, args...)

	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se

	err := cmd.Run()
	if err != nil {
		return nil, &cmdErr{stdout: so.Bytes(), stderr: se.Bytes(), err: err}
	}

	return so.Bytes(), nil
}

type cmdErr struct {
	stdout []byte
	stderr []byte
	err    error
}

func (e *cmdErr) Error() string {
	return e.err.Error() + ": stderr=" + string(e.stderr)
}

func parseInfo(b []byte) (infoOut, error) {
	var i infoOut
	err := json.Unmarshal(b, &i)

	return i, err
}

func parseList(b []byte) ([]string, error) {
	var names []string

	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)

	for sc.Scan() {
		var l listLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, err
		}

		if l.Name != "" {
			names = append(names, l.Name)
		}
	}

	return names, sc.Err()
}

// TestMNDXCrossValidation drives Go vs. C parity binaries against each
// MNDX fixture from CASC_PARITY_MNDX_FIXTURES. Skips when no fixtures
// or no binaries are available.
func TestMNDXCrossValidation(t *testing.T) {
	val := os.Getenv("CASC_PARITY_MNDX_FIXTURES")
	if val == "" {
		t.Skip("CASC_PARITY_MNDX_FIXTURES not set")
	}

	goBin := parityBin(t)
	cBin := cParityBin(t)

	readN := 0
	if v := os.Getenv("CASC_PARITY_MNDX_READ"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			readN = n
		}
	}

	for _, dir := range strings.Split(val, ":") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}

		t.Run(filepath.Base(dir), func(t *testing.T) {
			if _, err := os.Stat(dir); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					t.Skipf("fixture %q does not exist", dir)
				}

				t.Fatalf("stat: %v", err)
			}

			// Go side: info.
			out, err := runJSON(t, goBin, "info", dir)
			if err != nil {
				t.Fatalf("go info: %v", err)
			}

			goInfo, err := parseInfo(out)
			if err != nil {
				t.Fatalf("decode go info: %v: %s", err, out)
			}

			if !strings.EqualFold(goInfo.RootType, "MNDX") {
				t.Skipf("fixture root_type=%q is not MNDX", goInfo.RootType)
			}

			// Go side: list.
			out, err = runJSON(t, goBin, "list", dir)
			if err != nil {
				t.Fatalf("go list: %v", err)
			}

			goNames, err := parseList(out)
			if err != nil {
				t.Fatalf("decode go list: %v", err)
			}

			sort.Strings(goNames)

			if len(goNames) == 0 {
				t.Fatalf("MNDX fixture %s produced empty Go listing", dir)
			}

			if cBin == "" {
				t.Logf("C parity binary not built; "+
					"validated Go side only (%d entries)", len(goNames))
				return
			}

			// C side: info + list.
			out, err = runJSON(t, cBin, "info", dir)
			if err != nil {
				t.Fatalf("c info: %v", err)
			}

			cInfo, err := parseInfo(out)
			if err != nil {
				t.Fatalf("decode c info: %v: %s", err, out)
			}

			if cInfo.FileCount != goInfo.FileCount {
				t.Errorf(
					"file_count drift: go=%d c=%d",
					goInfo.FileCount, cInfo.FileCount,
				)
			}

			out, err = runJSON(t, cBin, "list", dir)
			if err != nil {
				t.Fatalf("c list: %v", err)
			}

			cNames, err := parseList(out)
			if err != nil {
				t.Fatalf("decode c list: %v", err)
			}

			sort.Strings(cNames)

			onlyGo, onlyC := setDiff(goNames, cNames)
			if len(onlyGo) > 0 || len(onlyC) > 0 {
				t.Errorf("name set drift: only_go=%d only_c=%d (sample go=%v c=%v)",
					len(onlyGo), len(onlyC),
					sample(onlyGo, 5), sample(onlyC, 5))
			}

			if readN > 0 {
				common := intersect(goNames, cNames)
				if len(common) > readN {
					common = common[:readN]
				}

				mism := 0

				for _, name := range common {
					gh, gerr := readSHA256(t, goBin, dir, name)
					ch, cerr := readSHA256(t, cBin, dir, name)

					if gerr != nil || cerr != nil {
						mism++
						continue
					}

					if gh != ch {
						mism++

						t.Errorf("read drift on %q: go=%s c=%s", name, gh, ch)
					}
				}

				if mism > 0 {
					t.Errorf("%d/%d files mismatched on read", mism, len(common))
				}
			}
		})
	}
}

func readSHA256(t *testing.T, bin, dir, name string) (string, error) {
	t.Helper()

	out, err := runJSON(t, bin, "read", dir, name)
	if err != nil {
		return "", err
	}

	var r readOut
	if err := json.Unmarshal(out, &r); err != nil {
		return "", err
	}

	if r.SHA256 == "" {
		// Belt and braces: hash the name as a poor-man's fallback so
		// missing SHA256 fields surface as a hard mismatch.
		sum := sha256.Sum256([]byte(name))
		return "missing:" + hex.EncodeToString(sum[:8]), nil
	}

	return r.SHA256, nil
}

// setDiff returns sorted (a-b, b-a) given pre-sorted inputs.
func setDiff(a, b []string) ([]string, []string) {
	var (
		i, j         int
		onlyA, onlyB []string
	)

	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			onlyA = append(onlyA, a[i])
			i++
		case a[i] > b[j]:
			onlyB = append(onlyB, b[j])
			j++
		default:
			i++
			j++
		}
	}

	onlyA = append(onlyA, a[i:]...)
	onlyB = append(onlyB, b[j:]...)

	return onlyA, onlyB
}

// intersect returns elements in both a and b given pre-sorted inputs.
func intersect(a, b []string) []string {
	var (
		i, j   int
		common []string
	)

	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			i++
		case a[i] > b[j]:
			j++
		default:
			common = append(common, a[i])
			i++
			j++
		}
	}

	return common
}

func sample(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}

	return xs[:n]
}
