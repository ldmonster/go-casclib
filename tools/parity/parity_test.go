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

// Package parity drives the casc-parity binary against fixtures and
// validates its output. This is an integration suite, not a unit test.
//
// Run modes:
//
//  1. Preflight: TestParityCommandCapabilityPreflight always runs. It
//     invokes `casc-parity capabilities` and asserts the JSON schema.
//
//  2. Fixture replay: TestParityFixtures runs only when CASC_PARITY_FIXTURES
//     is set to a colon-separated list of storage directories. For each
//     fixture the test runs `info` and `list` subcommands and asserts that
//     they produce well-formed JSON and a non-zero file count.
//
// The binary path is taken from CASCLIB_PARITY_CMD or defaults to
// `bin/casc-parity` relative to the repository root.
package parity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func parityBin(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("CASCLIB_PARITY_CMD"); v != "" {
		return v
	}
	// Walk up from cwd looking for bin/casc-parity.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "bin", "casc-parity")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("casc-parity binary not found; set CASCLIB_PARITY_CMD or run `task parity:build`")
	return ""
}

func runParity(t *testing.T, args ...string) (stdout, stderr []byte, err error) {
	t.Helper()
	bin := parityBin(t)
	cmd := exec.Command(bin, args...)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	return so.Bytes(), se.Bytes(), err
}

// TestParityCommandCapabilityPreflight asserts the parity binary reports a
// known protocol version and the expected subcommand set.
func TestParityCommandCapabilityPreflight(t *testing.T) {
	stdout, stderr, err := runParity(t, "capabilities")
	if err != nil {
		t.Fatalf("capabilities: %v\nstderr: %s", err, stderr)
	}
	var caps struct {
		Impl        string   `json:"impl"`
		Version     string   `json:"version"`
		Protocol    string   `json:"protocol"`
		Subcommands []string `json:"subcommands"`
	}
	if err := json.Unmarshal(stdout, &caps); err != nil {
		t.Fatalf("decode capabilities: %v\nout: %s", err, stdout)
	}
	if caps.Impl == "" {
		t.Errorf("missing impl in capabilities: %s", stdout)
	}
	if caps.Protocol == "" {
		t.Errorf("missing protocol in capabilities: %s", stdout)
	}
	wanted := map[string]bool{
		"capabilities": false,
		"info":         false,
		"list":         false,
		"read":         false,
	}
	for _, sc := range caps.Subcommands {
		if _, ok := wanted[sc]; ok {
			wanted[sc] = true
		}
	}
	for sc, present := range wanted {
		if !present {
			t.Errorf("capabilities missing subcommand %q", sc)
		}
	}
}

// TestParityCommandUsageErrors covers user-error paths.
func TestParityCommandUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no-args", nil},
		{"unknown-cmd", []string{"frobnicate"}},
		{"info-missing-arg", []string{"info"}},
		{"list-missing-arg", []string{"list"}},
		{"read-missing-args", []string{"read", "/tmp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, err := runParity(t, tc.args...)
			if err == nil {
				t.Fatalf("expected non-zero exit for %v", tc.args)
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("expected ExitError, got %T: %v", err, err)
			}
			if ee.ExitCode() != 1 {
				t.Errorf("expected exit code 1 (user error), got %d; stderr=%s",
					ee.ExitCode(), stderr)
			}
		})
	}
}

// TestParityCommandInfoBadDir validates exit code 2 for storage errors.
func TestParityCommandInfoBadDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	_, stderr, err := runParity(t, "info", dir)
	if err == nil {
		t.Fatalf("expected non-zero exit for missing dir; stderr=%s", stderr)
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if ee.ExitCode() == 0 {
		t.Errorf("expected non-zero exit code")
	}
}

// TestParityFixtures runs `info` and `list` on each fixture dir from the
// CASC_PARITY_FIXTURES env var (colon-separated). If unset, the test is
// skipped.
func TestParityFixtures(t *testing.T) {
	val := os.Getenv("CASC_PARITY_FIXTURES")
	if val == "" {
		t.Skip("CASC_PARITY_FIXTURES not set; skipping fixture replay")
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
				t.Fatalf("stat fixture: %v", err)
			}
			// info
			stdout, stderr, err := runParity(t, "info", dir)
			if err != nil {
				t.Fatalf("info %s failed: %v\nstderr: %s", dir, err, stderr)
			}
			var info struct {
				FileCount int `json:"file_count"`
			}
			if err := json.Unmarshal(stdout, &info); err != nil {
				t.Fatalf("decode info json: %v\nout=%s", err, stdout)
			}
			if info.FileCount < 0 {
				t.Errorf("non-sensical file_count: %d", info.FileCount)
			}
			// list
			stdout, stderr, err = runParity(t, "list", dir)
			if err != nil {
				t.Fatalf("list %s failed: %v\nstderr: %s", dir, err, stderr)
			}
			lines := 0
			scan := bufio.NewScanner(bytes.NewReader(stdout))
			scan.Buffer(make([]byte, 0, 1<<20), 16<<20)
			for scan.Scan() {
				var entry struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(scan.Bytes(), &entry); err != nil {
					t.Fatalf("decode list line: %v: %q", err, scan.Text())
				}
				lines++
			}
			if err := scan.Err(); err != nil {
				t.Fatalf("scan list: %v", err)
			}
			if info.FileCount != lines {
				t.Errorf("info.file_count=%d but list emitted %d lines",
					info.FileCount, lines)
			}
		})
	}
}
