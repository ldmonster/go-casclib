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

// Command parity-diff drives both parity binaries (the Go in-repo
// implementation and the native CascLib oracle) against a fixture
// directory and emits a JSON drift report.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"sort"
)

type capabilities struct {
	Impl        string   `json:"impl"`
	Protocol    string   `json:"protocol"`
	Subcommands []string `json:"subcommands"`
}

type infoRecord struct {
	FileCount int `json:"file_count"`
}

type listEntry struct {
	Name string `json:"name"`
}

type readRecord struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type readPair struct {
	Name  string     `json:"name"`
	Go    readRecord `json:"go"`
	C     readRecord `json:"c"`
	Equal bool       `json:"equal"`
}

type binaryReport struct {
	Path         string       `json:"path"`
	Capabilities capabilities `json:"capabilities"`
	FileCount    int          `json:"file_count"`
	Names        []string     `json:"-"`
}

type drift struct {
	Fixture     string       `json:"fixture"`
	Pattern     string       `json:"pattern,omitempty"`
	Go          binaryReport `json:"go"`
	C           binaryReport `json:"c"`
	Differences []difference `json:"differences"`
	OnlyInGo    []string     `json:"only_in_go,omitempty"`
	OnlyInC     []string     `json:"only_in_c,omitempty"`
	Reads       []readPair   `json:"reads,omitempty"`
}

type difference struct {
	Field string `json:"field"`
	Go    any    `json:"go"`
	C     any    `json:"c"`
}

func main() {
	goBin := flag.String("go", "bin/casc-parity", "path to the Go parity binary")
	cBin := flag.String(
		"c",
		"tools/casclib-parity-c/build/casclib-parity-c",
		"path to the native CascLib parity binary",
	)
	fixture := flag.String("fixture", "", "storage directory to drive both binaries against")
	pattern := flag.String("pattern", "", "optional `list` glob")
	out := flag.String("out", "", "write JSON report to this file (default: stdout)")
	readN := flag.Int(
		"read",
		0,
		"if >0, run `read` against both binaries on up to N common file names and diff their sha256",
	)

	flag.Parse()

	if *fixture == "" {
		fail("missing -fixture")
	}

	if _, err := os.Stat(*fixture); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "fixture %q does not exist; nothing to compare\n", *fixture)
			os.Exit(0)
		}

		fail("stat fixture: %v", err)
	}

	d := drift{Fixture: *fixture, Pattern: *pattern}
	d.Go = mustReport(*goBin, *fixture, *pattern)
	d.C = mustReport(*cBin, *fixture, *pattern)

	if d.Go.Capabilities.Protocol != d.C.Capabilities.Protocol {
		d.Differences = append(d.Differences, difference{
			Field: "capabilities.protocol",
			Go:    d.Go.Capabilities.Protocol,
			C:     d.C.Capabilities.Protocol,
		})
	}

	if d.Go.FileCount != d.C.FileCount {
		d.Differences = append(d.Differences, difference{
			Field: "info.file_count",
			Go:    d.Go.FileCount,
			C:     d.C.FileCount,
		})
	}

	d.OnlyInGo, d.OnlyInC = symDiff(d.Go.Names, d.C.Names)
	if len(d.OnlyInGo) > 0 || len(d.OnlyInC) > 0 {
		d.Differences = append(d.Differences, difference{
			Field: "list.names",
			Go:    len(d.OnlyInGo),
			C:     len(d.OnlyInC),
		})
	}

	if *readN > 0 {
		common := commonNames(d.Go.Names, d.C.Names)
		if len(common) > *readN {
			common = common[:*readN]
		}

		mismatches := 0

		for _, name := range common {
			gr, gerr := readOne(*goBin, *fixture, name)

			cr, cerr := readOne(*cBin, *fixture, name)
			if gerr != nil || cerr != nil {
				// Skip files one side can't read; record as a mismatch.
				d.Reads = append(d.Reads, readPair{Name: name, Go: gr, C: cr, Equal: false})
				mismatches++

				continue
			}

			equal := gr.SHA256 == cr.SHA256 && gr.Size == cr.Size

			d.Reads = append(d.Reads, readPair{Name: name, Go: gr, C: cr, Equal: equal})
			if !equal {
				mismatches++
			}
		}

		if mismatches > 0 {
			d.Differences = append(d.Differences, difference{
				Field: "read.sha256",
				Go:    fmt.Sprintf("%d/%d mismatched", mismatches, len(common)),
				C:     fmt.Sprintf("%d/%d mismatched", mismatches, len(common)),
			})
		}
	}

	var (
		w       io.Writer = os.Stdout
		outFile *os.File
	)

	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fail("create out: %v", err)
		}

		outFile = f
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(d); err != nil {
		fmt.Fprintf(os.Stderr, "parity-diff: encode: %v\n", err)

		if outFile != nil {
			_ = outFile.Close()
		}

		os.Exit(2)
	}

	if outFile != nil {
		_ = outFile.Close()
	}

	if len(d.Differences) > 0 {
		fmt.Fprintf(os.Stderr, "parity-diff: %d difference(s) detected\n", len(d.Differences))

		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "parity-diff: no drift")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "parity-diff: "+format+"\n", args...)
	os.Exit(2)
}

func run(bin string, args ...string) ([]byte, error) {
	cmd := exec.Command(bin, args...)

	var so, se bytes.Buffer

	cmd.Stdout = &so

	cmd.Stderr = &se
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w (stderr=%s)", bin, args, err, se.String())
	}

	return so.Bytes(), nil
}

func mustReport(bin, fixture, pattern string) binaryReport {
	r := binaryReport{Path: bin}

	out, err := run(bin, "capabilities")
	if err != nil {
		fail("%v", err)
	}

	if err := json.Unmarshal(out, &r.Capabilities); err != nil {
		fail("decode capabilities (%s): %v", bin, err)
	}

	out, err = run(bin, "info", fixture)
	if err != nil {
		fail("%v", err)
	}

	var info infoRecord
	if err := json.Unmarshal(out, &info); err != nil {
		fail("decode info (%s): %v", bin, err)
	}

	r.FileCount = info.FileCount

	args := []string{"list", fixture}
	if pattern != "" {
		args = append(args, pattern)
	}

	out, err = run(bin, args...)
	if err != nil {
		fail("%v", err)
	}

	scan := bufio.NewScanner(bytes.NewReader(out))
	scan.Buffer(make([]byte, 0, 1<<20), 64<<20)

	for scan.Scan() {
		var e listEntry
		if err := json.Unmarshal(scan.Bytes(), &e); err != nil {
			fail("decode list (%s): %v: %q", bin, err, scan.Text())
		}

		r.Names = append(r.Names, e.Name)
	}

	if err := scan.Err(); err != nil {
		fail("scan list (%s): %v", bin, err)
	}

	sort.Strings(r.Names)

	return r
}

// symDiff returns elements present in a but not b, and vice versa.
// Both inputs must be sorted.
func symDiff(a, b []string) ([]string, []string) {
	var onlyA, onlyB []string

	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			i++
			j++
		case a[i] < b[j]:
			onlyA = append(onlyA, a[i])
			i++
		default:
			onlyB = append(onlyB, b[j])
			j++
		}
	}

	onlyA = append(onlyA, a[i:]...)
	onlyB = append(onlyB, b[j:]...)

	return onlyA, onlyB
}

// commonNames returns the intersection of two sorted name slices.
func commonNames(a, b []string) []string {
	out := make([]string, 0, min(len(a), len(b)))

	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}

	return out
}

// readOne invokes `<bin> read <fixture> <name>` and decodes the resulting
// {name,size,sha256,...} record. Errors propagate to the caller so they
// can be recorded as drift rather than aborting the whole run.
func readOne(bin, fixture, name string) (readRecord, error) {
	out, err := run(bin, "read", fixture, name)
	if err != nil {
		return readRecord{Name: name}, err
	}

	var rr readRecord
	if err := json.Unmarshal(out, &rr); err != nil {
		return readRecord{Name: name}, fmt.Errorf("decode read (%s, %s): %w", bin, name, err)
	}

	return rr, nil
}
