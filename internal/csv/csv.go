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

package csv

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// File is a parsed Blizzard-style pipe-delimited table (.build.info, .info).
//
// Columns have a header of the form "Name!TYPE:WIDTH" — only the name is
// retained.
type File struct {
	Headers []string
	Rows    [][]string
}

// Parse reads one Blizzard CSV/TSV table from r. The separator is '|' by
// default, matching the .build.info format.
func Parse(r io.Reader) (*File, error) {
	return ParseSep(r, '|')
}

// ParseSep is like Parse but accepts a custom separator.
func ParseSep(r io.Reader, sep byte) (*File, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	out := &File{}
	first := true

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		fields := splitLine(line, sep)
		if first {
			out.Headers = make([]string, len(fields))
			for i, h := range fields {
				if idx := strings.IndexByte(h, '!'); idx >= 0 {
					h = h[:idx]
				}

				out.Headers[i] = strings.TrimSpace(h)
			}

			first = false

			continue
		}

		out.Rows = append(out.Rows, fields)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("csv scan: %w", err)
	}

	return out, nil
}

func splitLine(s string, sep byte) []string {
	out := make([]string, 0, 8)
	start := 0

	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}

	out = append(out, s[start:])

	return out
}

// Column returns the index of the named column, or -1 if absent.
func (f *File) Column(name string) int {
	for i, h := range f.Headers {
		if h == name {
			return i
		}
	}

	return -1
}

// Get returns f.Rows[row][col] safely; "" if out of bounds.
func (f *File) Get(row int, col string) string {
	c := f.Column(col)
	if c < 0 || row < 0 || row >= len(f.Rows) || c >= len(f.Rows[row]) {
		return ""
	}

	return f.Rows[row][c]
}
