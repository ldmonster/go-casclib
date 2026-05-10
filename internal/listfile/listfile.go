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

package listfile

import (
	"bufio"
	"io"
	"strings"

	"github.com/ldmonster/go-casclib/internal/hashes"
)

// List is an in-memory listfile mapping pre-hashed filenames to their
// canonical text form. Filenames are normalized to upper-case with backslash
// separators before hashing (Blizzard convention).
type List struct {
	byHash map[uint64]string
}

// New returns an empty list.
func New() *List {
	return &List{byHash: make(map[uint64]string)}
}

// Load reads filenames from r, one per line. Empty lines and lines starting
// with '#' or ';' are skipped.
func Load(r io.Reader) (*List, error) {
	l := New()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		l.Add(line)
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return l, nil
}

// Add stores a filename, recording its 64-bit Jenkins hash.
func (l *List) Add(name string) {
	h := HashFileName(name)
	l.byHash[h] = name
}

// Lookup returns the canonical name for the given pre-computed hash, or "".
func (l *List) Lookup(hash uint64) string {
	return l.byHash[hash]
}

// LookupName normalizes name and returns it if present in the list, or "".
func (l *List) LookupName(name string) string {
	return l.byHash[HashFileName(name)]
}

// Len returns the number of entries.
func (l *List) Len() int { return len(l.byHash) }

// HashFileName normalizes a filename (uppercase, '/' -> '\\') and returns
// the 64-bit Jenkins hashlittle2 used by CASC.
func HashFileName(name string) uint64 {
	b := []byte(name)
	for i, c := range b {
		switch {
		case c == '/':
			b[i] = '\\'
		case c >= 'a' && c <= 'z':
			b[i] = c - 32
		}
	}

	return hashes.HashFileName(b)
}
