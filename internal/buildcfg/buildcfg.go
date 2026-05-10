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

// Package buildcfg parses Blizzard build/CDN config files. These are plain
// text files of the form "name = value [value...]", where values are
// usually hex strings (CKey, EKey) or numbers. Comments start with '#'.
package buildcfg

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// Config is the parsed set of name -> values entries.
type Config struct {
	entries map[string][]string
	order   []string
}

// Get returns the first value for name, or "".
func (c *Config) Get(name string) string {
	if v, ok := c.entries[name]; ok && len(v) > 0 {
		return v[0]
	}

	return ""
}

// All returns all values for name (or nil).
func (c *Config) All(name string) []string { return c.entries[name] }

// Names returns the list of variable names in file order.
func (c *Config) Names() []string { return c.order }

// CKeyEntry is a (CKey [+ EKey [+ size]]) tuple as encoded by build configs.
type CKeyEntry struct {
	CKey casc.CKey
	EKey casc.EKey
	// HasEKey is true when an encoded key was present.
	HasEKey bool
	// ContentSize, if available (some entries carry "<size> <ckey> <ekey>").
	ContentSize uint64
}

// LookupCKey parses an entry like "encoding" / "encoding-size" pair.
//
// CASC build config entries come in a few shapes:
//
//	root = <ckey>
//	encoding = <ckey> <ekey>
//	encoding-size = <decimal-content-size> <decimal-encoded-size>
//	install = <ckey> <ekey>
//	download = <ckey> <ekey>
//
// LookupCKey returns the CKey/EKey portion, ignoring sizes (which live in a
// sibling "<name>-size" key).
func (c *Config) LookupCKey(name string) (*CKeyEntry, error) {
	vals := c.entries[name]
	if len(vals) == 0 {
		return nil, casc.ErrFileNotFound
	}

	out := &CKeyEntry{}
	if k, err := decodeKey16(vals[0]); err == nil {
		out.CKey = casc.CKey(k)
	} else {
		return nil, err
	}

	if len(vals) >= 2 {
		if k, err := decodeKey16(vals[1]); err == nil {
			out.EKey = casc.EKey(k)
			out.HasEKey = true
		}
	}

	return out, nil
}

func decodeKey16(s string) ([16]byte, error) {
	var out [16]byte
	if len(s) != 32 {
		return out, fmt.Errorf("buildcfg: key %q: want 32 hex chars, got %d", s, len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("buildcfg: %w", err)
	}

	copy(out[:], b)

	return out, nil
}

// Archives returns the list of archive MD5 hashes from a cdn-config's
// `archives = <hex> <hex> ...` field. Each entry is a 16-byte binary hash
// suitable for building the URL "<base>/data/aa/bb/<hex>.index".
//
// Returns a nil slice (no error) if `archives` is absent.
func (c *Config) Archives() ([][16]byte, error) {
	vals := c.entries["archives"]
	if len(vals) == 0 {
		return nil, nil
	}

	out := make([][16]byte, 0, len(vals))
	for _, v := range vals {
		k, err := decodeKey16(v)
		if err != nil {
			return nil, err
		}

		out = append(out, k)
	}

	return out, nil
}

// Parse reads a build/CDN config from r.
func Parse(r io.Reader) (*Config, error) {
	c := &Config{entries: make(map[string][]string)}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}

		name := strings.TrimSpace(line[:eq])
		rest := strings.TrimSpace(line[eq+1:])

		if name == "" {
			continue
		}

		fields := strings.Fields(rest)

		if _, exists := c.entries[name]; !exists {
			c.order = append(c.order, name)
		}

		c.entries[name] = fields
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return c, nil
}
