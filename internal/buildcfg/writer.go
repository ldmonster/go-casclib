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

// Build/CDN config writer + .build.info CSV writer.
//
// Build/CDN configs are plain "name = value [value...]" lines. .build.info
// is a tab-separated CSV with a one-line "field!type:size" header.

package buildcfg

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// NewConfig creates an empty config builder.
func NewConfig() *Config {
	return &Config{entries: make(map[string][]string)}
}

// Set replaces (or inserts) the values for name.
func (c *Config) Set(name string, values ...string) {
	if c.entries == nil {
		c.entries = make(map[string][]string)
	}

	if _, exists := c.entries[name]; !exists {
		c.order = append(c.order, name)
	}

	cp := make([]string, len(values))
	copy(cp, values)
	c.entries[name] = cp
}

// SetKey records "<name> = <hex(key)>" using lower-case hex.
func (c *Config) SetKey(name string, key [16]byte) {
	c.Set(name, hex.EncodeToString(key[:]))
}

// SetKeyPair records "<name> = <hex(ckey)> <hex(ekey)>".
func (c *Config) SetKeyPair(name string, ckey, ekey [16]byte) {
	c.Set(name, hex.EncodeToString(ckey[:]), hex.EncodeToString(ekey[:]))
}

// SetSizePair records "<name> = <content_size> <encoded_size>".
func (c *Config) SetSizePair(name string, contentSize, encodedSize uint64) {
	c.Set(name, strconv.FormatUint(contentSize, 10), strconv.FormatUint(encodedSize, 10))
}

// SetArchives records the archives = list with one hex hash per archive.
func (c *Config) SetArchives(hashes [][16]byte) {
	vals := make([]string, len(hashes))
	for i, h := range hashes {
		vals[i] = hex.EncodeToString(h[:])
	}

	c.Set("archives", vals...)
}

// EncodeText emits the config as text. Variables are written in the
// order they were first added via Set/SetKey/etc.
func (c *Config) EncodeText() []byte {
	var buf bytes.Buffer

	for _, name := range c.order {
		vals := c.entries[name]
		fmt.Fprintf(&buf, "%s = %s\n", name, strings.Join(vals, " "))
	}

	return buf.Bytes()
}

// BuildInfoRow describes one row of the .build.info file. All fields
// are optional; empty fields are emitted as the empty string.
type BuildInfoRow struct {
	Region        string
	BuildKey      string
	CDNKey        string
	InstallKey    string
	IMSize        string
	CDNPath       string
	CDNHosts      string
	CDNServers    string
	Tags          string
	Armadillo     string
	LastActivated string
	Version       string
	KeyRing       string
	Product       string
	UID           string
	BuildComplete string
	BuildToken    string
}

var buildInfoColumns = []string{
	"Branch!STRING:0",
	"Active!DEC:1",
	"Build Key!HEX:16",
	"CDN Key!HEX:16",
	"Install Key!HEX:16",
	"IM Size!DEC:4",
	"CDN Path!STRING:0",
	"CDN Hosts!STRING:0",
	"CDN Servers!STRING:0",
	"Tags!STRING:0",
	"Armadillo!STRING:0",
	"Last Activated!STRING:0",
	"Build Complete!DEC:1",
	"Last Played!STRING:0",
	"Product!STRING:0",
	"Version!STRING:0",
}

// EncodeBuildInfo serialises a one- or many-row .build.info file.
//
// The output starts with the column descriptor line, then one tab-
// separated row per BuildInfoRow.
func EncodeBuildInfo(rows []BuildInfoRow) []byte {
	var buf bytes.Buffer

	buf.WriteString(strings.Join(buildInfoColumns, "|"))
	buf.WriteByte('\n')

	for _, r := range rows {
		fields := []string{
			r.Region,     // Branch
			"1",          // Active
			r.BuildKey,   // Build Key
			r.CDNKey,     // CDN Key
			r.InstallKey, // Install Key
			r.IMSize,
			r.CDNPath,
			r.CDNHosts,
			r.CDNServers,
			r.Tags,
			r.Armadillo,
			r.LastActivated,
			r.BuildComplete,
			"",
			r.Product,
			r.Version,
		}
		buf.WriteString(strings.Join(fields, "|"))
		buf.WriteByte('\n')
	}

	return buf.Bytes()
}
