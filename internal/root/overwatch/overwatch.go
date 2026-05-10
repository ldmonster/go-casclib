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

// Package overwatch implements a minimal Overwatch root handler.
//
// The Overwatch ROOT file is a pipe-delimited CSV with at least the columns
// "FILENAME" and "MD5". Each row maps a top-level manifest filename (such
// as ".../Manifest/<lang>.apm" or ".../TactManifest/<lang>.cmf") to its
// CKey. The full file tree only becomes visible after expanding those
// manifest blobs, which requires per-build encryption keys and is
// **deferred** in this implementation.
//
// What this handler currently provides:
//
//   - Probe-based detection (CSV header containing "FILENAME" and "MD5").
//   - Mapping of manifest paths to their CKeys, exposed via LookupByName
//     and All — sufficient to drive the parity binary's `info` and `list`
//     subcommands, and to back FindFiles for installer-level inspection.
//
// What is not yet implemented:
//
//   - APM (Application Package Manifest) parsing — CascLib's
//     overwatch/apm.cpp. The on-disk format is documented in
//     CascRootFile_OW.cpp.
//   - CMF (Content Manifest File) parsing — CascLib's overwatch/cmf.cpp.
//     CMFs are encrypted with a per-build AES key derived via the
//     Overwatch key schedule (see overwatch/cmf-key.cpp).
//
// Adding APM/CMF support is the largest remaining root-handler task.
package overwatch

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/csv"
	"github.com/ldmonster/go-casclib/internal/listfile"
	"github.com/ldmonster/go-casclib/internal/root"
)

// Handler is the Overwatch root handler.
type Handler struct {
	byHash map[uint64]*entry
	all    []*entry
}

type entry struct {
	name string
	ck   casc.CKeyEntry
}

func init() { root.Register(Probe) }

// Probe identifies an Overwatch root by parsing the CSV header and looking
// for both "FILENAME" and "MD5" columns.
func Probe(data []byte) (root.Handler, error) {
	if !looksLikeASCII(data) {
		return nil, casc.ErrBadFormat
	}

	nl := bytes.IndexByte(data, '\n')
	if nl < 0 || nl > 4096 {
		return nil, casc.ErrBadFormat
	}

	hdr := strings.ToUpper(string(data[:nl]))
	if !strings.Contains(hdr, "FILENAME") || !strings.Contains(hdr, "MD5") {
		return nil, casc.ErrBadFormat
	}

	return Parse(data)
}

func looksLikeASCII(b []byte) bool {
	limit := len(b)
	if limit > 4096 {
		limit = 4096
	}

	for i := 0; i < limit; i++ {
		c := b[i]
		if c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7F) {
			continue
		}

		return false
	}

	return true
}

// Parse parses an Overwatch root CSV. Both "FILENAME" and "MD5" columns
// must be present.
func Parse(data []byte) (*Handler, error) {
	f, err := csv.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	nameCol := -1
	keyCol := -1

	for i, h := range f.Headers {
		switch strings.ToUpper(strings.TrimSpace(h)) {
		case "FILENAME":
			nameCol = i
		case "MD5", "CKEY", "CONTENTHASH", "CONTENT_KEY":
			if keyCol == -1 {
				keyCol = i
			}
		}
	}

	if nameCol < 0 || keyCol < 0 {
		return nil, casc.ErrBadFormat
	}

	h := &Handler{byHash: make(map[uint64]*entry, len(f.Rows))}
	for _, row := range f.Rows {
		if nameCol >= len(row) || keyCol >= len(row) {
			continue
		}

		name := strings.TrimSpace(row[nameCol])

		hexCK := strings.TrimSpace(row[keyCol])
		if len(hexCK) != 32 || name == "" {
			continue
		}

		raw, err := hex.DecodeString(hexCK)
		if err != nil {
			continue
		}

		var ck casc.CKey
		copy(ck[:], raw)

		hash := listfile.HashFileName(name)
		e := &entry{name: name, ck: casc.CKeyEntry{
			CKey:         ck,
			FileNameHash: hash,
			FileDataID:   casc.InvalidID,
			Flags:        casc.CEFlagHasCKey,
		}}
		h.byHash[hash] = e
		h.all = append(h.all, e)
	}

	if len(h.all) == 0 {
		return nil, casc.ErrBadFormat
	}

	return h, nil
}

// Name implements root.Handler.
func (h *Handler) Name() string { return "Overwatch" }

// Features reports the supported feature set.
func (h *Handler) Features() uint32 {
	return casc.FeatureFileNames | casc.FeatureRootCKey
}

// LookupByName implements root.Handler.
func (h *Handler) LookupByName(name string) *casc.CKeyEntry {
	if e := h.byHash[listfile.HashFileName(name)]; e != nil {
		return &e.ck
	}

	return nil
}

// LookupByFileDataID implements root.Handler.
func (h *Handler) LookupByFileDataID(uint32) *casc.CKeyEntry { return nil }

// All implements root.Handler.
func (h *Handler) All(yield func(string, *casc.CKeyEntry) bool) {
	for _, e := range h.all {
		if !yield(e.name, &e.ck) {
			return
		}
	}
}
