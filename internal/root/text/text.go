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

// Package text implements the simple text-format root file used by older
// games (StarCraft 1, HotS, etc.). The format is one entry per line:
//
//	<filename>|<MD5>
//
// where MD5 is the file's CKey as 32 hex characters.
package text

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/listfile"
	"github.com/ldmonster/go-casclib/internal/root"
)

// Handler is a text-root implementation.
type Handler struct {
	byHash map[uint64]*entry
}

type entry struct {
	name string
	ck   casc.CKeyEntry
}

func init() {
	root.Register(Probe)
}

// Probe accepts ASCII text containing at least one "|<32 hex chars>" entry
// in the first ~1 KB. We deliberately scan past comment lines.
func Probe(data []byte) (root.Handler, error) {
	head := data
	if len(head) > 1024 {
		head = head[:1024]
	}

	if !looksLikeText(head) {
		return nil, casc.ErrBadFormat
	}

	if !bytes.ContainsRune(head, '|') {
		return nil, casc.ErrBadFormat
	}

	return Parse(data)
}

func looksLikeText(b []byte) bool {
	for _, c := range b {
		if c == '\t' || c == '\r' || c == '\n' || c >= 0x20 {
			continue
		}

		return false
	}

	return true
}

// Parse parses an in-memory text root file.
func Parse(data []byte) (*Handler, error) {
	h := &Handler{byHash: make(map[uint64]*entry)}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		bar := strings.IndexByte(line, '|')
		if bar < 0 {
			continue
		}

		name := strings.TrimSpace(line[:bar])

		hexStr := strings.TrimSpace(line[bar+1:])
		if len(hexStr) != 32 {
			continue
		}

		md5b, err := hex.DecodeString(hexStr)
		if err != nil {
			continue
		}

		var ck casc.CKey
		copy(ck[:], md5b)

		hash := listfile.HashFileName(name)
		e := &entry{name: name, ck: casc.CKeyEntry{
			CKey:         ck,
			FileNameHash: hash,
			FileDataID:   casc.InvalidID,
			Flags:        casc.CEFlagHasCKey,
		}}
		h.byHash[hash] = e
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return h, nil
}

// Name implements root.Handler.
func (h *Handler) Name() string { return "Text" }

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
	for _, e := range h.byHash {
		if !yield(e.name, &e.ck) {
			return
		}
	}
}

// Features implements root.Handler.
func (h *Handler) Features() uint32 {
	return casc.FeatureFileNames | casc.FeatureRootCKey | casc.FeatureFNameHashes
}
