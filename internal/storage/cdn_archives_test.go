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

package storage

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/cdn"
)

// buildEncodedSpan duplicates internal/archive's test helper: produce a
// full BLTE-encoded-header + single-'N'-frame BLTE blob for `payload`.
func buildEncodedSpan(payload []byte) []byte {
	encoded := append([]byte{'N'}, payload...)
	hash := md5.Sum(encoded)
	const frameHdrSize = 24
	const headerSize = 12 + frameHdrSize

	var blte bytes.Buffer
	blte.Write([]byte{'B', 'L', 'T', 'E'})
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	blte.Write(hs)
	blte.WriteByte(0x0F)
	blte.Write([]byte{0, 0, 1})
	enc := make([]byte, 4)
	binary.BigEndian.PutUint32(enc, uint32(len(encoded)))
	cont := make([]byte, 4)
	binary.BigEndian.PutUint32(cont, uint32(len(payload)))
	blte.Write(enc)
	blte.Write(cont)
	blte.Write(hash[:])
	blte.Write(encoded)

	const encodedHeaderSize = 30
	var span bytes.Buffer
	span.Write(make([]byte, encodedHeaderSize))
	span.Write(blte.Bytes())
	return span.Bytes()
}

// TestStorage_OnlineArchiveLookup spins up a stub CDN serving:
//   - an archive-index file at data/aa/bb/<archHash>.index
//   - a blob at data/aa/bb/<archHash> containing the BLTE span for our EKey
//
// It then calls Storage.fetchByEKeyViaArchives directly and verifies we
// recover the original payload.
func TestStorage_OnlineArchiveLookup(t *testing.T) {
	payload := []byte("greetings from the CDN archive path")
	span := buildEncodedSpan(payload)

	// EKey: arbitrary (must be non-zero so the index recognises the row).
	var ek casc.EKey
	for i := range ek {
		ek[i] = byte(0xA0 + i)
	}

	// Place the span at offset 0x80 inside the archive blob.
	const offset = 0x80
	archive := make([]byte, offset+len(span))
	copy(archive[offset:], span)

	// Build a 1-record archive-index.
	idxFooter := cdn.ArchiveIndexFooter{
		PageSizeKB:      4,
		OffsetBytes:     4,
		SizeBytes:       4,
		EKeyLength:      16,
		FooterHashBytes: 8,
	}
	indexBlob := cdn.EncodeArchiveIndex(idxFooter, []cdn.ArchiveIndexEntry{
		{EKey: ek, Offset: offset, EncodedSize: uint64(len(span))},
	})

	// Stub CDN.
	var archHash [casc.MD5HashSize]byte
	for i := range archHash {
		archHash[i] = byte(0x10 + i)
	}
	hexHash := hex.EncodeToString(archHash[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, hexHash+".index"):
			w.Write(indexBlob)
		case strings.HasSuffix(r.URL.Path, hexHash):
			rng := r.Header.Get("Range")
			if rng == "" {
				w.Write(archive)
				return
			}
			// Parse "bytes=A-B".
			rng = strings.TrimPrefix(rng, "bytes=")
			parts := strings.SplitN(rng, "-", 2)
			a, _ := strconv.Atoi(parts[0])
			b, _ := strconv.Atoi(parts[1])
			w.WriteHeader(http.StatusPartialContent)
			w.Write(archive[a : b+1])
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	client := cdn.NewClient([]string{host}, "tpr/test")

	// Directly populate the archive set and storage.
	set := cdn.NewArchiveSet()
	parsed, err := cdn.ParseArchiveIndex(indexBlob)
	if err != nil {
		t.Fatalf("parse index: %v", err)
	}
	set.Add(archHash, parsed)

	s := &Storage{CDN: client, CDNArchives: set}
	got, err := s.fetchByEKeyViaArchives(t.Context(), ek)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}

	// Sanity: a missing EKey should miss archives and 404 on flat fetch.
	var miss casc.EKey
	miss[0] = 0xFF
	if _, err := s.fetchByEKeyViaArchives(t.Context(), miss); err == nil {
		t.Fatal("expected error for missing EKey, got nil")
	}
}

// TestLoadCDNArchiveIndexes_PartialFailure: one archive returns 500, the
// other returns a valid index. Loader should keep going and produce a set
// with one archive's contents.
func TestLoadCDNArchiveIndexes_PartialFailure(t *testing.T) {
	var ek casc.EKey
	ek[0] = 0xCD

	idxFooter := cdn.ArchiveIndexFooter{
		PageSizeKB: 4, OffsetBytes: 4, SizeBytes: 4, EKeyLength: 16, FooterHashBytes: 8,
	}
	goodIndex := cdn.EncodeArchiveIndex(idxFooter, []cdn.ArchiveIndexEntry{
		{EKey: ek, Offset: 0, EncodedSize: 16},
	})

	var goodHash, badHash [casc.MD5HashSize]byte
	for i := range goodHash {
		goodHash[i] = byte(0xA0 + i)
	}
	for i := range badHash {
		badHash[i] = byte(0xB0 + i)
	}
	goodHex := hex.EncodeToString(goodHash[:])
	badHex := hex.EncodeToString(badHash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, goodHex):
			w.Write(goodIndex)
		case strings.Contains(r.URL.Path, badHex):
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := cdn.NewClient([]string{strings.TrimPrefix(srv.URL, "http://")}, "tpr/test")
	set := cdn.NewArchiveSet()
	if err := fetchAndMergeArchiveIndexes(context.Background(), c,
		[][casc.MD5HashSize]byte{goodHash, badHash}, set, 2); err != nil {
		t.Fatalf("loader: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("set len=%d, want 1", set.Len())
	}
	if _, ok := set.Lookup(ek); !ok {
		t.Fatal("good ekey missing from set")
	}
}
