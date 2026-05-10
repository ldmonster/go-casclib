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

package casc

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-casclib/internal/buildcfg"
	internalcasc "github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/index"
	"github.com/ldmonster/go-casclib/internal/storage"
)

// buildBLTESpan builds an encoded-header + single-'N' BLTE span for payload.
func buildBLTESpan(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoded := append([]byte{'N'}, payload...)
	hash := md5.Sum(encoded)
	const frameHdrSize = 24
	const headerSize = 12 + frameHdrSize
	const encHdr = 30

	var buf bytes.Buffer
	buf.Write(make([]byte, encHdr))
	buf.Write([]byte{'B', 'L', 'T', 'E'})
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	buf.Write(hs)
	buf.WriteByte(0x0F)
	buf.Write([]byte{0, 0, 1})
	enc := make([]byte, 4)
	binary.BigEndian.PutUint32(enc, uint32(len(encoded)))
	cont := make([]byte, 4)
	binary.BigEndian.PutUint32(cont, uint32(len(payload)))
	buf.Write(enc)
	buf.Write(cont)
	buf.Write(hash[:])
	buf.Write(encoded)
	return buf.Bytes()
}

func mkEKey(seed byte) internalcasc.EKey {
	var k internalcasc.EKey
	for i := 0; i < 16; i++ {
		k[i] = seed + byte(i)
	}
	return k
}

func mkCKey(seed byte) internalcasc.CKey {
	var k internalcasc.CKey
	for i := 0; i < 16; i++ {
		k[i] = seed + byte(i)
	}
	return k
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = d[v>>4]
		out[i*2+1] = d[v&0x0F]
	}
	return string(out)
}

func buildSyntheticEncoding(ck internalcasc.CKey, ek internalcasc.EKey, contentSize uint32) []byte {
	const pageKB = 4
	const pageBytes = pageKB * 1024

	hdr := make([]byte, 22)
	binary.LittleEndian.PutUint16(hdr[0:2], internalcasc.MagicEncoding)
	hdr[2] = 1
	hdr[3] = 16
	hdr[4] = 16
	binary.BigEndian.PutUint16(hdr[5:7], pageKB)
	binary.BigEndian.PutUint16(hdr[7:9], pageKB)
	binary.BigEndian.PutUint32(hdr[9:13], 1)
	binary.BigEndian.PutUint32(hdr[13:17], 0)
	hdr[17] = 0
	binary.BigEndian.PutUint32(hdr[18:22], 0)

	cKeyPageIndex := make([]byte, 32)
	page := make([]byte, pageBytes)
	binary.LittleEndian.PutUint16(page[0:2], 1)
	binary.BigEndian.PutUint32(page[2:6], contentSize)
	copy(page[6:22], ck[:])
	copy(page[22:38], ek[:])

	out := append(hdr, cKeyPageIndex...)
	out = append(out, page...)
	return out
}

// fromInner is a test-only constructor: wraps an *internal storage.Storage
// in a public *Storage. Lives in *_test.go so it's not part of the API.
func fromInner(s *storage.Storage) *Storage { return &Storage{inner: s} }

// TestEndToEndOpenFile drives the full pipeline:
// indexes → archive pool → ENCODING (BLTE) → ROOT (BLTE, text format)
// → ReadByEKey → OpenFile.
func TestEndToEndOpenFile(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "Data", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}

	rootCK := mkCKey(0x55)
	rootEK := mkEKey(0xBB)
	encEK := mkEKey(0xCC)
	contentCK := mkCKey(0x77)
	contentEK := mkEKey(0xDD)

	// ENCODING entries: rootCK -> rootEK; contentCK -> contentEK.
	enc1 := buildSyntheticEncoding(rootCK, rootEK, 0x100)
	enc2 := buildSyntheticEncoding(contentCK, contentEK, 5)
	// Combine ENCODING into a single page-bigger blob: simpler to just pick
	// the second one with both entries. Build a bespoke page.
	encBytes := buildEncodingTwoEntries(rootCK, rootEK, contentCK, contentEK)
	_, _ = enc1, enc2

	// ROOT (text format).
	payload := []byte("HELLO")
	rootText := []byte("Hello.txt|" + hexOf(contentCK[:]) + "\n")

	encSpan := buildBLTESpan(t, encBytes)
	rootSpan := buildBLTESpan(t, rootText)
	contentSpan := buildBLTESpan(t, payload)

	// Lay all three spans into data.000 at known offsets.
	const encOff = 0x100
	rootOff := encOff + len(encSpan)
	contentOff := rootOff + len(rootSpan)
	body := make([]byte, contentOff+len(contentSpan))
	copy(body[encOff:], encSpan)
	copy(body[rootOff:], rootSpan)
	copy(body[contentOff:], contentSpan)
	if err := os.WriteFile(filepath.Join(dataDir, "data.000"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	idx := &index.IndexFile{Entries: []index.EKeyEntry{
		{EKey: encEK, ArchiveOffs: encOff, EncodedSize: uint32(len(encSpan))},
		{EKey: rootEK, ArchiveOffs: uint32(rootOff), EncodedSize: uint32(len(rootSpan))},
		{EKey: contentEK, ArchiveOffs: uint32(contentOff), EncodedSize: uint32(len(contentSpan))},
	}}

	// Construct the storage manually (bypass .build.info parsing).
	s := &storage.Storage{
		Path:         dir,
		Indexes:      []*index.IndexFile{idx},
		EncodingCKey: &buildcfg.CKeyEntry{EKey: encEK, HasEKey: true},
		RootCKey:     &buildcfg.CKeyEntry{CKey: rootCK},
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	pub := fromInner(s)
	defer pub.Close()

	f, err := pub.OpenFile("Hello.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}

	// Negative case.
	if _, err := pub.OpenFile("Nope.txt"); err == nil {
		t.Errorf("expected error for missing file")
	}

	// FindFiles iterator: with empty pattern lists everything; with a glob
	// it filters by name (case-insensitive).
	var seen []string
	if err := pub.FindFiles("", func(name string, info FileInfo) bool {
		seen = append(seen, name)
		return true
	}); err != nil {
		t.Fatalf("FindFiles: %v", err)
	}
	if len(seen) == 0 {
		t.Error("FindFiles yielded no entries")
	}

	matched := 0
	if err := pub.FindFiles("hello.*", func(name string, info FileInfo) bool {
		matched++
		if info.ContentSize == 0 {
			t.Errorf("ContentSize zero for %q", name)
		}
		return true
	}); err != nil {
		t.Fatalf("FindFiles glob: %v", err)
	}
	if matched != 1 {
		t.Errorf("glob matched %d, want 1", matched)
	}
}

// buildEncodingTwoEntries packs two CKey -> EKey rows into one CKey page.
func buildEncodingTwoEntries(ck1 internalcasc.CKey, ek1 internalcasc.EKey,
	ck2 internalcasc.CKey, ek2 internalcasc.EKey) []byte {
	const pageKB = 4
	const pageBytes = pageKB * 1024

	hdr := make([]byte, 22)
	binary.LittleEndian.PutUint16(hdr[0:2], internalcasc.MagicEncoding)
	hdr[2] = 1
	hdr[3] = 16
	hdr[4] = 16
	binary.BigEndian.PutUint16(hdr[5:7], pageKB)
	binary.BigEndian.PutUint16(hdr[7:9], pageKB)
	binary.BigEndian.PutUint32(hdr[9:13], 1)
	binary.BigEndian.PutUint32(hdr[13:17], 0)
	hdr[17] = 0
	binary.BigEndian.PutUint32(hdr[18:22], 0)

	cKeyPageIndex := make([]byte, 32)
	page := make([]byte, pageBytes)

	off := 0
	writeRow := func(ck internalcasc.CKey, ek internalcasc.EKey, sz uint32) {
		binary.LittleEndian.PutUint16(page[off:off+2], 1)
		binary.BigEndian.PutUint32(page[off+2:off+6], sz)
		copy(page[off+6:off+22], ck[:])
		copy(page[off+22:off+38], ek[:])
		off += 38
	}
	writeRow(ck1, ek1, 0x100)
	writeRow(ck2, ek2, 5)

	out := append(hdr, cKeyPageIndex...)
	out = append(out, page...)
	return out
}
