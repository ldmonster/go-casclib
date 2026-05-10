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
	"crypto/md5"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-casclib/internal/buildcfg"
	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/index"

	// Side-effect: register the text root probe so LoadRoot can detect it.
	_ "github.com/ldmonster/go-casclib/internal/root/text"
)

// buildBLTESpan builds a BLTE_ENCODED_HEADER (30 bytes of zeros) + minimal
// single-'N' BLTE for payload.
func buildBLTESpan(t *testing.T, payload []byte) []byte {
	t.Helper()
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

	const encHdr = 30
	out := make([]byte, encHdr+blte.Len())
	copy(out[encHdr:], blte.Bytes())
	return out
}

// makeEKey returns a 16-byte EKey where the first 9 bytes are the seed.
func makeEKey(seed byte) casc.EKey {
	var k casc.EKey
	for i := 0; i < 16; i++ {
		k[i] = seed + byte(i)
	}
	return k
}

func TestEKeyMapAndReadByEKey(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "Data", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello from data.000")
	span := buildBLTESpan(t, payload)
	const off = 0x40
	body := make([]byte, off+len(span))
	copy(body[off:], span)
	if err := os.WriteFile(filepath.Join(dataDir, "data.000"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	ekey := makeEKey(0xAA)
	idxFile := &index.IndexFile{
		Entries: []index.EKeyEntry{
			{
				EKey:         ekey,
				ArchiveIndex: 0,
				ArchiveOffs:  off,
				EncodedSize:  uint32(len(span)),
			},
		},
	}

	s := &Storage{Path: dir, Indexes: []*index.IndexFile{idxFile}}
	s.buildEKeyMap()

	if _, ok := s.FindByEKey(ekey); !ok {
		t.Fatal("EKey not found in map")
	}

	got, err := s.ReadByEKey(ekey)
	if err != nil {
		t.Fatalf("ReadByEKey: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}

	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestLoadEncodingAndRoot(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "Data", "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Build a synthetic ENCODING file with one entry: rootCKey -> rootEKey.
	var rootCKey casc.CKey
	for i := 0; i < 16; i++ {
		rootCKey[i] = 0x55 + byte(i)
	}
	rootEKey := makeEKey(0xBB)
	encBytes := buildSyntheticEncoding(t, rootCKey, rootEKey)

	// Build a synthetic ROOT file (text format: "name|md5\n").
	rootName := "Hello.txt"
	var contentCKey casc.CKey
	for i := 0; i < 16; i++ {
		contentCKey[i] = 0x77 + byte(i)
	}
	rootText := []byte(rootName + "|")
	rootText = append(rootText, []byte(hexOf(contentCKey[:]))...)
	rootText = append(rootText, '\n')

	// Encrypt ENCODING and ROOT into BLTE spans, write into data.000.
	encSpan := buildBLTESpan(t, encBytes)
	rootSpan := buildBLTESpan(t, rootText)

	const encOff = 0x100
	rootOff := encOff + len(encSpan)
	body := make([]byte, rootOff+len(rootSpan))
	copy(body[encOff:], encSpan)
	copy(body[rootOff:], rootSpan)
	if err := os.WriteFile(filepath.Join(dataDir, "data.000"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	encEKey := makeEKey(0xCC)
	idxFile := &index.IndexFile{Entries: []index.EKeyEntry{
		{EKey: encEKey, ArchiveOffs: encOff, EncodedSize: uint32(len(encSpan))},
		{EKey: rootEKey, ArchiveOffs: uint32(rootOff), EncodedSize: uint32(len(rootSpan))},
	}}

	s := &Storage{
		Path:         dir,
		Indexes:      []*index.IndexFile{idxFile},
		EncodingCKey: &buildcfg.CKeyEntry{EKey: encEKey, HasEKey: true},
		RootCKey:     &buildcfg.CKeyEntry{CKey: rootCKey},
	}
	s.buildEKeyMap()
	defer s.Close()

	if err := s.LoadEncoding(); err != nil {
		t.Fatalf("LoadEncoding: %v", err)
	}
	if s.Encoding == nil || s.Encoding.Find(rootCKey) == nil {
		t.Fatal("encoding did not contain rootCKey")
	}

	if err := s.LoadRoot(); err != nil {
		t.Fatalf("LoadRoot: %v", err)
	}
	if s.Root == nil {
		t.Fatal("root handler not set")
	}
	if e := s.Root.LookupByName(rootName); e == nil || e.CKey != contentCKey {
		t.Fatalf("root lookup = %+v", e)
	}
}

// buildSyntheticEncoding returns an ENCODING manifest with one CKey -> EKey
// entry.
func buildSyntheticEncoding(t *testing.T, ck casc.CKey, ek casc.EKey) []byte {
	t.Helper()
	const pageKB = 4
	const pageBytes = pageKB * 1024

	hdr := make([]byte, 22)
	binary.LittleEndian.PutUint16(hdr[0:2], casc.MagicEncoding)
	hdr[2] = 1
	hdr[3] = 16
	hdr[4] = 16
	binary.BigEndian.PutUint16(hdr[5:7], pageKB)
	binary.BigEndian.PutUint16(hdr[7:9], pageKB)
	binary.BigEndian.PutUint32(hdr[9:13], 1) // 1 CKey page
	binary.BigEndian.PutUint32(hdr[13:17], 0)
	hdr[17] = 0
	binary.BigEndian.PutUint32(hdr[18:22], 0) // ESpec block size = 0

	// Single CKey page index (32 bytes of zeros — we don't verify it).
	cKeyPageIndex := make([]byte, 32)

	// One entry: ekeyCount(2 LE) + contentSize(4 BE) + CKey(16) + EKey(16).
	page := make([]byte, pageBytes)
	binary.LittleEndian.PutUint16(page[0:2], 1)
	binary.BigEndian.PutUint32(page[2:6], 0x12345)
	copy(page[6:22], ck[:])
	copy(page[22:38], ek[:])

	out := make([]byte, 0)
	out = append(out, hdr...)
	out = append(out, cKeyPageIndex...)
	out = append(out, page...)
	return out
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0F]
	}
	return string(out)
}
