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

package overwatch

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

// Build a minimal plain-text v100 CMF and round-trip it.
func TestLoadCMF_PlainV100(t *testing.T) {
	build := uint32(40000) // <= 47161 -> v100
	dataCount := int32(2)
	entryCount := int32(1)
	// magic for non-encrypted: high byte = version, low 24 bits = 0x00666D63 ('cmf').
	// IsEncrypted requires (magic>>8)==0x636D66, which means "cmf" in the high 3 bytes.
	magic := uint32(0x00<<24) | 0x00666D63 // version=0, magic 'cmf' in low 3 bytes (big-endian view 'fmc'); plain.

	var buf bytes.Buffer
	w32 := func(v uint32) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	w32(build)
	w32(0) // unk04
	w32(0) // unk08
	w32(0) // unk10
	w32(0) // unk14
	w32(uint32(dataCount))
	w32(0) // unk18
	w32(uint32(entryCount))
	w32(magic)
	// APM entries (1 × 24 bytes, all zero)
	buf.Write(make([]byte, int(entryCount)*apmEntryV2Size))
	// Hash entries v100 (2 × 28 bytes)
	for i := 0; i < int(dataCount); i++ {
		var e [cmfHashEntry100Size]byte
		binary.LittleEndian.PutUint64(e[0:8], uint64(i+1))
		binary.LittleEndian.PutUint32(e[8:12], uint32(100*(i+1)))
		for j := 0; j < 16; j++ {
			e[12+j] = byte(0xA0 + i)
		}
		buf.Write(e[:])
	}

	cmf, err := LoadCMF(buf.Bytes(), "test.cmf", nil)
	if err != nil {
		t.Fatalf("LoadCMF: %v", err)
	}
	if cmf.Header.BuildVersion != build {
		t.Errorf("build = %d, want %d", cmf.Header.BuildVersion, build)
	}
	if cmf.Header.IsEncrypted() {
		t.Errorf("expected plain, got encrypted")
	}
	if len(cmf.Assets) != int(dataCount) {
		t.Fatalf("assets = %d, want %d", len(cmf.Assets), dataCount)
	}
	if cmf.Assets[1].Size != 200 {
		t.Errorf("asset[1].Size = %d, want 200", cmf.Assets[1].Size)
	}
	for j := 0; j < 16; j++ {
		if cmf.Assets[0].CKey[j] != 0xA0 {
			t.Errorf("asset[0].CKey[%d] = %x, want 0xA0", j, cmf.Assets[0].CKey[j])
		}
	}
}

// Encrypt a synthetic CMF body with a known key, then decrypt via LoadCMF.
func TestLoadCMF_Encrypted(t *testing.T) {
	build := uint32(60000) // >122 PTR, <=148 PTR → v122 header
	dataCount := int32(1)
	entryCount := int32(0)
	// IsEncrypted: (magic>>8) == 0x636D66 ('cmf')
	magic := uint32(0x636D6600) | 0x42 // version 0x42 in low byte

	plainName := "encrypted.cmf"
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	// IV is derived from SHA1(plainName) + provider; use first 16 bytes of SHA1.
	digest := sha1.Sum([]byte(plainName))
	var iv [16]byte
	copy(iv[:], digest[:16])

	// Build header (v122 = 40 bytes)
	var hdr bytes.Buffer
	w32 := func(v uint32) { _ = binary.Write(&hdr, binary.LittleEndian, v) }
	w32(build)
	w32(0)
	w32(0)
	w32(0)
	w32(0)
	w32(0)
	w32(uint32(dataCount))
	w32(0)
	w32(uint32(entryCount))
	w32(magic)

	// Build plaintext body: APM(0 × 24) + hash list (1 × 28 bytes for build < 57230)
	var body [cmfHashEntry100Size]byte
	binary.LittleEndian.PutUint64(body[0:8], 0xDEADBEEF)
	binary.LittleEndian.PutUint32(body[8:12], 4242)
	for j := 0; j < 16; j++ {
		body[12+j] = 0x55
	}
	plain := body[:]
	// Pad up to multiple of 16 (already 28 → pad to 32).
	pad := (-len(plain)) & 15
	plain = append(plain, make([]byte, pad)...)

	// AES-256-CBC encrypt
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(enc, plain)

	// Assemble file
	full := append(hdr.Bytes(), enc...)

	// Provider: returns the same key/IV we used.
	reg := NewKeyRegistry()
	reg.Register(build, func(h CMFHeader, d [20]byte) ([32]byte, [16]byte, error) {
		return key, iv, nil
	})

	cmf, err := LoadCMF(full, plainName, reg)
	if err != nil {
		t.Fatalf("LoadCMF: %v", err)
	}
	if !cmf.Header.IsEncrypted() {
		t.Error("expected IsEncrypted=true")
	}
	if cmf.Assets[0].Size != 4242 {
		t.Errorf("size = %d, want 4242", cmf.Assets[0].Size)
	}
	if cmf.Assets[0].GUID != [8]byte{0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0} {
		t.Errorf("guid = %x", cmf.Assets[0].GUID)
	}
}

func TestLoadCMF_EncryptedNoProvider(t *testing.T) {
	build := uint32(60000)
	magic := uint32(0x636D6600) | 0x42
	var hdr bytes.Buffer
	w32 := func(v uint32) { _ = binary.Write(&hdr, binary.LittleEndian, v) }
	w32(build)
	for i := 0; i < 8; i++ {
		w32(0)
	}
	w32(magic)
	hdr.Write(make([]byte, 32)) // dummy body
	if _, err := LoadCMF(hdr.Bytes(), "x.cmf", NewKeyRegistry()); err == nil {
		t.Fatal("expected ErrEncrypted")
	}
}

func TestLoadAPM(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint64(98765))
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3)) // pkg
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2)) // entries
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x666D6300))
	for i := 0; i < 2; i++ {
		_ = binary.Write(&buf, binary.LittleEndian, uint32(uint32(i)+10)) // index
		_ = binary.Write(&buf, binary.LittleEndian, uint64(0xAA))
		_ = binary.Write(&buf, binary.LittleEndian, uint64(0xBB))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	}
	apm, err := LoadAPM(buf.Bytes())
	if err != nil {
		t.Fatalf("LoadAPM: %v", err)
	}
	if apm.Header.BuildNumber != 98765 {
		t.Errorf("build = %d", apm.Header.BuildNumber)
	}
	if len(apm.Entries) != 2 {
		t.Fatalf("entries = %d", len(apm.Entries))
	}
	if apm.Entries[1].Index != 11 || apm.Entries[1].HashA != 0xAA {
		t.Errorf("entry[1] = %+v", apm.Entries[1])
	}
}

func TestAssetFileName(t *testing.T) {
	a := CMFAsset{}
	binary.LittleEndian.PutUint64(a.GUID[:], 0xDEADBEEF12345678)
	got := AssetFileName("test.cmf", a)
	want := "ContentManifestFiles/test.cmf/DEADBEEF12345678"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
