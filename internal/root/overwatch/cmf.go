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

// Overwatch Content Manifest File (CMF) and APM parsers.
//
// CMF files map asset GUIDs to CKeys. The header is one of three
// versioned variants (v100/v122/v148) selected by build number, and the
// payload may be AES-CBC-256 encrypted. Keys are derived per-build via
// arithmetic on the header fields and the SHA-1 of the CMF's plain
// filename — Blizzard ships a different key/IV recipe per game build,
// so a runtime KeyProvider extension point is required.
//
// This file ports:
//   * overwatch.h structs (CASC_CMF_HEADER, V100/V122/V148, hash entries)
//   * cmf.cpp's LoadContentManifestFile flow
//   * apm.cpp's APM parsing
//
// The 13K-LOC table of generated per-build key/IV recipes
// (CascLib/src/overwatch/cmf-key.cpp) is **not** ported. Callers who
// need to decrypt a real Overwatch build register their own KeyProvider.
//
// C++ reference: CascLib/src/overwatch/{cmf.cpp,apm.cpp,overwatch.h}.

package overwatch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// Build version cutoffs (mirrors CascLib).
const (
	overwatchVersion122PTR = 47161
	overwatchVersion148PTR = 68309
	cmfEncryptedMagicBE    = 0x636D66 // 'cmf' shifted right by 8

	cmfHashEntry100Size = 8 + 4 + 16
	cmfHashEntry135Size = 8 + 4 + 1 + 16

	apmEntryV2Size = 24
)

// CMFHeader is the in-memory canonical CMF header (matches v148 layout).
type CMFHeader struct {
	BuildVersion          uint32
	Unk04                 uint32
	Unk08                 uint32
	Unk0C                 uint32
	Unk10                 uint32
	Unk14                 uint32
	Unk18                 uint32
	DataPatchRecordCount  int32
	DataCount             int32
	EntryPatchRecordCount int32
	EntryCount            int32
	Magic                 uint32
}

// IsEncrypted reports whether the payload is AES-encrypted.
func (h *CMFHeader) IsEncrypted() bool { return (h.Magic >> 8) == cmfEncryptedMagicBE }

// Version returns the on-disk version byte.
func (h *CMFHeader) Version() byte {
	if h.IsEncrypted() {
		return byte(h.Magic & 0xFF)
	}

	return byte((h.Magic >> 24) & 0xFF)
}

// readHeader picks the right struct variant by build version.
// Returns (header, bytesConsumed, error).
func readHeader(buf []byte) (CMFHeader, int, error) {
	if len(buf) < 4 {
		return CMFHeader{}, 0, fmt.Errorf("overwatch: cmf header truncated")
	}

	build := binary.LittleEndian.Uint32(buf[:4])
	switch {
	case build > overwatchVersion148PTR:
		// v148: 12 dwords = 48 bytes.
		const sz = 48
		if len(buf) < sz {
			return CMFHeader{}, 0, fmt.Errorf("overwatch: cmf v148 header truncated")
		}

		h := CMFHeader{
			BuildVersion:          binary.LittleEndian.Uint32(buf[0:4]),
			Unk04:                 binary.LittleEndian.Uint32(buf[4:8]),
			Unk08:                 binary.LittleEndian.Uint32(buf[8:12]),
			Unk0C:                 binary.LittleEndian.Uint32(buf[12:16]),
			Unk10:                 binary.LittleEndian.Uint32(buf[16:20]),
			Unk14:                 binary.LittleEndian.Uint32(buf[20:24]),
			Unk18:                 binary.LittleEndian.Uint32(buf[24:28]),
			DataPatchRecordCount:  int32(binary.LittleEndian.Uint32(buf[28:32])),
			DataCount:             int32(binary.LittleEndian.Uint32(buf[32:36])),
			EntryPatchRecordCount: int32(binary.LittleEndian.Uint32(buf[36:40])),
			EntryCount:            int32(binary.LittleEndian.Uint32(buf[40:44])),
			Magic:                 binary.LittleEndian.Uint32(buf[44:48]),
		}

		return h, sz, nil
	case build > overwatchVersion122PTR:
		// v122: 10 dwords = 40 bytes.
		const sz = 40
		if len(buf) < sz {
			return CMFHeader{}, 0, fmt.Errorf("overwatch: cmf v122 header truncated")
		}

		h := CMFHeader{
			BuildVersion: binary.LittleEndian.Uint32(buf[0:4]),
			Unk04:        binary.LittleEndian.Uint32(buf[4:8]),
			Unk08:        binary.LittleEndian.Uint32(buf[8:12]),
			Unk0C:        binary.LittleEndian.Uint32(buf[12:16]),
			Unk10:        binary.LittleEndian.Uint32(buf[16:20]),
			Unk14:        binary.LittleEndian.Uint32(buf[20:24]),
			DataCount:    int32(binary.LittleEndian.Uint32(buf[24:28])),
			Unk18:        binary.LittleEndian.Uint32(buf[28:32]),
			EntryCount:   int32(binary.LittleEndian.Uint32(buf[32:36])),
			Magic:        binary.LittleEndian.Uint32(buf[36:40]),
		}

		return h, sz, nil
	default:
		// v100: 9 dwords = 36 bytes.
		const sz = 36
		if len(buf) < sz {
			return CMFHeader{}, 0, fmt.Errorf("overwatch: cmf v100 header truncated")
		}

		h := CMFHeader{
			BuildVersion: binary.LittleEndian.Uint32(buf[0:4]),
			Unk04:        binary.LittleEndian.Uint32(buf[4:8]),
			Unk08:        binary.LittleEndian.Uint32(buf[8:12]),
			Unk10:        binary.LittleEndian.Uint32(buf[12:16]),
			Unk14:        binary.LittleEndian.Uint32(buf[16:20]),
			DataCount:    int32(binary.LittleEndian.Uint32(buf[20:24])),
			Unk18:        binary.LittleEndian.Uint32(buf[24:28]),
			EntryCount:   int32(binary.LittleEndian.Uint32(buf[28:32])),
			Magic:        binary.LittleEndian.Uint32(buf[32:36]),
		}

		return h, sz, nil
	}
}

// KeyProvider derives the AES-256 key + IV for a given build/header.
// nameDigest is the SHA-1 of the CMF's plain filename.
type KeyProvider func(hdr CMFHeader, nameDigest [20]byte) (key [32]byte, iv [16]byte, err error)

// KeyRegistry is a lookup keyed by build number.
type KeyRegistry struct {
	providers map[uint32]KeyProvider
}

// NewKeyRegistry returns an empty registry.
func NewKeyRegistry() *KeyRegistry { return &KeyRegistry{providers: map[uint32]KeyProvider{}} }

// Register adds a provider for the given build.
func (r *KeyRegistry) Register(build uint32, p KeyProvider) {
	r.providers[build] = p
}

// Find returns the provider for an exact build match (Blizzard's own
// table uses exact-match too).
func (r *KeyRegistry) Find(build uint32) KeyProvider {
	if r == nil || r.providers == nil {
		return nil
	}

	return r.providers[build]
}

// ErrEncrypted is returned when a CMF is encrypted but no KeyProvider is
// registered for its build.
var ErrEncrypted = errors.New("overwatch: cmf is encrypted; no key provider registered")

// CMFAsset is one row of the CMF hash list.
type CMFAsset struct {
	GUID [8]byte
	Size uint32
	CKey [16]byte
}

// CMF is the parsed Content Manifest File.
type CMF struct {
	Header CMFHeader
	Assets []CMFAsset
}

// LoadCMF parses a CMF blob. plainName is the filename portion (no
// directory) used for SHA-1 keying when the payload is encrypted.
// keys may be nil if the CMF is known to be plain.
func LoadCMF(data []byte, plainName string, keys *KeyRegistry) (*CMF, error) {
	hdr, hdrSize, err := readHeader(data)
	if err != nil {
		return nil, err
	}

	body := append([]byte(nil), data[hdrSize:]...) // copy: we may decrypt in place

	if hdr.IsEncrypted() {
		prov := keys.Find(hdr.BuildVersion)
		if prov == nil {
			return nil, fmt.Errorf("%w (build %d)", ErrEncrypted, hdr.BuildVersion)
		}

		digest := sha1.Sum([]byte(plainName))

		key, iv, err := prov(hdr, digest)
		if err != nil {
			return nil, fmt.Errorf("overwatch: key provider failed: %w", err)
		}

		if err := aesCBCDecryptInPlace(body, key[:], iv[:]); err != nil {
			return nil, err
		}
	}

	// Skip APM entries (per cmf.cpp: they are not used for asset extraction).
	if hdr.EntryCount < 0 {
		return nil, fmt.Errorf("overwatch: negative entry count %d", hdr.EntryCount)
	}

	skip := int(hdr.EntryCount) * apmEntryV2Size
	if skip < 0 || skip > len(body) {
		return nil, fmt.Errorf("overwatch: APM entries past EOF")
	}

	body = body[skip:]

	// Parse the hash list.
	if hdr.DataCount < 0 {
		return nil, fmt.Errorf("overwatch: negative data count %d", hdr.DataCount)
	}

	out := &CMF{Header: hdr, Assets: make([]CMFAsset, hdr.DataCount)}
	if hdr.BuildVersion >= 57230 {
		need := int(hdr.DataCount) * cmfHashEntry135Size
		if need > len(body) {
			return nil, fmt.Errorf("overwatch: hash list (v135) past EOF")
		}

		for i := 0; i < int(hdr.DataCount); i++ {
			o := i * cmfHashEntry135Size
			copy(out.Assets[i].GUID[:], body[o:o+8])
			out.Assets[i].Size = binary.LittleEndian.Uint32(body[o+8 : o+12])
			// skip field_C at o+12
			copy(out.Assets[i].CKey[:], body[o+13:o+29])
		}
	} else {
		need := int(hdr.DataCount) * cmfHashEntry100Size
		if need > len(body) {
			return nil, fmt.Errorf("overwatch: hash list (v100) past EOF")
		}

		for i := 0; i < int(hdr.DataCount); i++ {
			o := i * cmfHashEntry100Size
			copy(out.Assets[i].GUID[:], body[o:o+8])
			out.Assets[i].Size = binary.LittleEndian.Uint32(body[o+8 : o+12])
			copy(out.Assets[i].CKey[:], body[o+12:o+28])
		}
	}

	return out, nil
}

// aesCBCDecryptInPlace decrypts buf with AES-256-CBC. buf must be a
// multiple of the AES block size.
func aesCBCDecryptInPlace(buf, key, iv []byte) error {
	if len(buf)%aes.BlockSize != 0 {
		return fmt.Errorf("overwatch: cmf body is not block-aligned (%d bytes)", len(buf))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("overwatch: aes key: %w", err)
	}

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(buf, buf)

	return nil
}

// -----------------------------------------------------------------------
// APM (Application Package Manifest)

// APMHeader represents a v2 APM header in canonical form.
type APMHeader struct {
	BuildNumber  uint64
	PackageCount uint32
	EntryCount   uint32
	Magic        uint32
}

// APMEntry is one v2 APM entry (24 bytes).
type APMEntry struct {
	Index   uint32
	HashA   uint64
	HashB   uint64
	Padding uint32
}

// APM is the parsed Application Package Manifest.
type APM struct {
	Header  APMHeader
	Entries []APMEntry
}

// LoadAPM parses an APM v2 blob. (V1 builds <22 are not currently shipped
// by Blizzard; CascLib likewise treats v2 as canonical.)
func LoadAPM(data []byte) (*APM, error) {
	// V2 with pack(4): 8 + 8 + 4 + 4 + 4 + 4 + 4 = 36 bytes.
	const v2HeaderSize = 36
	if len(data) < v2HeaderSize {
		return nil, fmt.Errorf("overwatch: apm header truncated")
	}

	h := APMHeader{
		BuildNumber:  binary.LittleEndian.Uint64(data[0:8]),
		PackageCount: binary.LittleEndian.Uint32(data[20:24]),
		EntryCount:   binary.LittleEndian.Uint32(data[28:32]),
		Magic:        binary.LittleEndian.Uint32(data[32:36]),
	}

	body := data[v2HeaderSize:]
	if int(h.EntryCount)*apmEntryV2Size > len(body) {
		return nil, fmt.Errorf("overwatch: apm entries past EOF")
	}

	out := &APM{Header: h, Entries: make([]APMEntry, h.EntryCount)}
	for i := 0; i < int(h.EntryCount); i++ {
		o := i * apmEntryV2Size
		out.Entries[i].Index = binary.LittleEndian.Uint32(body[o : o+4])
		out.Entries[i].HashA = binary.LittleEndian.Uint64(body[o+4 : o+12])
		out.Entries[i].HashB = binary.LittleEndian.Uint64(body[o+12 : o+20])
		out.Entries[i].Padding = binary.LittleEndian.Uint32(body[o+20 : o+24])
	}

	return out, nil
}

// -----------------------------------------------------------------------
// AssetFileName builds the asset file name template
// "ContentManifestFiles/<plainCmfName>/<assetID>" — used to route asset
// CKeys into the file tree.
func AssetFileName(plainCmfName string, asset CMFAsset) string {
	// Asset ID = decimal of the 64-bit GUID (matches CascLib).
	id := binary.LittleEndian.Uint64(asset.GUID[:])
	return fmt.Sprintf("ContentManifestFiles/%s/%016X", plainCmfName, id)
}
