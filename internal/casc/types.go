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

// Package casc holds shared on-disk constants, fixed-size keys, and core
// in-memory types used throughout the library. It corresponds to a mix of
// CascStructs.h, CascPort.h, and parts of CascCommon.h in the upstream C++.
package casc

// Hash sizes.
const (
	MD5HashSize    = 0x10
	MD5StringSize  = 0x20
	SHA1HashSize   = 0x14
	SHA1StringSize = 0x28
)

// Storage / index constants.
const (
	IndexCount   = 0x10 // Number of index files
	CKeySize     = 0x10 // Size of the content key
	EKeySize     = 0x09 // Size of the (trimmed) encoded key
	MaxDataFiles = 0x1000

	IndexPageSize = 0x200
	KeyLength     = 0x10
)

// Invalid sentinels.
const (
	InvalidIndex  = uint32(0xFFFFFFFF)
	InvalidSize   = uint32(0xFFFFFFFF)
	InvalidPos    = uint32(0xFFFFFFFF)
	InvalidID     = uint32(0xFFFFFFFF)
	InvalidOffs64 = uint64(0xFFFFFFFFFFFFFFFF)
	InvalidSize64 = uint64(0xFFFFFFFFFFFFFFFF)
)

// File-magic numbers (little-endian when read with binary.LittleEndian).
const (
	MagicEncoding = 0x4E45 // 'EN'
	MagicDownload = 0x4C44 // 'DL'
	MagicInstall  = 0x4E49 // 'IN'

	BLTESignature = 0x45544C42 // 'BLTE'
)

// Storage feature bits (CASC_FEATURE_*).
const (
	FeatureFileNames           uint32 = 0x00000001
	FeatureRootCKey            uint32 = 0x00000002
	FeatureTags                uint32 = 0x00000004
	FeatureFNameHashes         uint32 = 0x00000008
	FeatureFNameHashesOptional uint32 = 0x00000010
	FeatureFileDataIDs         uint32 = 0x00000020
	FeatureLocaleFlags         uint32 = 0x00000040
	FeatureContentFlags        uint32 = 0x00000080
	FeatureDataArchives        uint32 = 0x00000100
	FeatureDataFiles           uint32 = 0x00000200
	FeatureOnline              uint32 = 0x00000400
	FeatureForceDownload       uint32 = 0x00001000
	FeatureAllowDownload       uint32 = 0x00002000
)

// Locale flags.
const (
	LocaleAll    uint32 = 0xFFFFFFFF
	LocaleAllWoW uint32 = 0x0001F3F6
	LocaleNone   uint32 = 0x00000000
	LocaleEnUS   uint32 = 0x00000002
	LocaleKoKR   uint32 = 0x00000004
	LocaleFrFR   uint32 = 0x00000010
	LocaleDeDE   uint32 = 0x00000020
	LocaleZhCN   uint32 = 0x00000040
	LocaleEsES   uint32 = 0x00000080
	LocaleZhTW   uint32 = 0x00000100
	LocaleEnGB   uint32 = 0x00000200
	LocaleEnCN   uint32 = 0x00000400
	LocaleEnTW   uint32 = 0x00000800
	LocaleEsMX   uint32 = 0x00001000
	LocaleRuRU   uint32 = 0x00002000
	LocalePtBR   uint32 = 0x00004000
	LocaleItIT   uint32 = 0x00008000
	LocalePtPT   uint32 = 0x00010000
)

// CKey is a 16-byte content key (MD5 of file content).
type CKey [MD5HashSize]byte

// EKey is a 16-byte encoded key (MD5 of file header / first frame).
// Note: in index files, EKeys are often stored trimmed to 9 bytes.
type EKey [MD5HashSize]byte

// CKeyEntry is the unified in-memory entry for one storage file. It mirrors
// PCASC_CKEY_ENTRY in the C++ implementation.
type CKeyEntry struct {
	CKey         CKey
	EKey         EKey
	StorageOffs  uint64 // byte offset within combined data files (or 0)
	TagBitMask   uint64 // tag bitmask (DOWNLOAD manifest)
	FileNameHash uint64 // jenkins hashlittle2 of the full filename, if known
	ContentSize  uint64
	EncodedSize  uint64
	ArchiveIndex uint32 // data file index (0..0xFFF)
	ArchiveOffs  uint32 // offset within data file
	FileDataID   uint32 // FileDataID (WoW), or InvalidID
	LocaleFlags  uint32
	ContentFlags uint32
	SpanCount    uint16
	Flags        uint16
}

// CKey/EKey entry flags (CASC_CE_*).
const (
	CEFlagFileIsLocal uint16 = 0x0001
	CEFlagFilePatch   uint16 = 0x0002
	CEFlagHasCKey     uint16 = 0x0004
	CEFlagHasEKey     uint16 = 0x0008
	CEFlagFileVerify  uint16 = 0x0010
	CEFlagSameCKey    uint16 = 0x0020
)
