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

package index

import (
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/hashes"
)

// Header is the parsed, version-agnostic representation of an index header.
type Header struct {
	IndexVersion        uint16
	BucketIndex         byte
	StorageOffsetLength byte // bytes
	EncodedSizeLength   byte
	EKeyLength          byte // typically 0x09 in local indexes
	FileOffsetBits      byte
	SegmentSize         uint64
	HeaderLength        int // bytes from start of file
	HeaderPadding       int // bytes after header, before entries
	EntryLength         int
	EKeyCount           uint32 // V1 only; 0 for V2 (counted via entries)
}

// EKeyEntry is the trimmed-EKey entry stored in index files.
type EKeyEntry struct {
	EKey         casc.EKey // first EKeyLength bytes are valid
	ArchiveIndex uint32    // data file index
	ArchiveOffs  uint32    // offset within data file
	EncodedSize  uint32
}

// IndexFile is the result of parsing a single .idx file.
type IndexFile struct {
	Header  Header
	Entries []EKeyEntry
}

// fileIndexHeaderV1Size is sizeof(FILE_INDEX_HEADER_V1) per CascStructs.h:
// 2+1+1+4 + 8+8 + 4 + 4+4+4+4+4 = 48.
const fileIndexHeaderV1Size = 48

// fileIndexHeaderV2Size is sizeof(FILE_INDEX_HEADER_V2).
const fileIndexHeaderV2Size = 16

// fileIndexGuardedBlockSize is sizeof(FILE_INDEX_GUARDED_BLOCK).
const fileIndexGuardedBlockSize = 8

// fileIndexPageSize is the V2 page size (per CascIndexFiles.cpp).
const fileIndexPageSize = 0x1000

// Parse autodetects the index file version (V1 or V2) and returns a parsed
// representation. bucketIndex is the index file number (0..0x0F); the
// header contains a redundant copy that must match.
func Parse(data []byte, bucketIndex byte) (*IndexFile, error) {
	// Try V2 first (wrapped in a guarded block).
	if hdr, err := parseHeaderV2(data, bucketIndex); err == nil {
		entries, err := loadEntriesV2(data, hdr)
		if err != nil {
			return nil, err
		}

		return &IndexFile{Header: *hdr, Entries: entries}, nil
	}

	// Fall back to V1.
	hdr, err := parseHeaderV1(data, bucketIndex)
	if err != nil {
		return nil, err
	}

	entries, err := loadEntriesV1(data, hdr)
	if err != nil {
		return nil, err
	}

	return &IndexFile{Header: *hdr, Entries: entries}, nil
}

// parseHeaderV1 captures and validates a V1 (IndexVersion=5) header.
func parseHeaderV1(data []byte, bucketIndex byte) (*Header, error) {
	if len(data) < fileIndexHeaderV1Size {
		return nil, casc.ErrBadFormat
	}

	h := data[:fileIndexHeaderV1Size]

	indexVersion := binary.LittleEndian.Uint16(h[0:2])
	if indexVersion != 0x05 {
		return nil, casc.ErrBadFormat
	}

	if h[2] != bucketIndex {
		return nil, casc.ErrBadFormat
	}

	field8 := binary.LittleEndian.Uint64(h[8:16])
	if field8 == 0 {
		return nil, casc.ErrBadFormat
	}

	segmentSize := binary.LittleEndian.Uint64(h[16:24])

	encSizeLen := h[24]
	storeOffsLen := h[25]
	ekeyLen := h[26]
	fileOffsBits := h[27]

	if encSizeLen != 4 || storeOffsLen != 5 || ekeyLen != 9 {
		return nil, casc.ErrNotSupported
	}

	ekeyCount1 := binary.LittleEndian.Uint32(h[28:32])
	ekeyCount2 := binary.LittleEndian.Uint32(h[32:36])

	const v1FullSize = fileIndexHeaderV1Size
	if len(data) < v1FullSize {
		return nil, casc.ErrBadFormat
	}

	keysHash1 := binary.LittleEndian.Uint32(data[36:40])
	keysHash2 := binary.LittleEndian.Uint32(data[40:44])
	headerHash := binary.LittleEndian.Uint32(data[44:48])

	// Verify header hash with HeaderHash field zeroed.
	hdrCopy := make([]byte, v1FullSize)
	copy(hdrCopy, data[:v1FullSize])
	binary.LittleEndian.PutUint32(hdrCopy[44:48], 0)

	if hashes.HashLittle(hdrCopy, 0) != headerHash {
		return nil, casc.ErrBadFormat
	}

	hdr := &Header{
		IndexVersion:        indexVersion,
		BucketIndex:         h[2],
		StorageOffsetLength: storeOffsLen,
		EncodedSizeLength:   encSizeLen,
		EKeyLength:          ekeyLen,
		FileOffsetBits:      fileOffsBits,
		SegmentSize:         segmentSize,
		HeaderLength:        v1FullSize,
		HeaderPadding:       0,
		EntryLength:         int(ekeyLen) + int(storeOffsLen) + int(encSizeLen),
		EKeyCount:           ekeyCount1 + ekeyCount2,
	}

	// Verify the two key blocks.
	off := v1FullSize

	block1 := int(ekeyCount1) * hdr.EntryLength
	if off+block1 > len(data) {
		return nil, casc.ErrFileCorrupt
	}

	if hashes.HashLittle(data[off:off+block1], 0) != keysHash1 {
		return nil, casc.ErrFileCorrupt
	}

	off += block1

	block2 := int(ekeyCount2) * hdr.EntryLength
	if off+block2 > len(data) {
		return nil, casc.ErrFileCorrupt
	}

	if hashes.HashLittle(data[off:off+block2], 0) != keysHash2 {
		return nil, casc.ErrFileCorrupt
	}

	return hdr, nil
}

// parseHeaderV2 captures and validates a V2 (IndexVersion=7) header.
func parseHeaderV2(data []byte, bucketIndex byte) (*Header, error) {
	hdr, err := captureGuardedBlock1(data)
	if err != nil {
		return nil, err
	}

	if len(hdr) < fileIndexHeaderV2Size {
		return nil, casc.ErrBadFormat
	}

	indexVersion := binary.LittleEndian.Uint16(hdr[0:2])
	if indexVersion != 0x07 || hdr[2] != bucketIndex || hdr[3] != 0 {
		return nil, casc.ErrBadFormat
	}

	encSizeLen := hdr[4]
	storeOffsLen := hdr[5]
	ekeyLen := hdr[6]
	fileOffsBits := hdr[7]

	if encSizeLen != 4 || storeOffsLen != 5 || ekeyLen != 9 {
		return nil, casc.ErrBadFormat
	}

	segSize := binary.LittleEndian.Uint64(hdr[8:16])

	return &Header{
		IndexVersion:        indexVersion,
		BucketIndex:         hdr[2],
		StorageOffsetLength: storeOffsLen,
		EncodedSizeLength:   encSizeLen,
		EKeyLength:          ekeyLen,
		FileOffsetBits:      fileOffsBits,
		SegmentSize:         segSize,
		HeaderLength:        fileIndexGuardedBlockSize + fileIndexHeaderV2Size,
		HeaderPadding:       8,
		EntryLength:         int(ekeyLen) + int(storeOffsLen) + int(encSizeLen),
	}, nil
}

// captureGuardedBlock1 verifies a guarded-block wrapper (BlockSize, BlockHash)
// using continuous-buffer hashlittle, and returns the inner payload.
func captureGuardedBlock1(data []byte) ([]byte, error) {
	if len(data) < fileIndexGuardedBlockSize {
		return nil, casc.ErrFileCorrupt
	}

	blockSize := binary.LittleEndian.Uint32(data[0:4])
	blockHash := binary.LittleEndian.Uint32(data[4:8])

	end := fileIndexGuardedBlockSize + int(blockSize)
	if end > len(data) {
		return nil, casc.ErrFileCorrupt
	}

	if hashes.HashLittle(data[fileIndexGuardedBlockSize:end], 0) != blockHash {
		return nil, casc.ErrFileCorrupt
	}

	return data[fileIndexGuardedBlockSize:end], nil
}

// captureGuardedBlock2 verifies an entry-by-entry hashed block with two
// possible hashing methods: Blizzard's hashlittle2 and Blizzget's hashlittle.
// Returns the inner payload and its size.
func captureGuardedBlock2(data []byte, entryLen int) ([]byte, uint32, error) {
	if len(data) < fileIndexGuardedBlockSize {
		return nil, 0, casc.ErrFileCorrupt
	}

	blockSize := binary.LittleEndian.Uint32(data[0:4])
	blockHash := binary.LittleEndian.Uint32(data[4:8])

	if blockSize == 0 {
		return nil, 0, casc.ErrFileCorrupt
	}

	end := fileIndexGuardedBlockSize + int(blockSize)
	if end > len(data) {
		return nil, 0, casc.ErrFileCorrupt
	}

	payload := data[fileIndexGuardedBlockSize:end]
	count := int(blockSize) / entryLen

	// Method 1: hashlittle2 over each entry, accumulating.
	var hashHigh, hashLow uint32

	for i := 0; i < count; i++ {
		entry := payload[i*entryLen : (i+1)*entryLen]
		hashHigh, hashLow = hashes.HashLittle2(entry, hashHigh, hashLow)
	}

	if hashHigh == blockHash {
		return payload, blockSize, nil
	}

	// Method 2: hashlittle, accumulating initval per entry (Blizzget tool).
	var blizzGet uint32

	for i := 0; i < count; i++ {
		entry := payload[i*entryLen : (i+1)*entryLen]
		blizzGet = hashes.HashLittle(entry, blizzGet)
	}

	if blizzGet == blockHash {
		return payload, blockSize, nil
	}

	return nil, 0, casc.ErrFileCorrupt
}

// captureGuardedBlock3 verifies a per-entry 32-bit-hash wrapper. Used in
// V2 page-style EKey storage. The hash covers the entry plus one byte and is
// OR'd with 0x80000000.
func captureGuardedBlock3(data []byte, entryLen int) ([]byte, error) {
	if len(data) < 4+entryLen+1 {
		return nil, casc.ErrFileCorrupt
	}

	entryHash := binary.LittleEndian.Uint32(data[0:4])
	if entryHash == 0 {
		return nil, casc.ErrFileCorrupt
	}

	got := hashes.HashLittle(data[4:4+entryLen+1], 0) | 0x80000000
	if got != entryHash {
		return nil, casc.ErrFileCorrupt
	}

	return data[4 : 4+entryLen], nil
}

func loadEntriesV1(data []byte, h *Header) ([]EKeyEntry, error) {
	off := h.HeaderLength + h.HeaderPadding
	if off+int(h.EKeyCount)*h.EntryLength > len(data) {
		return nil, casc.ErrFileCorrupt
	}

	out := make([]EKeyEntry, 0, h.EKeyCount)
	for i := uint32(0); i < h.EKeyCount; i++ {
		e := decodeEntry(data[off:off+h.EntryLength], h)
		out = append(out, e)
		off += h.EntryLength
	}

	return out, nil
}

func loadEntriesV2(data []byte, h *Header) ([]EKeyEntry, error) {
	off := h.HeaderLength + h.HeaderPadding
	// First, try a single guarded block 2.
	if off < len(data) {
		if payload, _, err := captureGuardedBlock2(data[off:], h.EntryLength); err == nil {
			count := len(payload) / h.EntryLength

			out := make([]EKeyEntry, 0, count)
			for i := 0; i < count; i++ {
				out = append(out, decodeEntry(payload[i*h.EntryLength:], h))
			}

			return out, nil
		}
	}

	// Page-style storage: pages of 0x1000 bytes starting at offset 0x1000.
	// Each entry is preceded by a 32-bit hash and aligned to 4 bytes.
	if len(data) < 0x1000+0x7800 {
		return nil, casc.ErrFileCorrupt
	}

	alignedEntry := (h.EntryLength + 3) &^ 3
	out := make([]EKeyEntry, 0, 1024)

	for pageStart := 0x1000; pageStart < len(data); pageStart += fileIndexPageSize {
		pageEnd := pageStart + fileIndexPageSize
		if pageEnd > len(data) {
			pageEnd = len(data)
		}

		p := pageStart
		for p+4+h.EntryLength <= pageEnd {
			entry, err := captureGuardedBlock3(data[p:pageEnd], h.EntryLength)
			if err != nil {
				break
			}

			out = append(out, decodeEntry(entry, h))
			// Move to the next entry: 4-byte hash + entry, aligned to 4.
			p += 4 + alignedEntry
		}
	}

	return out, nil
}

// decodeEntry decodes one variable-length EKey entry. Lengths come from h.
func decodeEntry(b []byte, h *Header) EKeyEntry {
	var e EKeyEntry
	copy(e.EKey[:], b[:h.EKeyLength])

	// StorageOffset: big-endian, h.StorageOffsetLength bytes (typically 5).
	// Top FileOffsetBits low bits = file offset within data file.
	// Top remaining bits = archive (data file) index.
	storeOff := readBE(b[h.EKeyLength : int(h.EKeyLength)+int(h.StorageOffsetLength)])
	mask := uint64(1)<<uint(h.FileOffsetBits) - 1
	e.ArchiveOffs = uint32(storeOff & mask)
	e.ArchiveIndex = uint32(storeOff >> uint(h.FileOffsetBits))

	// EncodedSize: big-endian, h.EncodedSizeLength bytes (typically 4).
	szOff := int(h.EKeyLength) + int(h.StorageOffsetLength)
	e.EncodedSize = uint32(readBE(b[szOff : szOff+int(h.EncodedSizeLength)]))

	return e
}

func readBE(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}

	return v
}

// String returns a debug summary.
func (h Header) String() string {
	return fmt.Sprintf(
		"IndexHeader{V=%d Bucket=%d EKeyLen=%d FileOffsBits=%d EntryLen=%d EKeyCount=%d}",
		h.IndexVersion,
		h.BucketIndex,
		h.EKeyLength,
		h.FileOffsetBits,
		h.EntryLength,
		h.EKeyCount,
	)
}
