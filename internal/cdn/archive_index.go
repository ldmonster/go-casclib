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

// CDN archive-index parser.
//
// CDN-hosted CASC storages bundle many EKey blobs into a small number of
// large "archive" files. Each archive has a sibling "<archive-md5>.index"
// file mapping EKeys to (offset, encoded-size) within the archive blob.
// The cdn-config's `archives` field lists the archive MD5 hashes.
//
// On-disk layout (matches CascLib's CascStructs.h FILE_INDEX_FOOTER and
// CascIndexFiles.cpp::CaptureArchiveIndexFooter / LoadArchiveIndexPage):
//
//	body:
//	  pages, each PageLength bytes (= PageSizeKB << 10) of records,
//	  followed by a 16-byte MD5 of the page (last page may be zero-padded).
//	  record:
//	    [EKeyLength]   EKey (16 bytes typical)
//	    [SizeBytes]    EncodedSize, big-endian (4 bytes typical)
//	    [OffsetBytes]  ArchiveOffset, big-endian (4 bytes typical, 6 for "group")
//	footer (36 bytes for the canonical FooterHashBytes==8 variant):
//	  [16] TocHash
//	  [1]  Version = 1
//	  [2]  Reserved = {0,0}
//	  [1]  PageSizeKB
//	  [1]  OffsetBytes
//	  [1]  SizeBytes
//	  [1]  EKeyLength
//	  [1]  FooterHashBytes (== 8)
//	  [4]  ElementCount, little-endian
//	  [8]  FooterHash (truncated MD5 over footer[16:36] with FooterHash zeroed)
package cdn

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// archiveFooterLen is the canonical footer size with FooterHashBytes == 8.
const archiveFooterLen = 36

// ArchiveIndexFooter is the parsed trailer of a CDN archive-index file.
type ArchiveIndexFooter struct {
	TocHash         [16]byte
	Version         byte
	PageSizeKB      byte
	OffsetBytes     byte
	SizeBytes       byte
	EKeyLength      byte
	FooterHashBytes byte
	ElementCount    uint32
	FooterHash      [16]byte // first FooterHashBytes are valid

	// Derived.
	PageLength   int // PageSizeKB << 10
	ItemLength   int // EKeyLength + OffsetBytes + SizeBytes
	FooterLength int
}

// ArchiveIndexEntry is one EKey -> (offset, encoded-size) record.
type ArchiveIndexEntry struct {
	EKey        casc.EKey
	Offset      uint64 // byte offset within the archive blob
	EncodedSize uint64 // on-CDN encoded size of that span
}

// ArchiveIndex is a parsed archive-index file (one .index per archive).
type ArchiveIndex struct {
	Footer  ArchiveIndexFooter
	Entries []ArchiveIndexEntry
}

// ParseArchiveIndex parses an archive-index blob with footer hash verification.
func ParseArchiveIndex(data []byte) (*ArchiveIndex, error) {
	if len(data) < archiveFooterLen {
		return nil, fmt.Errorf("%w: archive-index too short (%d)", casc.ErrBadFormat, len(data))
	}

	f := data[len(data)-archiveFooterLen:]

	footer := ArchiveIndexFooter{
		Version:         f[16],
		PageSizeKB:      f[19],
		OffsetBytes:     f[20],
		SizeBytes:       f[21],
		EKeyLength:      f[22],
		FooterHashBytes: f[23],
	}
	copy(footer.TocHash[:], f[0:16])
	footer.ElementCount = binary.LittleEndian.Uint32(f[24:28])
	copy(footer.FooterHash[:8], f[28:36])

	if footer.Version != 1 || f[17] != 0 || f[18] != 0 || footer.FooterHashBytes != 8 {
		return nil, fmt.Errorf("%w: archive-index footer (version=%d reserved=%d,%d hashBytes=%d)",
			casc.ErrBadFormat, footer.Version, f[17], f[18], footer.FooterHashBytes)
	}

	if footer.PageSizeKB == 0 || footer.EKeyLength == 0 || footer.EKeyLength > casc.MD5HashSize {
		return nil, fmt.Errorf("%w: archive-index sizes (page=%dKB ekey=%d)",
			casc.ErrBadFormat, footer.PageSizeKB, footer.EKeyLength)
	}

	if footer.OffsetBytes == 0 || footer.OffsetBytes > 8 || footer.SizeBytes == 0 ||
		footer.SizeBytes > 8 {
		return nil, fmt.Errorf("%w: archive-index size widths (off=%d size=%d)",
			casc.ErrBadFormat, footer.OffsetBytes, footer.SizeBytes)
	}

	footer.PageLength = int(footer.PageSizeKB) << 10
	footer.ItemLength = int(footer.EKeyLength) + int(footer.OffsetBytes) + int(footer.SizeBytes)
	footer.FooterLength = archiveFooterLen

	// Footer hash: MD5 over footer[16:36] with FooterHash zeroed; compare
	// the first FooterHashBytes against the on-disk FooterHash.
	var fbuf [archiveFooterLen]byte
	copy(fbuf[:], f)

	for i := 28; i < archiveFooterLen; i++ {
		fbuf[i] = 0
	}

	sum := md5.Sum(fbuf[16:])
	for i := 0; i < int(footer.FooterHashBytes); i++ {
		if sum[i] != footer.FooterHash[i] {
			return nil, fmt.Errorf("%w: archive-index footer hash mismatch", casc.ErrFileCorrupt)
		}
	}

	bodyLen := len(data) - footer.FooterLength
	pageStride := footer.PageLength + casc.MD5HashSize
	pageCount := bodyLen / pageStride

	out := &ArchiveIndex{Footer: footer}
	out.Entries = make([]ArchiveIndexEntry, 0, footer.ElementCount)

	var zero casc.EKey

	itemLen := footer.ItemLength
	sizeOff := int(footer.EKeyLength)

	offOff := sizeOff + int(footer.SizeBytes)
	for p := 0; p < pageCount; p++ {
		page := data[p*pageStride : p*pageStride+footer.PageLength]
		for o := 0; o+itemLen <= len(page); o += itemLen {
			rec := page[o : o+itemLen]

			var ek casc.EKey
			copy(ek[:footer.EKeyLength], rec[:footer.EKeyLength])

			if ek == zero {
				break // zero-padded tail of the page
			}

			size := beUintN(rec[sizeOff:offOff])
			off := beUintN(rec[offOff : offOff+int(footer.OffsetBytes)])
			out.Entries = append(out.Entries, ArchiveIndexEntry{
				EKey:        ek,
				Offset:      off,
				EncodedSize: size,
			})
		}
	}

	return out, nil
}

// EncodeArchiveIndex serializes a (footer, entries) pair into the on-disk
// archive-index format. Used by tests; not part of CascLib's surface.
func EncodeArchiveIndex(footer ArchiveIndexFooter, entries []ArchiveIndexEntry) []byte {
	pageLen := int(footer.PageSizeKB) << 10
	itemLen := int(footer.EKeyLength) + int(footer.OffsetBytes) + int(footer.SizeBytes)
	itemsPerPage := pageLen / itemLen

	pageCount := (len(entries) + itemsPerPage - 1) / itemsPerPage
	if pageCount == 0 {
		pageCount = 1
	}

	out := make([]byte, pageCount*(pageLen+casc.MD5HashSize)+archiveFooterLen)
	for p := 0; p < pageCount; p++ {
		pageStart := p * (pageLen + casc.MD5HashSize)
		page := out[pageStart : pageStart+pageLen]

		for i := 0; i < itemsPerPage; i++ {
			idx := p*itemsPerPage + i
			if idx >= len(entries) {
				break
			}

			e := entries[idx]
			rec := page[i*itemLen : (i+1)*itemLen]
			copy(rec[:footer.EKeyLength], e.EKey[:footer.EKeyLength])
			putBEUintN(rec[footer.EKeyLength:int(footer.EKeyLength)+int(footer.SizeBytes)],
				e.EncodedSize, int(footer.SizeBytes))
			putBEUintN(rec[int(footer.EKeyLength)+int(footer.SizeBytes):itemLen],
				e.Offset, int(footer.OffsetBytes))
		}

		sum := md5.Sum(page)
		copy(out[pageStart+pageLen:pageStart+pageLen+casc.MD5HashSize], sum[:])
	}

	footerOff := len(out) - archiveFooterLen
	footer.FooterHashBytes = 8
	footer.ElementCount = uint32(len(entries))
	f := out[footerOff:]
	copy(f[0:16], footer.TocHash[:])
	f[16] = 1
	f[17] = 0
	f[18] = 0
	f[19] = footer.PageSizeKB
	f[20] = footer.OffsetBytes
	f[21] = footer.SizeBytes
	f[22] = footer.EKeyLength
	f[23] = footer.FooterHashBytes
	binary.LittleEndian.PutUint32(f[24:28], footer.ElementCount)

	var fbuf [archiveFooterLen]byte
	copy(fbuf[:], f)
	sum := md5.Sum(fbuf[16:])
	copy(f[28:36], sum[:8])

	return out
}

// putBEUintN writes the low n bytes of v as big-endian into b.
func putBEUintN(b []byte, v uint64, n int) {
	for i := 0; i < n; i++ {
		b[n-1-i] = byte(v >> (8 * i))
	}
}
