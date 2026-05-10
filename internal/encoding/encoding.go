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

package encoding

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// Header is the parsed ENCODING file header.
type Header struct {
	Version        byte
	CKeyLength     byte
	EKeyLength     byte
	CKeyPageSize   uint32 // bytes (header value is in KB)
	EKeyPageSize   uint32
	CKeyPageCount  uint32
	EKeyPageCount  uint32
	ESpecBlockSize uint32
}

// CKeyEntry is one CKey -> [EKey...] mapping in the ENCODING manifest.
type CKeyEntry struct {
	ContentSize uint64
	CKey        casc.CKey
	EKeys       []casc.EKey
}

// File represents a parsed ENCODING manifest.
type File struct {
	Header Header
	// Entries indexed by CKey for O(1) lookup.
	Entries map[casc.CKey]*CKeyEntry
}

// fileEncodingHeaderSize is the on-disk size of FILE_ENCODING_HEADER (22).
const fileEncodingHeaderSize = 22

// Parse parses an ENCODING manifest from raw bytes.
func Parse(data []byte) (*File, error) {
	if len(data) < fileEncodingHeaderSize {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint16(data[0:2]) != casc.MagicEncoding {
		return nil, casc.ErrBadFormat
	}

	if data[2] != 1 {
		return nil, fmt.Errorf("%w: ENCODING version %d", casc.ErrNotSupported, data[2])
	}

	cKeyLen := data[3]
	eKeyLen := data[4]
	cPageSizeKB := casc.BEUint16(data[5:7])
	ePageSizeKB := casc.BEUint16(data[7:9])
	cPageCount := casc.BEUint32(data[9:13])
	ePageCount := casc.BEUint32(data[13:17])
	// data[17] = field_11 (must be 0)
	especSize := casc.BEUint32(data[18:22])

	hdr := Header{
		Version:        1,
		CKeyLength:     cKeyLen,
		EKeyLength:     eKeyLen,
		CKeyPageSize:   uint32(cPageSizeKB) * 1024,
		EKeyPageSize:   uint32(ePageSizeKB) * 1024,
		CKeyPageCount:  cPageCount,
		EKeyPageCount:  ePageCount,
		ESpecBlockSize: especSize,
	}

	if cKeyLen != 16 || eKeyLen != 16 {
		return nil, fmt.Errorf("%w: ENCODING with non-16-byte keys", casc.ErrNotSupported)
	}

	off := fileEncodingHeaderSize + int(especSize)
	// CKey page index: cPageCount * (16+16). We can skip it; trust the pages.
	off += int(cPageCount) * (casc.MD5HashSize * 2)

	if off > len(data) {
		return nil, casc.ErrFileCorrupt
	}

	entries := make(map[casc.CKey]*CKeyEntry, cPageCount*16)

	pageBytes := int(hdr.CKeyPageSize)
	for i := uint32(0); i < cPageCount; i++ {
		if off+pageBytes > len(data) {
			return nil, casc.ErrFileCorrupt
		}

		page := data[off : off+pageBytes]
		// Each entry: USHORT EKeyCount + 4-byte BE ContentSize + 16-byte CKey + EKeyCount*16 EKey.
		p := 0
		for p+6 <= pageBytes {
			ekeyCount := binary.LittleEndian.Uint16(page[p : p+2])
			if ekeyCount == 0 {
				break
			}

			recordSize := 6 + casc.MD5HashSize + int(ekeyCount)*casc.MD5HashSize
			if p+recordSize > pageBytes {
				return nil, casc.ErrFileCorrupt
			}

			cs := casc.BEUint32(page[p+2 : p+6])

			var ckey casc.CKey
			copy(ckey[:], page[p+6:p+6+casc.MD5HashSize])

			ekeys := make([]casc.EKey, ekeyCount)
			for k := 0; k < int(ekeyCount); k++ {
				koff := p + 6 + casc.MD5HashSize + k*casc.MD5HashSize
				copy(ekeys[k][:], page[koff:koff+casc.MD5HashSize])
			}

			entries[ckey] = &CKeyEntry{
				ContentSize: uint64(cs),
				CKey:        ckey,
				EKeys:       ekeys,
			}
			p += recordSize
		}

		off += pageBytes
	}

	return &File{Header: hdr, Entries: entries}, nil
}

// Find returns the entry for ckey, or nil.
func (f *File) Find(ckey casc.CKey) *CKeyEntry {
	return f.Entries[ckey]
}

// VerifyPage validates a 16-byte SegmentHash by recomputing MD5 over a page.
// Useful in tests.
func VerifyPage(page []byte, expected [16]byte) bool {
	return md5.Sum(page) == expected
}
