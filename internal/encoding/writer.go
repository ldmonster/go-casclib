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

// ENCODING manifest writer.
//
// Emits a v1 ENCODING file: the 22-byte header, ESpec block, CKey page
// index, CKey pages, and (optionally) the EKey page index + EKey pages.
//
// C++ reference: FILE_ENCODING_HEADER + FILE_CKEY_PAGE in CascStructs.h
// and CaptureEncodingHeader in CascOpenStorage.cpp.

package encoding

import (
	"crypto/md5"
	"encoding/binary"
	"sort"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// WriteOptions controls Encode.
type WriteOptions struct {
	// CKeyPageSize is the per-page byte budget for CKey pages. Zero
	// defaults to 4096. Must be a multiple of 1024 (the on-disk header
	// stores KB).
	CKeyPageSize uint32
	// EKeyPageSize is the per-page byte budget for EKey pages. Zero
	// defaults to 4096.
	EKeyPageSize uint32
	// IncludeEKeyPages, if true, emits EKey pages mapping each EKey
	// to its index in the CKey table (record format mirrors CascLib).
	// Default false — the Go parser does not consult them.
	IncludeEKeyPages bool
	// ESpecBlock is the raw ESpec string block. Zero-length means no
	// spec strings (the CKey page records reference an empty trailer).
	ESpecBlock []byte
}

// Encode produces an ENCODING manifest from the supplied entries.
//
// Each entry maps one CKey to one or more EKeys plus a content size.
// Entries are sorted by CKey before emission for determinism.
func Encode(entries []CKeyEntry, opts WriteOptions) ([]byte, error) {
	if opts.CKeyPageSize == 0 {
		opts.CKeyPageSize = 4096
	}

	if opts.EKeyPageSize == 0 {
		opts.EKeyPageSize = 4096
	}

	if opts.CKeyPageSize%1024 != 0 || opts.EKeyPageSize%1024 != 0 {
		return nil, casc.ErrInvalidParameter
	}

	sorted := make([]CKeyEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return ckeyLess(sorted[i].CKey, sorted[j].CKey)
	})

	cKeyPages, cKeyIndex := layoutCKeyPages(sorted, int(opts.CKeyPageSize))

	var (
		eKeyPages [][]byte
		eKeyIndex []byte
	)

	if opts.IncludeEKeyPages {
		eKeyPages, eKeyIndex = layoutEKeyPages(sorted, int(opts.EKeyPageSize))
	}

	totalSize := fileEncodingHeaderSize +
		len(opts.ESpecBlock) +
		len(cKeyIndex) +
		len(cKeyPages)*int(opts.CKeyPageSize) +
		len(eKeyIndex) +
		len(eKeyPages)*int(opts.EKeyPageSize)

	out := make([]byte, totalSize)

	// Header.
	binary.LittleEndian.PutUint16(out[0:2], casc.MagicEncoding)
	out[2] = 1
	out[3] = casc.MD5HashSize
	out[4] = casc.MD5HashSize
	putBEUint16(out[5:7], uint16(opts.CKeyPageSize/1024))
	putBEUint16(out[7:9], uint16(opts.EKeyPageSize/1024))
	putBEUint32(out[9:13], uint32(len(cKeyPages)))
	putBEUint32(out[13:17], uint32(len(eKeyPages)))
	out[17] = 0
	putBEUint32(out[18:22], uint32(len(opts.ESpecBlock)))

	off := fileEncodingHeaderSize
	copy(out[off:off+len(opts.ESpecBlock)], opts.ESpecBlock)
	off += len(opts.ESpecBlock)

	copy(out[off:off+len(cKeyIndex)], cKeyIndex)
	off += len(cKeyIndex)

	for _, p := range cKeyPages {
		copy(out[off:off+int(opts.CKeyPageSize)], p)
		off += int(opts.CKeyPageSize)
	}

	if opts.IncludeEKeyPages {
		copy(out[off:off+len(eKeyIndex)], eKeyIndex)
		off += len(eKeyIndex)

		for _, p := range eKeyPages {
			copy(out[off:off+int(opts.EKeyPageSize)], p)
			off += int(opts.EKeyPageSize)
		}
	}

	return out, nil
}

// layoutCKeyPages partitions sorted entries into fixed-size pages and
// returns the pages plus the (FirstKey, PageHash) page index.
func layoutCKeyPages(entries []CKeyEntry, pageSize int) ([][]byte, []byte) {
	const recordHdr = 6 + casc.MD5HashSize // EKeyCount(2) + ContentSize(BE,4) + CKey(16)

	var pages [][]byte

	type pageInfo struct {
		first casc.CKey
		hash  [16]byte
	}

	var infos []pageInfo

	i := 0
	for i < len(entries) {
		page := make([]byte, pageSize)
		first := entries[i].CKey
		off := 0

		for i < len(entries) {
			e := entries[i]
			rec := recordHdr + len(e.EKeys)*casc.MD5HashSize

			if rec > pageSize {
				// Single record larger than a page — fail-safe truncate to first ekey.
				if len(e.EKeys) == 0 {
					rec = recordHdr
				} else {
					rec = recordHdr + casc.MD5HashSize
					e.EKeys = e.EKeys[:1]
				}
			}

			if off+rec > pageSize {
				break
			}

			binary.BigEndian.PutUint16(page[off:off+2], 0) // EKeyCount: little? See parser
			// Parser uses LittleEndian.Uint16 for ekeyCount; ContentSize is
			// big-endian uint32. Match the parser exactly:
			binary.LittleEndian.PutUint16(page[off:off+2], uint16(len(e.EKeys)))
			putBEUint32(page[off+2:off+6], uint32(e.ContentSize))
			copy(page[off+6:off+6+casc.MD5HashSize], e.CKey[:])

			koff := off + 6 + casc.MD5HashSize
			for _, ek := range e.EKeys {
				copy(page[koff:koff+casc.MD5HashSize], ek[:])
				koff += casc.MD5HashSize
			}

			off += rec
			i++
		}

		hash := md5.Sum(page)
		infos = append(infos, pageInfo{first: first, hash: hash})
		pages = append(pages, page)
	}

	idx := make([]byte, len(infos)*(casc.MD5HashSize*2))
	for n, info := range infos {
		copy(idx[n*32:n*32+casc.MD5HashSize], info.first[:])
		copy(idx[n*32+casc.MD5HashSize:(n+1)*32], info.hash[:])
	}

	return pages, idx
}

// layoutEKeyPages emits EKey-record pages: EKey + EncIndex (BE u32) +
// EncodedSize (BE u40). Only the first EKey of each entry is recorded.
func layoutEKeyPages(entries []CKeyEntry, pageSize int) ([][]byte, []byte) {
	const recordSize = casc.MD5HashSize + 4 + 5

	var (
		pages [][]byte
		infos [][2][16]byte
	)

	i := 0
	for i < len(entries) {
		page := make([]byte, pageSize)
		off := 0

		var first casc.EKey

		if len(entries[i].EKeys) > 0 {
			first = entries[i].EKeys[0]
		}

		for i < len(entries) && off+recordSize <= pageSize {
			e := entries[i]
			if len(e.EKeys) > 0 {
				copy(page[off:off+casc.MD5HashSize], e.EKeys[0][:])
				putBEUint32(page[off+casc.MD5HashSize:off+casc.MD5HashSize+4], uint32(i))
				putBEUint40(page[off+casc.MD5HashSize+4:off+casc.MD5HashSize+9], 0)
				off += recordSize
			}

			i++
		}

		hash := md5.Sum(page)

		var firstFixed [16]byte
		copy(firstFixed[:], first[:])

		infos = append(infos, [2][16]byte{firstFixed, hash})

		pages = append(pages, page)
	}

	idx := make([]byte, len(infos)*32)
	for n, p := range infos {
		copy(idx[n*32:n*32+16], p[0][:])
		copy(idx[n*32+16:(n+1)*32], p[1][:])
	}

	return pages, idx
}

func ckeyLess(a, b casc.CKey) bool {
	for i := 0; i < casc.MD5HashSize; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}

	return false
}

func putBEUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func putBEUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func putBEUint40(b []byte, v uint64) {
	b[0] = byte(v >> 32)
	b[1] = byte(v >> 24)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 8)
	b[4] = byte(v)
}
