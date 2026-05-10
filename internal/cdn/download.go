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

// Package cdn parses the DOWNLOAD manifest used by CASC storages and
// provides a minimal HTTP client for fetching CDN-hosted blobs.
//
// The DOWNLOAD manifest is a flat table that lists every encoded blob the
// game *might* need, along with a priority and per-tag bitmaps describing
// which platform / locale / install-group an entry belongs to. CASC clients
// use it to drive background downloads.
//
// On-disk layout:
//
//	[2] Magic = 'DL' (0x4C44)
//	[1] Version (1..3)
//	[1] EKeyLength (typically 16)
//	[1] EntryHasChecksum
//	[4 BE] EntryCount
//	[2 BE] TagCount
//	-- v2+ --
//	[1] FlagByteSize
//	-- v3+ --
//	[1] BasePriority
//	[3] Unknown
//	-- entries --
//	for each EntryCount:
//	  [EKeyLength] EKey
//	  [5 BE] EncodedSize
//	  [1] Priority
//	  [4 BE] Checksum (if EntryHasChecksum)
//	  [FlagByteSize] Flags
//	-- tags --
//	for each TagCount:
//	  [zero-terminated] tag name
//	  [2 BE] tag type
//	  [ceil(EntryCount/8)] entry bitmap
//
// C++ reference: CascOpenStorage.cpp::CaptureDownloadHeader / -Entry / -Tag.
package cdn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
)

const downloadMagic uint16 = 0x4C44 // 'DL'

// DownloadHeader is the parsed DOWNLOAD manifest header.
type DownloadHeader struct {
	Version          byte
	EKeyLength       byte
	EntryHasChecksum bool
	EntryCount       uint32
	TagCount         uint16
	FlagByteSize     byte // v2+
	BasePriority     byte // v3+

	// HeaderLength is the byte offset at which entries start.
	HeaderLength int
	// EntryLength is the size of one entry record in bytes.
	EntryLength int
}

// DownloadEntry is one entry from the manifest.
type DownloadEntry struct {
	EKey        casc.EKey
	EncodedSize uint64 // 5-byte big-endian
	Priority    byte
	Checksum    uint32
	Flags       uint64
}

// DownloadTag is one tag bitmap.
type DownloadTag struct {
	Name   string
	Type   uint16
	Bitmap []byte
}

// DownloadManifest is the parsed manifest.
type DownloadManifest struct {
	Header  DownloadHeader
	Entries []DownloadEntry
	Tags    []DownloadTag
}

// ParseDownload parses a DOWNLOAD manifest blob.
func ParseDownload(data []byte) (*DownloadManifest, error) {
	if len(data) < 10 {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint16(data[0:2]) != downloadMagic {
		return nil, fmt.Errorf("%w: DOWNLOAD magic", casc.ErrBadFormat)
	}

	version := data[2]
	if version < 1 || version > 3 {
		return nil, fmt.Errorf("%w: DOWNLOAD version %d", casc.ErrNotSupported, version)
	}

	hdr := DownloadHeader{
		Version:          version,
		EKeyLength:       data[3],
		EntryHasChecksum: data[4] != 0,
		EntryCount:       casc.BEUint32(data[5:9]),
		TagCount:         casc.BEUint16(data[9:11]),
	}
	if hdr.EKeyLength == 0 || hdr.EKeyLength > casc.MD5HashSize {
		return nil, fmt.Errorf("%w: DOWNLOAD EKeyLength %d", casc.ErrBadFormat, hdr.EKeyLength)
	}

	off := 11
	if version >= 2 {
		if off+1 > len(data) {
			return nil, casc.ErrBadFormat
		}

		hdr.FlagByteSize = data[off]
		off++
	}

	if version >= 3 {
		if off+4 > len(data) {
			return nil, casc.ErrBadFormat
		}

		hdr.BasePriority = data[off]
		off += 4 // priority + 3 unknown
	}

	hdr.HeaderLength = off

	hdr.EntryLength = int(hdr.EKeyLength) + 5 + 1 + int(hdr.FlagByteSize)
	if hdr.EntryHasChecksum {
		hdr.EntryLength += 4
	}

	man := &DownloadManifest{Header: hdr}

	// Entries.
	entriesBytes := int(hdr.EntryCount) * hdr.EntryLength
	if off+entriesBytes > len(data) {
		return nil, fmt.Errorf("%w: DOWNLOAD entries truncated", casc.ErrBadFormat)
	}

	man.Entries = make([]DownloadEntry, hdr.EntryCount)
	for i := uint32(0); i < hdr.EntryCount; i++ {
		eOff := off + int(i)*hdr.EntryLength

		var e DownloadEntry
		copy(e.EKey[:hdr.EKeyLength], data[eOff:eOff+int(hdr.EKeyLength)])
		eOff += int(hdr.EKeyLength)
		e.EncodedSize = beUint5(data[eOff : eOff+5])
		eOff += 5
		e.Priority = data[eOff]

		eOff++
		if hdr.EntryHasChecksum {
			e.Checksum = casc.BEUint32(data[eOff : eOff+4])
			eOff += 4
		}

		if hdr.FlagByteSize > 0 {
			e.Flags = beUintN(data[eOff : eOff+int(hdr.FlagByteSize)])
		}

		man.Entries[i] = e
	}

	off += entriesBytes

	// Tags.
	bitmapLen := int((hdr.EntryCount + 7) / 8)

	man.Tags = make([]DownloadTag, 0, hdr.TagCount)
	for i := uint16(0); i < hdr.TagCount; i++ {
		nameEnd := bytes.IndexByte(data[off:], 0)
		if nameEnd < 0 {
			return nil, fmt.Errorf("%w: DOWNLOAD tag name unterminated", casc.ErrBadFormat)
		}

		name := string(data[off : off+nameEnd])

		off += nameEnd + 1
		if off+2 > len(data) {
			return nil, casc.ErrBadFormat
		}

		typ := casc.BEUint16(data[off : off+2])
		off += 2
		// Last tag's bitmap may be truncated; clamp to what's left.
		bm := bitmapLen
		if remaining := len(data) - off; remaining < bm {
			bm = remaining
		}

		buf := make([]byte, bm)
		copy(buf, data[off:off+bm])
		off += bm

		man.Tags = append(man.Tags, DownloadTag{Name: name, Type: typ, Bitmap: buf})
	}

	return man, nil
}

// beUint5 decodes a 5-byte big-endian unsigned integer.
func beUint5(b []byte) uint64 {
	_ = b[4]
	return uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
}

// beUintN decodes 1..8 byte big-endian unsigned integer.
func beUintN(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}

	return v
}
