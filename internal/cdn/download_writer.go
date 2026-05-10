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

// DOWNLOAD manifest writer (v3).
//
// Emits the format documented at the top of download.go: header,
// optional v2/v3 fixed fields, entries, then a tag table whose bitmaps
// pack one bit per entry.
//
// C++ reference: CascOpenStorage.cpp::CaptureDownloadHeader / -Entry / -Tag.

package cdn

import (
	"encoding/binary"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// WriteDownloadOptions controls EncodeDownload.
type WriteDownloadOptions struct {
	// Version selects the on-disk version (1, 2 or 3). Defaults to 3.
	Version byte
	// EKeyLength is the on-disk EKey width. Defaults to 16.
	EKeyLength byte
	// FlagByteSize is the per-entry flag-bitmap width in bytes. Defaults
	// to 0 (no flags). Only meaningful for Version >= 2.
	FlagByteSize byte
	// EntryHasChecksum, if true, encodes a 4-byte checksum per entry.
	EntryHasChecksum bool
	// BasePriority is the v3 base priority.
	BasePriority byte
}

// EncodeDownload serialises a DownloadManifest. The supplied entries
// and tags are emitted in order. Each tag's Bitmap must have exactly
// ceil(len(entries)/8) bytes (or it will be padded / truncated).
func EncodeDownload(
	entries []DownloadEntry,
	tags []DownloadTag,
	opts WriteDownloadOptions,
) ([]byte, error) {
	if opts.Version == 0 {
		opts.Version = 3
	}

	if opts.Version < 1 || opts.Version > 3 {
		return nil, fmt.Errorf("%w: DOWNLOAD version %d", casc.ErrNotSupported, opts.Version)
	}

	if opts.EKeyLength == 0 {
		opts.EKeyLength = casc.MD5HashSize
	}

	if int(opts.EKeyLength) > casc.MD5HashSize {
		return nil, casc.ErrInvalidParameter
	}

	headerLen := 11
	if opts.Version >= 2 {
		headerLen += 1 // FlagByteSize
	}

	if opts.Version >= 3 {
		headerLen += 4 // BasePriority + 3 unknown
	}

	entryLen := int(opts.EKeyLength) + 5 + 1 + int(opts.FlagByteSize)
	if opts.EntryHasChecksum {
		entryLen += 4
	}

	bitmapLen := (len(entries) + 7) / 8

	var (
		out      []byte
		entryOff int
	)

	totalSize := headerLen + len(entries)*entryLen
	for _, t := range tags {
		totalSize += len(t.Name) + 1 + 2 + bitmapLen
		_ = t
	}

	out = make([]byte, totalSize)

	// Header.
	binary.LittleEndian.PutUint16(out[0:2], downloadMagic)
	out[2] = opts.Version
	out[3] = opts.EKeyLength

	if opts.EntryHasChecksum {
		out[4] = 1
	}

	putBEUint32(out[5:9], uint32(len(entries)))
	putBEUint16(out[9:11], uint16(len(tags)))

	off := 11
	if opts.Version >= 2 {
		out[off] = opts.FlagByteSize
		off++
	}

	if opts.Version >= 3 {
		out[off] = opts.BasePriority
		// 3 unknown bytes left zero.
		off += 4
	}

	entryOff = off
	for i, e := range entries {
		o := entryOff + i*entryLen
		copy(out[o:o+int(opts.EKeyLength)], e.EKey[:opts.EKeyLength])
		o += int(opts.EKeyLength)
		putBEUint5(out[o:o+5], e.EncodedSize)
		o += 5
		out[o] = e.Priority
		o++

		if opts.EntryHasChecksum {
			putBEUint32(out[o:o+4], e.Checksum)
			o += 4
		}

		if opts.FlagByteSize > 0 {
			putBEUintN(out[o:o+int(opts.FlagByteSize)], e.Flags, int(opts.FlagByteSize))
		}
	}

	off = entryOff + len(entries)*entryLen

	// Tags.
	for _, t := range tags {
		copy(out[off:off+len(t.Name)], t.Name)
		off += len(t.Name)
		out[off] = 0
		off++
		putBEUint16(out[off:off+2], t.Type)
		off += 2

		copyBitmap(out[off:off+bitmapLen], t.Bitmap)

		off += bitmapLen
	}

	return out, nil
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

func putBEUint5(b []byte, v uint64) {
	b[0] = byte(v >> 32)
	b[1] = byte(v >> 24)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 8)
	b[4] = byte(v)
}

func copyBitmap(dst, src []byte) {
	n := len(src)
	if n > len(dst) {
		n = len(dst)
	}

	copy(dst[:n], src[:n])
}
