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

// INSTALL manifest writer.
//
// Emits the v1 INSTALL format documented in install.go.
//
// C++ reference: CascRootFile_Install.cpp.

package install

import (
	"encoding/binary"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// Entry is one (filename, CKey, size) record for the writer.
type Entry struct {
	Name        string
	CKey        casc.CKey
	ContentSize uint32
}

// WriteOptions controls Encode.
type WriteOptions struct {
	HashSize byte // defaults to 16
}

// Encode emits an INSTALL manifest. Entries are written in the order
// supplied; tag bitmaps must use the same indexing.
func Encode(entries []Entry, tags []Tag, opts WriteOptions) ([]byte, error) {
	if opts.HashSize == 0 {
		opts.HashSize = casc.MD5HashSize
	}

	if int(opts.HashSize) > casc.MD5HashSize {
		return nil, casc.ErrInvalidParameter
	}

	bitmapLen := (len(entries) + 7) / 8

	totalSize := fileInstallHeaderSize
	for _, t := range tags {
		totalSize += len(t.Name) + 1 + 2 + bitmapLen
	}

	for _, e := range entries {
		totalSize += len(e.Name) + 1 + int(opts.HashSize) + 4
	}

	out := make([]byte, totalSize)

	binary.LittleEndian.PutUint16(out[0:2], casc.MagicInstall)
	out[2] = 1
	out[3] = opts.HashSize
	out[4] = byte(uint16(len(tags)) >> 8)
	out[5] = byte(uint16(len(tags)))
	out[6] = byte(uint32(len(entries)) >> 24)
	out[7] = byte(uint32(len(entries)) >> 16)
	out[8] = byte(uint32(len(entries)) >> 8)
	out[9] = byte(uint32(len(entries)))

	off := fileInstallHeaderSize

	// Tags.
	for _, t := range tags {
		copy(out[off:off+len(t.Name)], t.Name)
		off += len(t.Name)
		out[off] = 0
		off++
		out[off] = byte(t.Type >> 8)
		out[off+1] = byte(t.Type)
		off += 2

		bm := bitmapLen
		if len(t.Bitmap) < bm {
			bm = len(t.Bitmap)
		}

		copy(out[off:off+bm], t.Bitmap[:bm])
		off += bitmapLen
	}

	// Entries.
	for _, e := range entries {
		copy(out[off:off+len(e.Name)], e.Name)
		off += len(e.Name)
		out[off] = 0
		off++
		copy(out[off:off+int(opts.HashSize)], e.CKey[:opts.HashSize])
		off += int(opts.HashSize)
		out[off] = byte(e.ContentSize >> 24)
		out[off+1] = byte(e.ContentSize >> 16)
		out[off+2] = byte(e.ContentSize >> 8)
		out[off+3] = byte(e.ContentSize)
		off += 4
	}

	return out, nil
}
