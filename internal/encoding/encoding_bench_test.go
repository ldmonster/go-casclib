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
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// BenchmarkParseEncoding parses an ENCODING manifest with many CKey pages.
// Approximates the per-open cost on a real install.
func BenchmarkParseEncoding(b *testing.B) {
	data := buildLargeEncoding(64) // 64 pages × 4 KiB
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}

func buildLargeEncoding(pageCount int) []byte {
	const pageKB = 4
	const pageBytes = pageKB * 1024

	hdr := make([]byte, fileEncodingHeaderSize)
	binary.LittleEndian.PutUint16(hdr[0:2], casc.MagicEncoding)
	hdr[2] = 1
	hdr[3] = 16
	hdr[4] = 16
	binary.BigEndian.PutUint16(hdr[5:7], pageKB)
	binary.BigEndian.PutUint16(hdr[7:9], pageKB)
	binary.BigEndian.PutUint32(hdr[9:13], uint32(pageCount))
	binary.BigEndian.PutUint32(hdr[13:17], 0)
	hdr[17] = 0
	binary.BigEndian.PutUint32(hdr[18:22], 0)

	makeEntry := func(seed byte) []byte {
		const n = 1
		buf := make([]byte, 6+16+n*16)
		binary.LittleEndian.PutUint16(buf[0:2], uint16(n))
		binary.BigEndian.PutUint32(buf[2:6], 0x12345)
		for i := 0; i < 16; i++ {
			buf[6+i] = seed + byte(i)
		}
		for i := 0; i < 16; i++ {
			buf[22+i] = seed*7 + byte(i)
		}
		return buf
	}

	pages := make([]byte, 0, pageCount*pageBytes)
	for p := 0; p < pageCount; p++ {
		page := make([]byte, pageBytes)
		off := 0
		// Pack ~100 entries per page.
		for i := 0; i < 100 && off+38 <= pageBytes; i++ {
			e := makeEntry(byte(p*7 + i))
			copy(page[off:], e)
			off += len(e)
		}
		pages = append(pages, page...)
	}

	cKeyPageIndex := make([]byte, pageCount*32)
	out := make([]byte, 0, len(hdr)+len(cKeyPageIndex)+len(pages))
	out = append(out, hdr...)
	out = append(out, cKeyPageIndex...)
	out = append(out, pages...)
	return out
}
