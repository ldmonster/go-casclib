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
	"testing"

	"github.com/ldmonster/go-casclib/internal/hashes"
)

// BenchmarkParseV1_5K parses a synthetic 5000-entry V1 index. Measures the
// throughput of the hot path used during local-storage open.
func BenchmarkParseV1_5K(b *testing.B) {
	data := buildSyntheticV1Bench(0x03, 2500, 2500)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(data, 0x03); err != nil {
			b.Fatal(err)
		}
	}
}

func buildSyntheticV1Bench(bucket byte, count1, count2 int) []byte {
	const entryLen = 18
	hdr := make([]byte, 40)
	binary.LittleEndian.PutUint16(hdr[0:2], 0x05)
	hdr[2] = bucket
	binary.LittleEndian.PutUint64(hdr[8:16], 0x40000000)
	hdr[16] = 4
	hdr[17] = 5
	hdr[18] = 9
	hdr[19] = 30
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(count1))
	binary.LittleEndian.PutUint32(hdr[24:28], uint32(count2))

	mk := func(n int, base byte) []byte {
		buf := make([]byte, n*entryLen)
		for i := 0; i < n; i++ {
			off := i * entryLen
			for j := 0; j < 9; j++ {
				buf[off+j] = base + byte(i) + byte(j)
			}
			fileOffs := uint64(i) * 0x1000
			storeOff := (uint64(base) << 30) | fileOffs
			for k := 0; k < 5; k++ {
				buf[off+9+k] = byte(storeOff >> uint(8*(4-k)))
			}
			binary.BigEndian.PutUint32(buf[off+14:off+18], uint32(0x10000+i))
		}
		return buf
	}
	b1 := mk(count1, 1)
	b2 := mk(count2, 2)
	binary.LittleEndian.PutUint32(hdr[28:32], hashes.HashLittle(b1, 0))
	binary.LittleEndian.PutUint32(hdr[32:36], hashes.HashLittle(b2, 0))
	binary.LittleEndian.PutUint32(hdr[36:40], 0)
	binary.LittleEndian.PutUint32(hdr[36:40], hashes.HashLittle(hdr, 0))

	full := make([]byte, 0, len(hdr)+len(b1)+len(b2))
	full = append(full, hdr...)
	full = append(full, b1...)
	full = append(full, b2...)
	return full
}
