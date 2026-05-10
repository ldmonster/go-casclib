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

package datafile

import (
	"crypto/md5"
	"encoding/binary"
	"testing"
)

// buildSingleN constructs a single-N-frame BLTE blob (no allocation in
// hot loops; helper isolated from test-only deps).
func buildSingleN(payload []byte) []byte {
	const frameHdrSize = 24
	const headerSize = 12 + frameHdrSize
	encoded := append([]byte{'N'}, payload...)
	hash := md5.Sum(encoded)

	buf := make([]byte, 0, headerSize+len(encoded))
	buf = append(buf, 'B', 'L', 'T', 'E')
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	buf = append(buf, hs...)
	buf = append(buf, 0x0F)
	buf = append(buf, 0, 0, 1)
	enc := make([]byte, 4)
	binary.BigEndian.PutUint32(enc, uint32(len(encoded)))
	cont := make([]byte, 4)
	binary.BigEndian.PutUint32(cont, uint32(len(payload)))
	buf = append(buf, enc...)
	buf = append(buf, cont...)
	buf = append(buf, hash[:]...)
	buf = append(buf, encoded...)
	return buf
}

func BenchmarkParseHeader(b *testing.B) {
	blob := buildSingleN(make([]byte, 4096))
	b.SetBytes(int64(len(blob)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseHeader(blob); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeNFrame_64KB(b *testing.B) {
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	blob := buildSingleN(payload)
	hdr, err := ParseHeader(blob)
	if err != nil {
		b.Fatal(err)
	}
	dec := &FrameDecoder{}
	frame := hdr.Frames[0]
	body := blob[hdr.HeaderSize:]
	encoded := body[:frame.EncodedSize]
	b.SetBytes(int64(frame.ContentSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decode(frame, encoded); err != nil {
			b.Fatal(err)
		}
	}
}
