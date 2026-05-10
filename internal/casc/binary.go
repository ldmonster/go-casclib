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

package casc

// Big-endian variable-length integer helpers used pervasively in CASC formats.
// The upstream C++ provides ConvertBytesToInteger_2/3/4/4_LE/5/6 inline.

// BEUint16 reads a 2-byte big-endian unsigned integer.
func BEUint16(b []byte) uint16 {
	_ = b[1]
	return uint16(b[0])<<8 | uint16(b[1])
}

// BEUint24 reads a 3-byte big-endian unsigned integer.
func BEUint24(b []byte) uint32 {
	_ = b[2]
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// BEUint32 reads a 4-byte big-endian unsigned integer.
func BEUint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// BEUint40 reads a 5-byte big-endian unsigned integer.
func BEUint40(b []byte) uint64 {
	_ = b[4]

	return uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 |
		uint64(b[3])<<8 | uint64(b[4])
}

// BEUint48 reads a 6-byte big-endian unsigned integer.
func BEUint48(b []byte) uint64 {
	_ = b[5]

	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
		uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

// LEUint32 reads a 4-byte little-endian unsigned integer.
func LEUint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// PutLEUint32 writes v as little-endian into b (4 bytes).
func PutLEUint32(b []byte, v uint32) {
	_ = b[3]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
