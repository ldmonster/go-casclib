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

package decrypt

import (
	"encoding/binary"
)

// salsa20Constants for 32-byte ("expand 32-byte k") and 16-byte ("expand 16-byte k") keys.
var (
	sigma = []byte("expand 32-byte k") // 32-byte key
	tau   = []byte("expand 16-byte k") // 16-byte key
)

// salsa20XOR performs Salsa20/20 stream-cipher XOR using a 16- or 32-byte key
// and an 8-byte nonce, producing dst from src in place. dst and src may
// overlap exactly. This matches the implementation in CascDecrypt.cpp.
//
// CASC uses a 16-byte key + 8-byte nonce. The standard golang.org/x/crypto/salsa20
// only supports 32-byte keys, so we implement it here.
func salsa20XOR(dst, src, key, nonce []byte) {
	if len(dst) < len(src) {
		panic("salsa20: short dst")
	}

	if len(nonce) != 8 {
		panic("salsa20: nonce must be 8 bytes")
	}

	var (
		consts   []byte
		keyIndex int
	)

	switch len(key) {
	case 16:
		consts = tau
		keyIndex = 0
	case 32:
		consts = sigma
		keyIndex = 16
	default:
		panic("salsa20: key must be 16 or 32 bytes")
	}

	var state [16]uint32

	state[0] = binary.LittleEndian.Uint32(consts[0:4])
	state[1] = binary.LittleEndian.Uint32(key[0:4])
	state[2] = binary.LittleEndian.Uint32(key[4:8])
	state[3] = binary.LittleEndian.Uint32(key[8:12])
	state[4] = binary.LittleEndian.Uint32(key[12:16])
	state[5] = binary.LittleEndian.Uint32(consts[4:8])
	state[6] = binary.LittleEndian.Uint32(nonce[0:4])
	state[7] = binary.LittleEndian.Uint32(nonce[4:8])
	state[8] = 0 // counter low
	state[9] = 0 // counter high
	state[10] = binary.LittleEndian.Uint32(consts[8:12])
	state[11] = binary.LittleEndian.Uint32(key[keyIndex+0 : keyIndex+4])
	state[12] = binary.LittleEndian.Uint32(key[keyIndex+4 : keyIndex+8])
	state[13] = binary.LittleEndian.Uint32(key[keyIndex+8 : keyIndex+12])
	state[14] = binary.LittleEndian.Uint32(key[keyIndex+12 : keyIndex+16])
	state[15] = binary.LittleEndian.Uint32(consts[12:16])

	var block [64]byte
	for len(src) > 0 {
		salsa20Block(&block, &state)

		n := 64
		if n > len(src) {
			n = len(src)
		}

		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ block[i]
		}

		src = src[n:]
		dst = dst[n:]

		state[8]++
		if state[8] == 0 {
			state[9]++
		}
	}
}

func rol32(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

// salsa20Block computes one 64-byte Salsa20/20 block.
func salsa20Block(out *[64]byte, state *[16]uint32) {
	x := *state
	for i := 0; i < 10; i++ {
		// Column round
		x[4] ^= rol32(x[0]+x[12], 7)
		x[8] ^= rol32(x[4]+x[0], 9)
		x[12] ^= rol32(x[8]+x[4], 13)
		x[0] ^= rol32(x[12]+x[8], 18)

		x[9] ^= rol32(x[5]+x[1], 7)
		x[13] ^= rol32(x[9]+x[5], 9)
		x[1] ^= rol32(x[13]+x[9], 13)
		x[5] ^= rol32(x[1]+x[13], 18)

		x[14] ^= rol32(x[10]+x[6], 7)
		x[2] ^= rol32(x[14]+x[10], 9)
		x[6] ^= rol32(x[2]+x[14], 13)
		x[10] ^= rol32(x[6]+x[2], 18)

		x[3] ^= rol32(x[15]+x[11], 7)
		x[7] ^= rol32(x[3]+x[15], 9)
		x[11] ^= rol32(x[7]+x[3], 13)
		x[15] ^= rol32(x[11]+x[7], 18)

		// Row round
		x[1] ^= rol32(x[0]+x[3], 7)
		x[2] ^= rol32(x[1]+x[0], 9)
		x[3] ^= rol32(x[2]+x[1], 13)
		x[0] ^= rol32(x[3]+x[2], 18)

		x[6] ^= rol32(x[5]+x[4], 7)
		x[7] ^= rol32(x[6]+x[5], 9)
		x[4] ^= rol32(x[7]+x[6], 13)
		x[5] ^= rol32(x[4]+x[7], 18)

		x[11] ^= rol32(x[10]+x[9], 7)
		x[8] ^= rol32(x[11]+x[10], 9)
		x[9] ^= rol32(x[8]+x[11], 13)
		x[10] ^= rol32(x[9]+x[8], 18)

		x[12] ^= rol32(x[15]+x[14], 7)
		x[13] ^= rol32(x[12]+x[15], 9)
		x[14] ^= rol32(x[13]+x[12], 13)
		x[15] ^= rol32(x[14]+x[13], 18)
	}

	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:i*4+4], x[i]+state[i])
	}
}
