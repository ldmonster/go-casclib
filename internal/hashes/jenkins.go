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

// Package hashes provides Jenkins lookup3 hashlittle / hashlittle2 used
// throughout CASC for filename hashing and table integrity. This is a
// faithful port of jenkins/lookup3.c by Bob Jenkins (public domain).
package hashes

// rot rotates x left by k bits.
func rot(x uint32, k uint) uint32 { return (x << k) | (x >> (32 - k)) }

// mix scrambles three 32-bit values reversibly.
func mix(a, b, c uint32) (uint32, uint32, uint32) {
	a -= c
	a ^= rot(c, 4)
	c += b
	b -= a
	b ^= rot(a, 6)
	a += c
	c -= b
	c ^= rot(b, 8)
	b += a
	a -= c
	a ^= rot(c, 16)
	c += b
	b -= a
	b ^= rot(a, 19)
	a += c
	c -= b
	c ^= rot(b, 4)
	b += a

	return a, b, c
}

// final performs final avalanche on three 32-bit values. Returns only
// b and c because all current callers discard a.
func final(a, b, c uint32) (uint32, uint32) {
	c ^= b
	c -= rot(b, 14)
	a ^= c
	a -= rot(c, 11)
	b ^= a
	b -= rot(a, 25)
	c ^= b
	c -= rot(b, 16)
	a ^= c
	a -= rot(c, 4)
	b ^= a
	b -= rot(a, 14)
	c ^= b
	c -= rot(b, 24)

	return b, c
}

// HashLittle returns a 32-bit hash of the given byte-slice key, mixed in with
// the supplied initval. Equivalent to hashlittle() in lookup3.c.
//
// We always use the byte-by-byte path. Go's compiler is good enough that the
// minor speed gain from the aligned path isn't worth the unsafe pointer
// arithmetic — and behavior is identical.
func HashLittle(key []byte, initval uint32) uint32 {
	length := uint32(len(key))
	a := 0xdeadbeef + length + initval
	b := a
	c := a

	k := key
	for length > 12 {
		a += uint32(k[0]) | uint32(k[1])<<8 | uint32(k[2])<<16 | uint32(k[3])<<24
		b += uint32(k[4]) | uint32(k[5])<<8 | uint32(k[6])<<16 | uint32(k[7])<<24
		c += uint32(k[8]) | uint32(k[9])<<8 | uint32(k[10])<<16 | uint32(k[11])<<24
		a, b, c = mix(a, b, c)
		length -= 12
		k = k[12:]
	}

	// Last partial block. Cases fall through.
	switch length {
	case 12:
		c += uint32(k[11]) << 24
		fallthrough
	case 11:
		c += uint32(k[10]) << 16
		fallthrough
	case 10:
		c += uint32(k[9]) << 8
		fallthrough
	case 9:
		c += uint32(k[8])
		fallthrough
	case 8:
		b += uint32(k[7]) << 24
		fallthrough
	case 7:
		b += uint32(k[6]) << 16
		fallthrough
	case 6:
		b += uint32(k[5]) << 8
		fallthrough
	case 5:
		b += uint32(k[4])
		fallthrough
	case 4:
		a += uint32(k[3]) << 24
		fallthrough
	case 3:
		a += uint32(k[2]) << 16
		fallthrough
	case 2:
		a += uint32(k[1]) << 8
		fallthrough
	case 1:
		a += uint32(k[0])
	case 0:
		return c
	}

	_, c = final(a, b, c)

	return c
}

// HashLittle2 returns two 32-bit hash values. Equivalent to hashlittle2() in
// lookup3.c. initpc is the primary initval, initpb is the secondary. The
// returned pair is (pc, pb).
func HashLittle2(key []byte, initpc, initpb uint32) (uint32, uint32) {
	length := uint32(len(key))
	a := 0xdeadbeef + length + initpc
	b := a
	c := a + initpb

	k := key
	for length > 12 {
		a += uint32(k[0]) | uint32(k[1])<<8 | uint32(k[2])<<16 | uint32(k[3])<<24
		b += uint32(k[4]) | uint32(k[5])<<8 | uint32(k[6])<<16 | uint32(k[7])<<24
		c += uint32(k[8]) | uint32(k[9])<<8 | uint32(k[10])<<16 | uint32(k[11])<<24
		a, b, c = mix(a, b, c)
		length -= 12
		k = k[12:]
	}

	switch length {
	case 12:
		c += uint32(k[11]) << 24
		fallthrough
	case 11:
		c += uint32(k[10]) << 16
		fallthrough
	case 10:
		c += uint32(k[9]) << 8
		fallthrough
	case 9:
		c += uint32(k[8])
		fallthrough
	case 8:
		b += uint32(k[7]) << 24
		fallthrough
	case 7:
		b += uint32(k[6]) << 16
		fallthrough
	case 6:
		b += uint32(k[5]) << 8
		fallthrough
	case 5:
		b += uint32(k[4])
		fallthrough
	case 4:
		a += uint32(k[3]) << 24
		fallthrough
	case 3:
		a += uint32(k[2]) << 16
		fallthrough
	case 2:
		a += uint32(k[1]) << 8
		fallthrough
	case 1:
		a += uint32(k[0])
	case 0:
		return c, b
	}

	b, c = final(a, b, c)

	return c, b
}

// HashFileName computes the WoW-compatible 64-bit Jenkins hash of a filename.
// CascLib normalizes file names (uppercase, '/' -> '\\') before hashing. The
// caller is expected to have done that — this helper does not normalize.
func HashFileName(name []byte) uint64 {
	pc, pb := HashLittle2(name, 0, 0)
	return uint64(pc) | uint64(pb)<<32
}
