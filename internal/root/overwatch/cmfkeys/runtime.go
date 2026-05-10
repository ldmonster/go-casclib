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

// Runtime helpers used by the generated per-build Key/IV functions.
//
// Mirrors the semantics of the C++ helpers in
// CascLib/src/overwatch/cmf.cpp (Constrain, SignedMod) and provides the
// callback signatures the codegen targets.
//
// All generated bodies in keyfuncs_generated.go reference identifiers
// declared here.

package cmfkeys

import "github.com/ldmonster/go-casclib/internal/root/overwatch"

// sha1DigestSize matches the SHA1_DIGESTSIZE macro from CascLib.
const sha1DigestSize = 20

// constrain is the Go translation of CascLib's Constrain():
//
//	static uint Constrain(LONGLONG value) {
//	    return (uint)(value % 0xFFFFFFFFULL);
//	}
//
// Note: the C++ uses 0xFFFFFFFF (32-bit max), NOT 0x100000000, so this
// is a real (non-power-of-two) modulo on a 64-bit value.
func constrain(value int64) uint32 {
	const m = int64(0xFFFFFFFF)

	r := value % m
	if r < 0 {
		r += m
	}

	return uint32(r)
}

// signedMod mirrors CascLib's SignedMod(): truncate to int32, take the
// remainder, then wrap negatives back into [0, p2).
func signedMod(p1, p2 int64) int32 {
	a := int32(p1)
	b := int32(p2)
	r := a % b

	if r < 0 {
		return r + b
	}

	return r
}

// keyFunc is a per-build Key derivation function. It writes the key
// schedule into buffer[:length] using the supplied keytable.
type keyFunc func(hdr overwatch.CMFHeader, keytable *[512]byte, buffer []byte, length int)

// ivFunc is a per-build IV derivation function. It writes the IV
// schedule into buffer[:length] using the supplied keytable and the
// SHA-1 digest of the file's plain-name.
type ivFunc func(hdr overwatch.CMFHeader, keytable *[512]byte, digest [20]byte, buffer []byte, length int)

// nonEncryptedMagic is the Go equivalent of
// CASC_CMF_HEADER::GetNonEncryptedMagic().
func nonEncryptedMagic(hdr overwatch.CMFHeader) uint32 {
	return uint32(0x00666D63) | (uint32(hdr.Version()) << 24)
}
