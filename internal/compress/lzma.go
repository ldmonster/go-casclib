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

package compress

import (
	"errors"
	"fmt"
)

// ErrLZMAUnsupported is returned by Unlzma when no LZMA decoder is
// registered.
//
// LZMA is intentionally not a top-level BLTE frame type in upstream
// CascLib — its dispatcher only handles 'E' (encrypted), 'Z' (zlib),
// 'N' (none) and 'F' (recursive, also unimplemented). The hook is kept
// for two reasons:
//
//  1. Future Blizzard data could embed LZMA-prefixed payload inside a
//     'Z' frame, mirroring the way bzip2 ('BZh' magic) is detected today.
//  2. A side-package can register a pure-Go LZMA decoder via
//     SetLZMADecoder without changing the BLTE pipeline.
var ErrLZMAUnsupported = errors.New("compress: LZMA decompression not registered")

// LZMADecoder decompresses an LZMA1 or XZ stream. Returning fewer bytes
// than expected is permitted; the BLTE pipeline zero-pads to the frame
// size.
type LZMADecoder func(in []byte, expected int) ([]byte, error)

var lzmaDecoder LZMADecoder

// SetLZMADecoder installs (or, with nil, removes) the LZMA decoder.
// Intended to be called from init() of a side-package that vendors an
// implementation. Not safe for concurrent installation.
func SetLZMADecoder(d LZMADecoder) { lzmaDecoder = d }

// LZMARegistered reports whether a decoder has been installed.
func LZMARegistered() bool { return lzmaDecoder != nil }

// Unlzma decompresses an LZMA stream using the registered decoder, or
// returns ErrLZMAUnsupported when none is set.
func Unlzma(in []byte, expected int) ([]byte, error) {
	if lzmaDecoder == nil {
		return nil, ErrLZMAUnsupported
	}

	out, err := lzmaDecoder(in, expected)
	if err != nil {
		return nil, fmt.Errorf("compress: lzma: %w", err)
	}

	return out, nil
}

// LooksLikeLZMA reports whether the buffer prefix matches a plausible
// LZMA1 or XZ stream header.
//
//   - XZ:    [0xFD '7' 'z' 'X' 'Z' 0x00]
//   - LZMA1: properties byte (lc*45 + lp*9 + pb) < 225, followed by a
//     4-byte little-endian dictionary size in [4 KiB, 1 GiB].
func LooksLikeLZMA(b []byte) bool {
	if len(b) >= 6 && b[0] == 0xFD && b[1] == '7' && b[2] == 'z' && b[3] == 'X' && b[4] == 'Z' &&
		b[5] == 0x00 {
		return true
	}

	if len(b) >= 13 && uint(b[0]) < 5*9*9 {
		dict := uint32(b[1]) | uint32(b[2])<<8 | uint32(b[3])<<16 | uint32(b[4])<<24
		if dict >= 4096 && dict <= 1<<30 {
			return true
		}
	}

	return false
}
