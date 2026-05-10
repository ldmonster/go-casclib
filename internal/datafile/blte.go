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
	"errors"
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/compress"
)

// Frame is one decoded BLTE frame descriptor (without raw payload).
type Frame struct {
	Index       int
	EncodedSize uint32
	ContentSize uint32
	FrameHash   [16]byte // MD5 of encoded frame; zero if absent
}

// Header is a parsed BLTE header.
type Header struct {
	HeaderSize uint32
	FrameCount uint32
	Frames     []Frame
	DataOffset int // offset within input where frame payloads begin
}

// ParseHeader parses a BLTE header (NOT the encoded-header span).
// Input must start with the 4-byte 'BLTE' signature.
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < 8 {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint32(data[0:4]) != casc.BLTESignature {
		return nil, casc.ErrBadFormat
	}

	headerSize := casc.BEUint32(data[4:8])

	if headerSize == 0 {
		// Single frame, no per-frame header. Caller must know the encoded
		// and content sizes from outside (CKey entry).
		return &Header{
			HeaderSize: 0,
			FrameCount: 1,
			Frames:     []Frame{{Index: 0}},
			DataOffset: 8,
		}, nil
	}

	// A multi-frame header must include at least the 12-byte fixed prefix
	// (4 magic + 4 size + 1 flags + 3 frame-count) before any frame entries.
	if headerSize < 12 || len(data) < int(headerSize) {
		return nil, casc.ErrBadFormat
	}

	if data[8] != 0x0F {
		return nil, casc.ErrBadFormat
	}

	frameCount := casc.BEUint24(data[9:12])

	const frameHdrSize = 4 + 4 + 16 // EncodedSize + ContentSize + FrameHash

	frameTableOff := 12
	if frameTableOff+int(frameCount)*frameHdrSize > int(headerSize) {
		return nil, casc.ErrBadFormat
	}

	frames := make([]Frame, frameCount)
	for i := uint32(0); i < frameCount; i++ {
		off := frameTableOff + int(i)*frameHdrSize
		f := &frames[i]
		f.Index = int(i)
		f.EncodedSize = casc.BEUint32(data[off : off+4])
		f.ContentSize = casc.BEUint32(data[off+4 : off+8])
		copy(f.FrameHash[:], data[off+8:off+24])
	}

	return &Header{
		HeaderSize: headerSize,
		FrameCount: frameCount,
		Frames:     frames,
		DataOffset: int(headerSize),
	}, nil
}

// FrameDecoder decodes one BLTE frame's payload (without the leading mode byte
// stripped by the caller's switch). It currently supports modes:
//
//	'N' raw
//	'Z' zlib-deflate
//	'E' encrypted (delegated via Decrypter callback)
//	'F' recursive frames (not supported)
//
// frameIndex is required for stream-cipher decryption (Salsa20 nonce).
type FrameDecoder struct {
	// Decrypt, if non-nil, is invoked when an 'E' mode frame is encountered.
	// It must return plaintext that itself starts with another mode byte.
	Decrypt func(in []byte, frameIndex int) ([]byte, error)

	// VerifyHashes enables MD5 verification against Frame.FrameHash.
	VerifyHashes bool

	// OvercomeEncrypted mirrors CascLib's CASC_OVERCOME_ENCRYPTED option:
	// when an 'E' frame's key is missing (Decrypt returns ErrEncrypted, or
	// is nil), substitute a zero-filled buffer of length ContentSize and
	// return success. Useful for partial extraction at the cost of corrupt
	// output for the affected blocks.
	OvercomeEncrypted bool
}

// Decode returns the decoded payload for frame fr. encoded is the raw frame
// bytes including the leading mode byte.
func (d *FrameDecoder) Decode(fr Frame, encoded []byte) ([]byte, error) {
	if d.VerifyHashes && fr.FrameHash != ([16]byte{}) {
		if md5.Sum(encoded) != fr.FrameHash {
			return nil, casc.ErrFileCorrupt
		}
	}

	return d.decodeStep(fr, encoded, 0)
}

func (d *FrameDecoder) decodeStep(fr Frame, encoded []byte, depth int) ([]byte, error) {
	if depth > 4 {
		return nil, fmt.Errorf("%w: too many BLTE frame transforms", casc.ErrFileCorrupt)
	}

	if len(encoded) == 0 {
		return nil, casc.ErrBadFormat
	}

	mode := encoded[0]
	body := encoded[1:]

	switch mode {
	case 'N':
		out := make([]byte, len(body))
		copy(out, body)

		return out, nil

	case 'Z':
		expected := int(fr.ContentSize)

		out, err := decompressZ(body, expected)
		if err != nil {
			return nil, err
		}
		// If decompressor produced fewer bytes than the declared content size,
		// pad with zeros (matches CascLib behavior for INSTALL files).
		if expected > 0 && len(out) < expected {
			padded := make([]byte, expected)
			copy(padded, out)
			out = padded
		}

		return out, nil

	case 'E':
		if d.Decrypt == nil {
			if d.OvercomeEncrypted {
				return zeroFrame(fr), nil
			}

			return nil, casc.ErrEncrypted
		}

		decrypted, err := d.Decrypt(body, fr.Index)
		if err != nil {
			if d.OvercomeEncrypted && errors.Is(err, casc.ErrEncrypted) {
				return zeroFrame(fr), nil
			}

			return nil, err
		}
		// After decryption, the result is itself a (mode-prefixed) frame.
		return d.decodeStep(fr, decrypted, depth+1)

	case 'F':
		return nil, fmt.Errorf("%w: recursive BLTE frames", casc.ErrNotSupported)

	default:
		return nil, fmt.Errorf("%w: unknown BLTE frame mode %q", casc.ErrNotSupported, mode)
	}
}

// decompressZ handles BLTE 'Z' frame bodies. The current CASC format always
// uses zlib for 'Z' frames. Older game builds (pre-2014) occasionally used
// bzip2, identifiable by the 'BZ' magic at the start of the body. As a
// forward-compatible fallback the dispatcher also detects LZMA1/XZ
// prefixes — these only succeed when a decoder has been installed via
// compress.SetLZMADecoder.
func decompressZ(body []byte, expected int) ([]byte, error) {
	if len(body) >= 2 && body[0] == 0x42 && body[1] == 0x5A { // 'BZ'
		return compress.Unbzip2(body, expected)
	}

	if compress.LZMARegistered() && compress.LooksLikeLZMA(body) {
		return compress.Unlzma(body, expected)
	}

	return compress.Inflate(body, expected)
}

// zeroFrame returns a zero-filled buffer matching the frame's declared
// content size. Used by OvercomeEncrypted to substitute missing-key
// frames.
func zeroFrame(fr Frame) []byte {
	return make([]byte, fr.ContentSize)
}
