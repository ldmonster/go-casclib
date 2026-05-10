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
	"fmt"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/compress"
)

// EncodeMode selects the per-frame transform applied by Encode.
type EncodeMode byte

const (
	// EncodeRaw emits 'N' (raw, no transform) frames. Always available.
	EncodeRaw EncodeMode = 'N'
	// EncodeZlib emits 'Z' (zlib) frames. Falls back to raw on a per-frame
	// basis if the compressed payload would be larger than the raw bytes.
	EncodeZlib EncodeMode = 'Z'
)

// EncodeOptions controls Encode.
type EncodeOptions struct {
	// Mode is the per-frame transform. Zero value defaults to EncodeZlib.
	Mode EncodeMode
	// FrameSize bounds the maximum content bytes per frame. Zero defaults to
	// 256 KiB which matches the most common upstream choice.
	FrameSize int
	// SingleFrameNoHeader, if true and the input fits in a single frame,
	// emits the legacy "no per-frame header" form (HeaderSize=0). Useful for
	// reproducing certain CDN-style spans. Defaults to false.
	SingleFrameNoHeader bool
}

const defaultFrameSize = 256 * 1024

// Encode compresses content into a BLTE stream and returns the bytes,
// the file's CKey (MD5 of the original content) and EKey (MD5 of the
// produced BLTE bytes).
//
// The output begins with the 'BLTE' signature; it does NOT include the
// outer 30-byte BLTE_ENCODED_HEADER (that is added by archive.WriteSpan).
func Encode(content []byte, opts EncodeOptions) ([]byte, [16]byte, [16]byte, error) {
	var ckey, ekey [16]byte

	if opts.FrameSize <= 0 {
		opts.FrameSize = defaultFrameSize
	}

	if opts.Mode == 0 {
		opts.Mode = EncodeZlib
	}

	if opts.Mode != EncodeRaw && opts.Mode != EncodeZlib {
		return nil, ckey, ekey, fmt.Errorf(
			"%w: encode mode %q",
			casc.ErrNotSupported, byte(opts.Mode),
		)
	}

	ckey = md5.Sum(content)

	// Single-frame "no header" form: HeaderSize=0; payload is the frame
	// bytes (mode byte + body) directly after the 8-byte fixed prefix.
	if opts.SingleFrameNoHeader {
		body, err := encodeFrame(opts.Mode, content)
		if err != nil {
			return nil, ckey, ekey, err
		}

		out := make([]byte, 8+len(body))
		binary.LittleEndian.PutUint32(out[0:4], casc.BLTESignature)
		// HeaderSize = 0 (big-endian).
		out[4], out[5], out[6], out[7] = 0, 0, 0, 0
		copy(out[8:], body)

		ekey = md5.Sum(out)

		return out, ckey, ekey, nil
	}

	// Multi-frame form. Split content into chunks of FrameSize, encode each.
	type encFrame struct {
		body        []byte // mode byte + transformed payload
		contentSize uint32
		hash        [16]byte
	}

	var chunks [][]byte

	if len(content) == 0 {
		// Always at least one frame, even for empty input.
		chunks = [][]byte{{}}
	} else {
		for off := 0; off < len(content); off += opts.FrameSize {
			end := off + opts.FrameSize
			if end > len(content) {
				end = len(content)
			}

			chunks = append(chunks, content[off:end])
		}
	}

	frames := make([]encFrame, len(chunks))
	for i, c := range chunks {
		body, err := encodeFrame(opts.Mode, c)
		if err != nil {
			return nil, ckey, ekey, err
		}

		frames[i] = encFrame{
			body:        body,
			contentSize: uint32(len(c)),
			hash:        md5.Sum(body),
		}
	}

	const frameEntrySize = 4 + 4 + 16

	headerSize := 12 + len(frames)*frameEntrySize

	totalSize := headerSize
	for _, f := range frames {
		totalSize += len(f.body)
	}

	out := make([]byte, totalSize)
	binary.LittleEndian.PutUint32(out[0:4], casc.BLTESignature)
	// HeaderSize is big-endian.
	out[4] = byte(headerSize >> 24)
	out[5] = byte(headerSize >> 16)
	out[6] = byte(headerSize >> 8)
	out[7] = byte(headerSize)
	out[8] = 0x0F
	// FrameCount is big-endian, 24 bits.
	out[9] = byte(len(frames) >> 16)
	out[10] = byte(len(frames) >> 8)
	out[11] = byte(len(frames))

	tableOff := 12

	for i, f := range frames {
		entry := out[tableOff+i*frameEntrySize:]
		entry[0] = byte(len(f.body) >> 24)
		entry[1] = byte(len(f.body) >> 16)
		entry[2] = byte(len(f.body) >> 8)
		entry[3] = byte(len(f.body))
		entry[4] = byte(f.contentSize >> 24)
		entry[5] = byte(f.contentSize >> 16)
		entry[6] = byte(f.contentSize >> 8)
		entry[7] = byte(f.contentSize)
		copy(entry[8:24], f.hash[:])
	}

	cursor := headerSize
	for _, f := range frames {
		copy(out[cursor:], f.body)
		cursor += len(f.body)
	}

	ekey = md5.Sum(out)

	return out, ckey, ekey, nil
}

// encodeFrame returns the on-wire bytes for a single frame: mode byte
// followed by transformed payload. For mode 'Z' the returned mode may
// downgrade to 'N' if zlib would inflate the chunk.
func encodeFrame(mode EncodeMode, chunk []byte) ([]byte, error) {
	switch mode {
	case EncodeRaw:
		body := make([]byte, 1+len(chunk))
		body[0] = 'N'
		copy(body[1:], chunk)

		return body, nil

	case EncodeZlib:
		zb, err := compress.Deflate(chunk)
		if err != nil {
			return nil, fmt.Errorf("zlib deflate: %w", err)
		}

		// Per-frame fallback to raw if zlib would inflate.
		if len(zb) >= len(chunk) {
			body := make([]byte, 1+len(chunk))
			body[0] = 'N'
			copy(body[1:], chunk)

			return body, nil
		}

		body := make([]byte, 1+len(zb))
		body[0] = 'Z'
		copy(body[1:], zb)

		return body, nil

	default:
		return nil, fmt.Errorf("%w: frame mode %q", casc.ErrNotSupported, byte(mode))
	}
}
