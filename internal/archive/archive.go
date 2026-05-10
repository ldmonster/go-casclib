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

// Package archive turns one parsed index.EKeyEntry into decoded file bytes
// by reading from the local data.NNN files and running the BLTE pipeline.
//
// C++ reference: CascReadFile.cpp -- OpenDataStream + LoadEncodedHeaderAndSpanFrames.
package archive

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/datafile"
	"github.com/ldmonster/go-casclib/internal/decrypt"
	"github.com/ldmonster/go-casclib/internal/index"
)

// EncodedHeaderSize is the size of BLTE_ENCODED_HEADER (the wrapper that
// precedes the actual BLTE signature inside data.NNN segments).
//
//	[16] EKey (byte-reversed)
//	[ 4] EncodedSize (little endian)
//	[ 1] field_14
//	[ 1] field_15 (zero)
//	[ 4] JenkinsHash (little endian)
//	[ 4] Checksum
const EncodedHeaderSize = 30

// Pool caches open data file handles, one per archive index.
//
// dataDir is the directory that contains "data.000", "data.001", ...
// (typically <install>/Data/data on a local CASC storage).
//
// Pool is goroutine-safe.
type Pool struct {
	dataDir string

	mu    sync.Mutex
	files map[uint32]*os.File
}

// NewPool creates a new pool rooted at dataDir.
func NewPool(dataDir string) *Pool {
	return &Pool{
		dataDir: dataDir,
		files:   make(map[uint32]*os.File),
	}
}

// Close releases all open file handles.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var firstErr error
	for _, f := range p.files {
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	p.files = nil

	return firstErr
}

// open returns the (cached) handle for data.NNN.
func (p *Pool) open(archiveIndex uint32) (*os.File, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.files == nil {
		return nil, fmt.Errorf("%w: pool closed", casc.ErrInvalidHandle)
	}

	if f, ok := p.files[archiveIndex]; ok {
		return f, nil
	}

	name := fmt.Sprintf("data.%03d", archiveIndex)

	f, err := os.Open(filepath.Join(p.dataDir, name))
	if err != nil {
		return nil, err
	}

	p.files[archiveIndex] = f

	return f, nil
}

// ReadSpan reads and BLTE-decodes the span described by entry.
//
// keys may be nil if the file is not encrypted; an unknown-key encrypted
// frame surfaces as casc.ErrEncrypted.
func (p *Pool) ReadSpan(entry index.EKeyEntry, keys *decrypt.KeyRegistry) ([]byte, error) {
	return p.ReadSpanWithOptions(entry, keys, DecodeOptions{})
}

// ReadSpanWithOptions reads and decodes a span like ReadSpan but lets the
// caller toggle BLTE-pipeline knobs (e.g. CASC_OVERCOME_ENCRYPTED).
func (p *Pool) ReadSpanWithOptions(
	entry index.EKeyEntry,
	keys *decrypt.KeyRegistry,
	opts DecodeOptions,
) ([]byte, error) {
	f, err := p.open(entry.ArchiveIndex)
	if err != nil {
		return nil, err
	}

	if entry.EncodedSize < EncodedHeaderSize {
		return nil, fmt.Errorf(
			"%w: encoded size %d too small",
			casc.ErrBadFormat,
			entry.EncodedSize,
		)
	}

	buf := make([]byte, entry.EncodedSize)
	if _, err := f.ReadAt(buf, int64(entry.ArchiveOffs)); err != nil {
		return nil, fmt.Errorf("read data.%03d @%d: %w", entry.ArchiveIndex, entry.ArchiveOffs, err)
	}

	return DecodeSpanWithOptions(buf, keys, opts)
}

// DecodeSpan decodes a raw span (BLTE_ENCODED_HEADER + BLTE_HEADER + frames).
//
// It is exported so callers operating on in-memory blobs (tests, CDN
// pre-fetched bytes) can reuse the same pipeline as ReadSpan.
//
// span may also be a bare BLTE stream (no encoded header) -- if the first
// 4 bytes are 'BLTE' the encoded header is skipped.
func DecodeSpan(span []byte, keys *decrypt.KeyRegistry) ([]byte, error) {
	return DecodeSpanWithOptions(span, keys, DecodeOptions{})
}

// DecodeOptions controls DecodeSpanWithOptions behaviour.
type DecodeOptions struct {
	// OvercomeEncrypted mirrors CascLib's CASC_OVERCOME_ENCRYPTED: when
	// set, encrypted frames whose key is missing are replaced with
	// zero-filled buffers and the overall decode succeeds.
	OvercomeEncrypted bool
}

// DecodeSpanWithOptions is DecodeSpan with caller-supplied options.
func DecodeSpanWithOptions(
	span []byte,
	keys *decrypt.KeyRegistry,
	opts DecodeOptions,
) ([]byte, error) {
	body, err := stripEncodedHeader(span)
	if err != nil {
		return nil, err
	}

	hdr, err := datafile.ParseHeader(body)
	if err != nil {
		return nil, err
	}

	dec := &datafile.FrameDecoder{
		VerifyHashes:      true,
		OvercomeEncrypted: opts.OvercomeEncrypted,
	}
	if keys != nil {
		dec.Decrypt = func(in []byte, frameIndex int) ([]byte, error) {
			return keys.DecryptFrame(in, frameIndex)
		}
	}

	// If frame count == 1 and HeaderSize == 0, the single frame consumes the
	// rest of body unprefixed by a per-frame entry.
	if hdr.HeaderSize == 0 {
		fr := hdr.Frames[0]
		fr.EncodedSize = uint32(len(body) - hdr.DataOffset)
		// ContentSize unknown; let the decoder tolerate (zlib output not padded).
		return dec.Decode(fr, body[hdr.DataOffset:])
	}

	out := make([]byte, 0, totalContentSize(hdr.Frames))

	cursor := hdr.DataOffset
	for _, fr := range hdr.Frames {
		end := cursor + int(fr.EncodedSize)
		if end > len(body) {
			return nil, fmt.Errorf("%w: frame %d out of bounds", casc.ErrFileCorrupt, fr.Index)
		}

		decoded, err := dec.Decode(fr, body[cursor:end])
		if err != nil {
			return nil, err
		}

		out = append(out, decoded...)
		cursor = end
	}

	return out, nil
}

// stripEncodedHeader removes the BLTE_ENCODED_HEADER wrapper if present,
// returning a slice that begins with the BLTE signature.
func stripEncodedHeader(span []byte) ([]byte, error) {
	if len(span) < 4 {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint32(span[:4]) == casc.BLTESignature {
		return span, nil
	}

	if len(span) < EncodedHeaderSize+4 {
		return nil, casc.ErrBadFormat
	}

	if binary.LittleEndian.Uint32(
		span[EncodedHeaderSize:EncodedHeaderSize+4],
	) != casc.BLTESignature {
		return nil, fmt.Errorf("%w: BLTE signature missing after encoded header", casc.ErrBadFormat)
	}

	return span[EncodedHeaderSize:], nil
}

func totalContentSize(frames []datafile.Frame) int {
	total := 0
	for _, f := range frames {
		total += int(f.ContentSize)
	}

	return total
}

// ReadStream is a low-level helper that reads exactly n bytes at offset off
// from data.archiveIndex. Exposed for tests/diagnostics.
func (p *Pool) ReadStream(archiveIndex, off, n uint32) ([]byte, error) {
	f, err := p.open(archiveIndex)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, int64(off)); err != nil {
		if err == io.EOF {
			return nil, casc.ErrEndOfFile
		}

		return nil, err
	}

	return buf, nil
}
