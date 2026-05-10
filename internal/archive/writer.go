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

// Archive writer: append BLTE-encoded blobs into local data.NNN segment
// files, building the 30-byte BLTE_ENCODED_HEADER wrapper and producing
// the index.EKeyEntry that points back to the written span.
//
// C++ reference: VerifyHeaderSpan in CascReadFile.cpp and the
// BLTE_ENCODED_HEADER struct in CascStructs.h.

package archive

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/hashes"
	"github.com/ldmonster/go-casclib/internal/index"
)

// DefaultSegmentSize is the cap on the size of one data.NNN file. Real
// CASC archives use 1 GiB; smaller is fine for tests/tooling.
const DefaultSegmentSize uint64 = 0x40000000

// jenkinsInitval matches the value hashlittle is seeded with in
// CascReadFile.cpp::VerifyHeaderSpan.
const jenkinsInitval uint32 = 0x3D6BE971

// encodedOffsetTable mirrors table_16C57A8 in CascReadFile.cpp.
var encodedOffsetTable = [16]uint32{
	0x049396B8, 0x72A82A9B, 0xEE626CCA, 0x9917754F,
	0x15DE40B1, 0xF5A8A9B6, 0x421EAC7E, 0xA9D55C9A,
	0x317FD40C, 0x04FAF80D, 0x3D6BE971, 0x52933CFD,
	0x27F64B7D, 0xC6F5C11B, 0xD5757E3A, 0x6C388745,
}

// Writer appends BLTE spans into data.NNN segment files under dataDir.
//
// Segment 0 is opened/created lazily; once a write would exceed
// SegmentSize the writer rolls over to data.001, etc. Concurrent calls
// are serialised internally; callers do not need to lock externally.
type Writer struct {
	dataDir     string
	segmentSize uint64

	mu           sync.Mutex
	segmentIndex uint32
	segmentFile  *os.File
	segmentOffs  uint64
	closed       bool
}

// NewWriter creates a Writer rooted at dataDir. The directory is
// created if it does not exist. SegmentSize 0 selects DefaultSegmentSize.
func NewWriter(dataDir string, segmentSize uint64) (*Writer, error) {
	if segmentSize == 0 {
		segmentSize = DefaultSegmentSize
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dataDir, err)
	}

	return &Writer{
		dataDir:     dataDir,
		segmentSize: segmentSize,
	}, nil
}

// Close flushes and closes the current segment file (if any).
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.closed = true

	if w.segmentFile == nil {
		return nil
	}

	err := w.segmentFile.Close()
	w.segmentFile = nil

	return err
}

// SegmentSize returns the configured per-segment cap.
func (w *Writer) SegmentSize() uint64 { return w.segmentSize }

// WriteSpan appends a BLTE span (the bytes returned by datafile.Encode,
// starting with the 'BLTE' signature) to the current segment, prefixing
// it with a fully-formed BLTE_ENCODED_HEADER. ekey is the encoded-key
// MD5 of the BLTE bytes (also returned by datafile.Encode).
//
// The returned EKeyEntry can be inserted into a V1 .idx; in particular
// ArchiveOffs points at the start of the BLTE_ENCODED_HEADER and
// EncodedSize is sizeof(BLTE_ENCODED_HEADER) + len(blte).
func (w *Writer) WriteSpan(blte []byte, ekey [16]byte) (index.EKeyEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return index.EKeyEntry{}, fmt.Errorf("%w: writer closed", casc.ErrInvalidHandle)
	}

	if len(blte) < 8 {
		return index.EKeyEntry{}, fmt.Errorf("%w: empty BLTE span", casc.ErrBadFormat)
	}

	totalLen := uint64(EncodedHeaderSize + len(blte))
	if totalLen > w.segmentSize {
		return index.EKeyEntry{}, fmt.Errorf(
			"%w: span %d larger than segment size %d",
			casc.ErrNotSupported, totalLen, w.segmentSize,
		)
	}

	// Roll over to a fresh segment if this write would overflow.
	if w.segmentFile != nil && w.segmentOffs+totalLen > w.segmentSize {
		if err := w.segmentFile.Close(); err != nil {
			return index.EKeyEntry{}, err
		}

		w.segmentFile = nil
		w.segmentIndex++
		w.segmentOffs = 0
	}

	if w.segmentFile == nil {
		if err := w.openSegment(); err != nil {
			return index.EKeyEntry{}, err
		}
	}

	header := buildEncodedHeader(ekey, uint32(len(blte)), w.segmentOffs)

	if _, err := w.segmentFile.Write(header); err != nil {
		return index.EKeyEntry{}, err
	}

	if _, err := w.segmentFile.Write(blte); err != nil {
		return index.EKeyEntry{}, err
	}

	entry := index.EKeyEntry{
		ArchiveIndex: w.segmentIndex,
		ArchiveOffs:  uint32(w.segmentOffs),
		EncodedSize:  uint32(totalLen),
	}
	copy(entry.EKey[:], ekey[:])

	w.segmentOffs += totalLen

	return entry, nil
}

func (w *Writer) openSegment() error {
	name := fmt.Sprintf("data.%03d", w.segmentIndex)
	path := filepath.Join(w.dataDir, name)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}

	off, err := f.Seek(0, 2 /* io.SeekEnd */)
	if err != nil {
		f.Close()
		return fmt.Errorf("seek %s: %w", name, err)
	}

	w.segmentFile = f
	w.segmentOffs = uint64(off)

	return nil
}

// buildEncodedHeader constructs the 30-byte BLTE_ENCODED_HEADER preceding
// a BLTE span at headerOffset within data.NNN.
//
// Layout (CascStructs.h::BLTE_ENCODED_HEADER):
//
//	[ 0..16) EKey, byte-reversed
//	[16..20) EncodedSize (BLTE byte length, little-endian)
//	[20]     field_14 (0)
//	[21]     field_15 (0)
//	[22..26) JenkinsHash (hashlittle of bytes 0..22 with initval 0x3D6BE971)
//	[26..30) Checksum
func buildEncodedHeader(ekey [16]byte, blteSize uint32, headerOffset uint64) []byte {
	hdr := make([]byte, EncodedHeaderSize)

	// Byte-reversed EKey.
	for i := 0; i < 16; i++ {
		hdr[i] = ekey[15-i]
	}

	binary.LittleEndian.PutUint32(hdr[16:20], blteSize)
	hdr[20] = 0 // field_14
	hdr[21] = 0 // field_15

	jh := hashes.HashLittle(hdr[:22], jenkinsInitval)
	binary.LittleEndian.PutUint32(hdr[22:26], jh)

	// Checksum: see VerifyHeaderSpan.
	signatureOffset := uint32(headerOffset) + EncodedHeaderSize

	encodedOffset := encodedOffsetTable[signatureOffset&0x0F] ^ signatureOffset

	var encodedOffsetBytes [4]byte

	binary.LittleEndian.PutUint32(encodedOffsetBytes[:], encodedOffset)

	var hashed [4]byte
	for i := 0; i < 26; i++ {
		hashed[i&3] ^= hdr[i]
	}

	for j := 0; j < 4; j++ {
		i := 26 + j
		hdr[i] = hashed[i&3] ^ encodedOffsetBytes[i&3]
	}

	return hdr
}
