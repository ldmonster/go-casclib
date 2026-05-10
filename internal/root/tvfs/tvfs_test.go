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

package tvfs

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// putBE32 writes a big-endian uint32 into b at offset.
func putBE32(b []byte, off int, v uint32) {
	binary.BigEndian.PutUint32(b[off:off+4], v)
}

// buildMinimalTVFS constructs a minimal TVFS with two top-level files:
//
//	"hello" -> EKey0xAA, ContentSize=11
//	"world" -> EKey0xBB, ContentSize=22
//
// Returns the bytes plus the two expected EKeys.
func buildMinimalTVFS(t *testing.T) ([]byte, [9]byte, [9]byte) {
	t.Helper()

	// CFT: two 9-byte EKeys.
	var ek1, ek2 [9]byte
	for i := 0; i < 9; i++ {
		ek1[i] = 0xA0 + byte(i)
		ek2[i] = 0xB0 + byte(i)
	}
	cft := append(append([]byte{}, ek1[:]...), ek2[:]...)
	// Index for ek1 = 0 within CFT, ek2 = 9.

	// VFS: two single-span entries.
	// Each entry layout: spanCount(1) + offset(4 BE) + contentSize(4 BE) + cftOff(1 byte, since CFT is small)
	makeVfsEntry := func(contentSize uint32, cftOff byte) []byte {
		var e bytes.Buffer
		e.WriteByte(1)  // span count
		var off [4]byte // BE file offset (zero)
		e.Write(off[:]) // file offset = 0
		var sz [4]byte
		binary.BigEndian.PutUint32(sz[:], contentSize)
		e.Write(sz[:])
		e.WriteByte(cftOff)
		return e.Bytes()
	}
	vfsHello := makeVfsEntry(11, 0)
	vfsWorld := makeVfsEntry(22, 9)
	vfsHelloOff := uint32(0)
	vfsWorldOff := uint32(len(vfsHello))
	vfs := append(append([]byte{}, vfsHello...), vfsWorld...)

	// Path table:
	//   0xFF + folderNodeValue (length-of-rest including those 4 bytes)
	//   then for each file:
	//     <nameLen><name>0xFF<nodevalue BE>
	makeFileEntry := func(name string, vfsOff uint32) []byte {
		buf := []byte{byte(len(name))}
		buf = append(buf, name...)
		buf = append(buf, 0xFF)
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], vfsOff)
		buf = append(buf, v[:]...)
		return buf
	}
	body := append(makeFileEntry("hello", vfsHelloOff),
		makeFileEntry("world", vfsWorldOff)...)
	// Wrap with root folder marker.
	pathTable := []byte{0xFF}
	folderSize := uint32(4 + len(body)) // includes the 4-byte NodeValue itself
	var nv [4]byte
	binary.BigEndian.PutUint32(nv[:], folderNodeBit|folderSize)
	pathTable = append(pathTable, nv[:]...)
	pathTable = append(pathTable, body...)

	// Header: 38 bytes.
	hdr := make([]byte, 38)
	binary.LittleEndian.PutUint32(hdr[0:4], tvfsMagic)
	hdr[4] = 1                                  // FormatVersion
	hdr[5] = 38                                 // HeaderSize
	hdr[6] = 9                                  // EKeySize
	hdr[7] = 9                                  // PatchKeySize
	binary.LittleEndian.PutUint32(hdr[8:12], 0) // Flags

	// We now know table sizes so place sequentially after header.
	pathOff := uint32(38)
	pathSize := uint32(len(pathTable))
	vfsOff := pathOff + pathSize
	vfsSize := uint32(len(vfs))
	cftOff := vfsOff + vfsSize
	cftSize := uint32(len(cft))

	putBE32(hdr, 12, pathOff)
	putBE32(hdr, 16, pathSize)
	putBE32(hdr, 20, vfsOff)
	putBE32(hdr, 24, vfsSize)
	putBE32(hdr, 28, cftOff)
	putBE32(hdr, 32, cftSize)
	binary.BigEndian.PutUint16(hdr[36:38], 0) // MaxDepth

	out := make([]byte, 0, int(cftOff)+len(cft))
	out = append(out, hdr...)
	out = append(out, pathTable...)
	out = append(out, vfs...)
	out = append(out, cft...)
	return out, ek1, ek2
}

func TestTVFSParse(t *testing.T) {
	data, ek1, ek2 := buildMinimalTVFS(t)
	h, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := h.LookupByName("hello"); got == nil {
		t.Fatal("hello not found")
	} else {
		if got.ContentSize != 11 {
			t.Errorf("hello content size = %d", got.ContentSize)
		}
		var want casc.EKey
		copy(want[:9], ek1[:])
		if got.EKey != want {
			t.Errorf("hello EKey mismatch: got %x", got.EKey)
		}
	}
	if got := h.LookupByName("world"); got == nil {
		t.Fatal("world not found")
	} else {
		if got.ContentSize != 22 {
			t.Errorf("world content size = %d", got.ContentSize)
		}
		var want casc.EKey
		copy(want[:9], ek2[:])
		if got.EKey != want {
			t.Errorf("world EKey mismatch: got %x", got.EKey)
		}
	}
	if h.LookupByName("missing") != nil {
		t.Errorf("missing should be nil")
	}

	// Iterate via All; expect both entries.
	count := 0
	h.All(func(name string, e *casc.CKeyEntry) bool {
		count++
		return true
	})
	if count != 2 {
		t.Errorf("All count = %d, want 2", count)
	}
}

func TestTVFSProbeWrongMagic(t *testing.T) {
	if _, err := Probe([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected error for wrong magic")
	}
}
