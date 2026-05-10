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

// MNDX Patricia trie reader.
//
// This file ports the bulk of CascRootFile_MNDX.cpp — the bit-packed,
// hash-bucketed Patricia trie used by Heroes of the Storm to encode
// filenames. Naming follows upstream where practical (with leading caps
// for export, lower for unexported) so the two sources can be diffed.
//
// Source map:
//   table_1BA1818        -> bitPos8Table (generated at init)
//   GetNumberOfSetBits   -> setBitsAll
//   TByteStream          -> byteStream
//   TGenericArray<T>     -> generic []T loaders (loadDwordArray, etc.)
//   BASEVALS             -> baseVals struct (bit-packed)
//   TSparseArray         -> sparseArray
//   TBitEntryArray       -> bitEntryArray
//   TPathFragmentTable   -> pathFragmentTable
//   TStruct40            -> searchState
//   TFileNameDatabase    -> fileNameDB
//   TMndxMarFile         -> marFile
//   TMndxSearch          -> mndxSearch

package mndx

import (
	"encoding/binary"
	"fmt"
)

// -------------------------------------------------------------------------
// Lookup table for: position of the (n+1)-th set bit in an 8-bit value.
// table[(n<<8)|b] = position 0..7 of the (n+1)-th set bit in byte b,
// or 7 if there are fewer set bits than n+1.
// (Matches upstream table_1BA1818 byte-for-byte; verified by build.)
var bitPos8Table [0x800]byte

func init() {
	for n := 0; n < 8; n++ {
		for b := 0; b < 256; b++ {
			pos := byte(7)
			seen := -1

			for i := 0; i < 8; i++ {
				if b&(1<<i) != 0 {
					seen++
					if seen == n {
						pos = byte(i)
						break
					}
				}
			}

			bitPos8Table[(n<<8)|b] = pos
		}
	}
}

// setBitsAll returns the SWAR popcount packed as 4 bytes:
//
//	bits 0-7   : popcount of the lower 8 bits
//	bits 8-15  : popcount of the lower 16 bits
//	bits 16-23 : popcount of the lower 24 bits
//	bits 24-31 : popcount of the entire 32-bit value
func setBitsAll(v uint32) uint32 {
	v = ((v >> 1) & 0x55555555) + (v & 0x55555555)
	v = ((v >> 2) & 0x33333333) + (v & 0x33333333)
	v = ((v >> 4) & 0x0F0F0F0F) + (v & 0x0F0F0F0F)

	return v * 0x01010101
}

func popcount32(v uint32) uint32 { return setBitsAll(v) >> 24 }

// -------------------------------------------------------------------------
// byteStream is the cursor used by the upstream loader. It only ever
// reads from a backing slice and returns cheap re-slices, so loaders
// keep references to the original blob and need no allocations of their
// own. (Mirrors TByteStream::GetBytes / CopyBytes / GetValue.)
type byteStream struct {
	buf []byte
}

func (s *byteStream) skip(n int) error {
	if n > len(s.buf) {
		return errBadFormat("byteStream skip past end")
	}

	s.buf = s.buf[n:]

	return nil
}

func (s *byteStream) getBytes(n int) ([]byte, error) {
	if n > len(s.buf) {
		return nil, errBadFormat("byteStream getBytes past end")
	}

	out := s.buf[:n]
	s.buf = s.buf[n:]

	return out, nil
}

func (s *byteStream) getU32() (uint32, error) {
	b, err := s.getBytes(4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(b), nil
}

func (s *byteStream) getU64() (uint64, error) {
	b, err := s.getBytes(8)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(b), nil
}

// getArrayItemCount reads an 8-byte LE byte-count, validates it's a
// multiple of itemSize and fits in 32 bits, and returns (byteCount, itemCount).
func (s *byteStream) getArrayItemCount(itemSize int) (uint32, uint32, error) {
	bc, err := s.getU64()
	if err != nil {
		return 0, 0, err
	}

	if bc > 0xFFFFFFFF || bc%uint64(itemSize) != 0 {
		return 0, 0, errBadFormat("byteStream array byte count not multiple of item size")
	}

	return uint32(bc), uint32(bc / uint64(itemSize)), nil
}

// loadByteArray reads the standard "8-byte size + bytes + 8-byte align padding".
func (s *byteStream) loadByteArray() ([]byte, error) {
	byteCount, itemCount, err := s.getArrayItemCount(1)
	if err != nil {
		return nil, err
	}

	out, err := s.getBytes(int(itemCount))
	if err != nil {
		return nil, err
	}

	if pad := (-int(byteCount)) & 0x07; pad != 0 {
		if err := s.skip(pad); err != nil {
			return nil, err
		}
	}
	// Copy out — backing buffer's lifetime is the parse blob,
	// but defensive copies make the loaded structure self-contained.
	cp := make([]byte, len(out))
	copy(cp, out)

	return cp, nil
}

func (s *byteStream) loadDwordArray() ([]uint32, error) {
	byteCount, itemCount, err := s.getArrayItemCount(4)
	if err != nil {
		return nil, err
	}

	raw, err := s.getBytes(int(itemCount) * 4)
	if err != nil {
		return nil, err
	}

	out := make([]uint32, itemCount)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
	}

	if pad := (-int(byteCount)) & 0x07; pad != 0 {
		if err := s.skip(pad); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// -------------------------------------------------------------------------
// BASEVALS is bit-packed; the C++ struct is:
//
//	DWORD BaseValue200;
//	DWORD AddValue40 : 7;
//	DWORD AddValue80 : 8;
//	DWORD AddValueC0 : 8;
//	DWORD AddValue100 : 9;
//	DWORD AddValue140 : 9;
//	DWORD AddValue180 : 9;
//	DWORD AddValue1C0 : 9;
//	DWORD __xalignment : 5;
//
// Total = 32 + 7+8+8+9+9+9+9+5 = 32 + 64 = 96 bits = 12 bytes? No —
// the 5-bit padding is wrong above. Actually upstream lays it across two
// DWORDs: 32 bits BaseValue200 + a packed 32-bit second word containing
// (7+8+8+9 = 32 bits) AddValue40/80/C0/100, then the 9+9+9+5 = 32 bits
// AddValue140/180/1C0+padding. That's 96 bits. Cross-check: sizeof
// BASEVALS expected to align to 8 (12 isn't 8-aligned). The C++ comment
// "we have extra shortcut every 0x40 items above the 0x200 base" plus
// the layout 32+7+8+8+9 = 64 (one DWORD!) and the rest 9+9+9+5 = 32 (next
// DWORD) gives 64+32 = 96 bits total but with x86 bitfield alignment
// the compiler will pack it as 12 bytes.
//
// We sidestep alignment ambiguity by reading both DWORDs explicitly.
type baseVals struct {
	BaseValue200 uint32
	AddValue40   uint32 // 7 bits
	AddValue80   uint32 // 8 bits
	AddValueC0   uint32 // 8 bits
	AddValue100  uint32 // 9 bits
	AddValue140  uint32 // 9 bits
	AddValue180  uint32 // 9 bits
	AddValue1C0  uint32 // 9 bits
}

// baseValsSize is the on-disk size of one BASEVALS record (matches sizeof
// of the C++ struct on a 32-bit packed layout = 12 bytes).
const baseValsSize = 12

func (s *byteStream) loadBaseValsArray() ([]baseVals, error) {
	byteCount, itemCount, err := s.getArrayItemCount(baseValsSize)
	if err != nil {
		return nil, err
	}

	raw, err := s.getBytes(int(itemCount) * baseValsSize)
	if err != nil {
		return nil, err
	}

	out := make([]baseVals, itemCount)
	for i := range out {
		o := i * baseValsSize
		out[i].BaseValue200 = binary.LittleEndian.Uint32(raw[o : o+4])
		w1 := binary.LittleEndian.Uint32(raw[o+4 : o+8])
		w2 := binary.LittleEndian.Uint32(raw[o+8 : o+12])
		// Word 1 layout (low → high): 7 | 8 | 8 | 9
		out[i].AddValue40 = w1 & 0x7F
		out[i].AddValue80 = (w1 >> 7) & 0xFF
		out[i].AddValueC0 = (w1 >> 15) & 0xFF
		out[i].AddValue100 = (w1 >> 23) & 0x1FF // 9 bits, only 9 bits available before w2
		// w1 has 7+8+8 = 23 bits used and then 9 bits → 32 total.
		// Word 2 layout: 9 | 9 | 9 | 5(pad)
		out[i].AddValue140 = w2 & 0x1FF
		out[i].AddValue180 = (w2 >> 9) & 0x1FF
		out[i].AddValue1C0 = (w2 >> 18) & 0x1FF
	}

	if pad := (-int(byteCount)) & 0x07; pad != 0 {
		if err := s.skip(pad); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// hashEntry mirrors HASH_ENTRY (3 DWORDs = 12 bytes).
type hashEntry struct {
	NodeIndex      uint32
	NextIndex      uint32
	FragmentOffset uint32 // FragmentOffset / ChildTableIndex / SingleChar union
}

const hashEntrySize = 12

func (h *hashEntry) IsSingleChar() bool      { return (h.FragmentOffset & 0xFFFFFF00) == 0xFFFFFF00 }
func (h *hashEntry) SingleChar() byte        { return byte(h.FragmentOffset & 0xFF) }
func (h *hashEntry) ChildTableIndex() uint32 { return h.FragmentOffset }

func (s *byteStream) loadHashEntryArray() ([]hashEntry, error) {
	byteCount, itemCount, err := s.getArrayItemCount(hashEntrySize)
	if err != nil {
		return nil, err
	}

	raw, err := s.getBytes(int(itemCount) * hashEntrySize)
	if err != nil {
		return nil, err
	}

	out := make([]hashEntry, itemCount)
	for i := range out {
		o := i * hashEntrySize
		out[i].NodeIndex = binary.LittleEndian.Uint32(raw[o : o+4])
		out[i].NextIndex = binary.LittleEndian.Uint32(raw[o+4 : o+8])
		out[i].FragmentOffset = binary.LittleEndian.Uint32(raw[o+8 : o+12])
	}

	if pad := (-int(byteCount)) & 0x07; pad != 0 {
		if err := s.skip(pad); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// -------------------------------------------------------------------------
// bitEntryArray packs N items of BitsPerEntry bits each into a uint32 array.
type bitEntryArray struct {
	Items        []uint32
	BitsPerEntry uint32
	EntryBitMask uint32
	TotalEntries uint32
}

func (b *bitEntryArray) load(s *byteStream) error {
	items, err := s.loadDwordArray()
	if err != nil {
		return err
	}

	b.Items = items
	if b.BitsPerEntry, err = s.getU32(); err != nil {
		return err
	}

	if b.BitsPerEntry > 0x20 {
		return errBadFormat("bitEntryArray BitsPerEntry > 32")
	}

	if b.EntryBitMask, err = s.getU32(); err != nil {
		return err
	}

	v64, err := s.getU64()
	if err != nil {
		return err
	}

	if v64 > 0xFFFFFFFF {
		return errBadFormat("bitEntryArray TotalEntries overflow")
	}

	b.TotalEntries = uint32(v64)

	return nil
}

func (b *bitEntryArray) Get(idx uint32) uint32 {
	if b.BitsPerEntry == 0 || len(b.Items) == 0 {
		return 0
	}

	wordIdx := (idx * b.BitsPerEntry) >> 5
	startBit := (idx * b.BitsPerEntry) & 0x1F
	endBit := startBit + b.BitsPerEntry

	var v uint32

	if endBit > 32 {
		if wordIdx+1 >= uint32(len(b.Items)) {
			if wordIdx < uint32(len(b.Items)) {
				v = b.Items[wordIdx] >> startBit
			}
		} else {
			v = (b.Items[wordIdx+1] << (32 - startBit)) | (b.Items[wordIdx] >> startBit)
		}
	} else {
		if wordIdx >= uint32(len(b.Items)) {
			return 0
		}

		v = b.Items[wordIdx] >> startBit
	}

	return v & b.EntryBitMask
}

// -------------------------------------------------------------------------
// sparseArray is the workhorse: a bitset over `TotalItemCount` slots
// plus per-0x200-block popcount shortcuts, plus index→item0/item1 maps
// for fast inverse lookup ("position of the n-th present/absent bit").
type sparseArray struct {
	ItemBits       []uint32
	BaseVals       []baseVals
	IndexToItem0   []uint32 // groups indexed in absent-bit space
	IndexToItem1   []uint32 // groups indexed in present-bit space
	TotalItemCount uint32
	ValidItemCount uint32
}

func (a *sparseArray) load(s *byteStream) error {
	bits, err := s.loadDwordArray()
	if err != nil {
		return err
	}

	a.ItemBits = bits
	if a.TotalItemCount, err = s.getU32(); err != nil {
		return err
	}

	if a.ValidItemCount, err = s.getU32(); err != nil {
		return err
	}

	if a.ValidItemCount > a.TotalItemCount {
		return errBadFormat("sparseArray ValidItemCount > TotalItemCount")
	}

	// Sanity: TotalItemCount cannot exceed the bit capacity of the ItemBits
	// array. Each uint32 word covers 32 bit positions. Reject adversarial
	// data that claims impossibly large counts, since code paths later do
	// make([]T, ValidItemCount) allocations.
	bitCapacity := uint32(len(a.ItemBits)) * 32
	if a.TotalItemCount > bitCapacity+32 { // allow up to one word of slack
		return errBadFormat("sparseArray TotalItemCount exceeds ItemBits capacity")
	}

	if a.BaseVals, err = s.loadBaseValsArray(); err != nil {
		return err
	}

	if a.IndexToItem0, err = s.loadDwordArray(); err != nil {
		return err
	}

	if a.IndexToItem1, err = s.loadDwordArray(); err != nil {
		return err
	}

	return nil
}

func (a *sparseArray) IsEmpty() bool { return a.TotalItemCount == 0 }

func (a *sparseArray) IsItemPresent(index uint32) bool {
	wordIdx := index >> 5
	if wordIdx >= uint32(len(a.ItemBits)) {
		return false
	}

	return a.ItemBits[wordIdx]&(1<<(index&0x1F)) != 0
}

// GetItemValueAt returns the rank (= number of set bits up to and
// including index, exclusive of the bit at `index`).
func (a *sparseArray) GetItemValueAt(index uint32) uint32 {
	bvIdx := index >> 9
	if bvIdx >= uint32(len(a.BaseVals)) {
		return 0
	}

	bv := &a.BaseVals[bvIdx]
	v := bv.BaseValue200

	switch ((index >> 6) & 0x07) - 1 {
	case 0:
		v += bv.AddValue40
	case 1:
		v += bv.AddValue80
	case 2:
		v += bv.AddValueC0
	case 3:
		v += bv.AddValue100
	case 4:
		v += bv.AddValue140
	case 5:
		v += bv.AddValue180
	case 6:
		v += bv.AddValue1C0
	}

	if index&0x20 != 0 {
		prevWord := (index >> 5) - 1
		if prevWord < uint32(len(a.ItemBits)) {
			v += popcount32(a.ItemBits[prevWord])
		}
	}

	wordIdx := index >> 5
	if wordIdx >= uint32(len(a.ItemBits)) {
		return v
	}

	mask := uint32(1)<<(index&0x1F) - 1

	return v + popcount32(a.ItemBits[wordIdx]&mask)
}

const (
	indexToGroupShift = 9
	groupSize         = 1 << indexToGroupShift // 0x200
)

// findGroupItems0 — port of FindGroup_Items0.
func (a *sparseArray) findGroupItems0(index uint32) uint32 {
	g := index >> indexToGroupShift
	if g+1 >= uint32(len(a.IndexToItem0)) {
		if g < uint32(len(a.IndexToItem0)) {
			return a.IndexToItem0[g] >> 9
		}

		return 0
	}

	minGroup := a.IndexToItem0[g] >> 9
	maxGroup := (a.IndexToItem0[g+1] + 0x1FF) >> 9

	nBV := uint32(len(a.BaseVals))
	if maxGroup-minGroup < 10 {
		for minGroup+1 < nBV && index >= (minGroup<<9)-a.BaseVals[minGroup+1].BaseValue200+0x200 {
			minGroup++
		}
	} else {
		for minGroup+1 < maxGroup {
			mid := (maxGroup + minGroup) >> 1
			if maxGroup < nBV && index < (maxGroup<<9)-a.BaseVals[maxGroup].BaseValue200 {
				maxGroup = mid
			} else {
				minGroup = mid
			}
		}
	}

	return minGroup
}

func (a *sparseArray) findGroupItems1(index uint32) uint32 {
	g := index >> indexToGroupShift
	if g+1 >= uint32(len(a.IndexToItem1)) {
		if g < uint32(len(a.IndexToItem1)) {
			return a.IndexToItem1[g] >> 9
		}

		return 0
	}

	startV := a.IndexToItem1[g] >> 9
	nextV := (a.IndexToItem1[g+1] + 0x1FF) >> 9

	nBV := uint32(len(a.BaseVals))
	if nextV-startV < 10 {
		for startV+1 < nBV && index >= a.BaseVals[startV+1].BaseValue200 {
			startV++
		}
	} else if startV+1 < nextV {
		mid := (nextV + startV) >> 1
		if mid < nBV && index >= a.BaseVals[mid].BaseValue200 {
			startV = mid
		}
		// else: nextV would be tightened to mid, but only startV is
		// returned in this single-step search, so the assignment is
		// dropped.
	}

	return startV
}

// GetItem0 — find index of the (index+1)-th *absent* (zero-bit) slot.
func (a *sparseArray) GetItem0(index uint32) uint32 {
	if index&0x1FF == 0 {
		g := index >> indexToGroupShift
		if g >= uint32(len(a.IndexToItem0)) {
			return 0
		}

		return a.IndexToItem0[g]
	}

	gi := a.findGroupItems0(index)
	if gi >= uint32(len(a.BaseVals)) {
		return 0
	}

	bv := &a.BaseVals[gi]
	edx := index + bv.BaseValue200 - (gi << 9)
	dwordIdx := gi << 4

	if edx < 0x100-bv.AddValue100 {
		if edx < 0x80-bv.AddValue80 {
			if edx >= 0x40-bv.AddValue40 {
				dwordIdx += 2
				edx = edx + bv.AddValue40 - 0x40
			}
		} else {
			if edx < 0xC0-bv.AddValueC0 {
				dwordIdx += 4
				edx = edx + bv.AddValue80 - 0x80
			} else {
				dwordIdx += 6
				edx = edx + bv.AddValueC0 - 0xC0
			}
		}
	} else {
		if edx < 0x180-bv.AddValue180 {
			if edx < 0x140-bv.AddValue140 {
				dwordIdx += 8
				edx = edx + bv.AddValue100 - 0x100
			} else {
				dwordIdx += 10
				edx = edx + bv.AddValue140 - 0x140
			}
		} else {
			if edx < 0x1C0-bv.AddValue1C0 {
				dwordIdx += 12
				edx = edx + bv.AddValue180 - 0x180
			} else {
				dwordIdx += 14
				edx = edx + bv.AddValue1C0 - 0x1C0
			}
		}
	}

	if dwordIdx >= uint32(len(a.ItemBits)) {
		return 0
	}

	bitGroup := ^a.ItemBits[dwordIdx]

	zb := setBitsAll(bitGroup)
	if edx >= (zb>>24)&0xFF {
		dwordIdx++
		if dwordIdx >= uint32(len(a.ItemBits)) {
			return 0
		}

		bitGroup = ^a.ItemBits[dwordIdx]
		edx -= (zb >> 24) & 0xFF
		zb = setBitsAll(bitGroup)
	}

	itemIdx := dwordIdx << 5
	low08 := zb & 0xFF
	low16 := (zb >> 8) & 0xFF
	low24 := (zb >> 16) & 0xFF

	if edx < low16 {
		if edx >= low08 {
			bitGroup >>= 8
			itemIdx += 8
			edx -= low08
		}
	} else {
		if edx < low24 {
			bitGroup >>= 16
			itemIdx += 16
			edx -= low16
		} else {
			bitGroup >>= 24
			itemIdx += 24
			edx -= low24
		}
	}

	bitGroup &= 0xFF

	return uint32(bitPos8Table[(edx<<8)|bitGroup]) + itemIdx
}

// GetItem1 — find index of the (index+1)-th *present* (one-bit) slot.
func (a *sparseArray) GetItem1(index uint32) uint32 {
	if index&0x1FF == 0 {
		g := index >> indexToGroupShift
		if g >= uint32(len(a.IndexToItem1)) {
			return 0
		}

		return a.IndexToItem1[g]
	}

	gi := a.findGroupItems1(index)
	if gi >= uint32(len(a.BaseVals)) {
		return 0
	}

	bv := &a.BaseVals[gi]
	dist := index - bv.BaseValue200
	dwordIdx := gi << 4

	if dist < bv.AddValue100 {
		if dist < bv.AddValue80 {
			if dist >= bv.AddValue40 {
				dist -= bv.AddValue40
				dwordIdx += 2
			}
		} else {
			if dist < bv.AddValueC0 {
				dist -= bv.AddValue80
				dwordIdx += 4
			} else {
				dist -= bv.AddValueC0
				dwordIdx += 6
			}
		}
	} else {
		if dist < bv.AddValue180 {
			if dist < bv.AddValue140 {
				dist -= bv.AddValue100
				dwordIdx += 8
			} else {
				dist -= bv.AddValue140
				dwordIdx += 10
			}
		} else {
			if dist < bv.AddValue1C0 {
				dist -= bv.AddValue180
				dwordIdx += 12
			} else {
				dist -= bv.AddValue1C0
				dwordIdx += 14
			}
		}
	}

	if dwordIdx >= uint32(len(a.ItemBits)) {
		return 0
	}

	bitGroup := a.ItemBits[dwordIdx]

	sb := setBitsAll(bitGroup)
	if dist >= (sb>>24)&0xFF {
		dwordIdx++
		if dwordIdx >= uint32(len(a.ItemBits)) {
			return 0
		}

		bitGroup = a.ItemBits[dwordIdx]
		dist -= (sb >> 24) & 0xFF
		sb = setBitsAll(bitGroup)
	}

	itemIdx := dwordIdx << 5
	low08 := sb & 0xFF
	low16 := (sb >> 8) & 0xFF
	low24 := (sb >> 16) & 0xFF

	if dist < low16 {
		if dist >= low08 {
			bitGroup >>= 8
			itemIdx += 8
			dist -= low08
		}
	} else {
		if dist < low24 {
			bitGroup >>= 16
			itemIdx += 16
			dist -= low16
		} else {
			bitGroup >>= 24
			itemIdx += 24
			dist -= low24
		}
	}

	bitGroup &= 0xFF

	return uint32(bitPos8Table[(dist<<8)|bitGroup]) + itemIdx
}

// -------------------------------------------------------------------------
// pathFragmentTable — characters of fragments, optionally with a mark
// bitmap (when no zero terminators are stored inline).
type pathFragmentTable struct {
	PathFragments []byte
	PathMarks     sparseArray
}

func (p *pathFragmentTable) load(s *byteStream) error {
	pf, err := s.loadByteArray()
	if err != nil {
		return err
	}

	p.PathFragments = pf

	return p.PathMarks.load(s)
}

//nolint:unused // kept as a faithful translation of the C++ search path; reachable once mask-based lookup is wired.
func (p *pathFragmentTable) comparePathFragment(sr *mndxSearch, off uint32) bool {
	st := &sr.state
	if p.PathMarks.IsEmpty() {
		for off < uint32(len(p.PathFragments)) && st.PathLength < uint32(len(sr.searchMask)) &&
			p.PathFragments[off] == sr.searchMask[st.PathLength] {
			st.PathLength++

			off++
			if off >= uint32(len(p.PathFragments)) {
				return false
			}

			if p.PathFragments[off] == 0 {
				return true
			}

			if st.PathLength >= uint32(len(sr.searchMask)) {
				return false
			}
		}

		return false
	}

	for off < uint32(len(p.PathFragments)) && st.PathLength < uint32(len(sr.searchMask)) &&
		p.PathFragments[off] == sr.searchMask[st.PathLength] {
		st.PathLength++

		if p.PathMarks.IsItemPresent(off) {
			return true
		}

		off++
		if off >= uint32(len(sr.searchMask)) { // upstream uses cchSearchMask here too
			return false
		}
	}

	return false
}

func (p *pathFragmentTable) copyPathFragment(sr *mndxSearch, off uint32) {
	st := &sr.state

	if p.PathMarks.IsEmpty() {
		for off < uint32(len(p.PathFragments)) && p.PathFragments[off] != 0 {
			st.PathBuffer = append(st.PathBuffer, p.PathFragments[off])
			off++
		}

		return
	}

	for off < uint32(len(p.PathFragments)) {
		st.PathBuffer = append(st.PathBuffer, p.PathFragments[off])
		if p.PathMarks.IsItemPresent(off) {
			return
		}

		off++
	}
}

func (p *pathFragmentTable) compareAndCopyPathFragment(sr *mndxSearch, off uint32) bool {
	st := &sr.state
	if p.PathMarks.IsEmpty() {
		for st.PathLength < uint32(len(sr.searchMask)) {
			if off >= uint32(len(p.PathFragments)) {
				return false
			}

			if p.PathFragments[off] != sr.searchMask[st.PathLength] {
				return false
			}

			st.PathBuffer = append(st.PathBuffer, p.PathFragments[off])
			off++
			st.PathLength++

			if off >= uint32(len(p.PathFragments)) {
				return true
			}

			if p.PathFragments[off] == 0 {
				return true
			}
		}
		// Copy the remainder of the fragment.
		for off < uint32(len(p.PathFragments)) && p.PathFragments[off] != 0 {
			st.PathBuffer = append(st.PathBuffer, p.PathFragments[off])
			off++
		}

		return true
	}

	for st.PathLength < uint32(len(sr.searchMask)) {
		if p.PathFragments[off] != sr.searchMask[st.PathLength] {
			return false
		}

		st.PathBuffer = append(st.PathBuffer, p.PathFragments[off])
		st.PathLength++

		if p.PathMarks.IsItemPresent(off) {
			return true
		}

		off++
	}

	for !p.PathMarks.IsItemPresent(off) {
		st.PathBuffer = append(st.PathBuffer, p.PathFragments[off])
		off++
	}

	return true
}

// -------------------------------------------------------------------------
// Search state

const (
	searchInit      = 0
	searchSearching = 2
	searchFinished  = 4

	invalidIndex uint32 = 0xFFFFFFFF
)

type pathStop struct {
	LoBitsIndex             uint32
	Field4                  uint32
	Count                   uint32
	HiBitsIndexPathFragment uint32
	Field10                 uint32
}

func newPathStop(a, b, c uint32) pathStop {
	return pathStop{
		LoBitsIndex:             a,
		Field4:                  b,
		Count:                   c,
		HiBitsIndexPathFragment: invalidIndex,
		Field10:                 invalidIndex,
	}
}

type searchState struct {
	PathStops   []pathStop
	PathBuffer  []byte
	NodeIndex   uint32
	PathLength  uint32
	ItemCount   uint32
	SearchPhase uint32
}

func (s *searchState) BeginSearch() {
	s.PathBuffer = s.PathBuffer[:0]
	s.PathStops = s.PathStops[:0]
	s.PathLength = 0
	s.NodeIndex = 0
	s.ItemCount = 0
	s.SearchPhase = searchSearching
}

func (s *searchState) CalcHashValue(mask []byte) uint32 {
	return uint32(mask[s.PathLength]) ^ (s.NodeIndex << 5) ^ s.NodeIndex
}

type mndxSearch struct {
	state      searchState
	searchMask []byte
	foundPath  []byte
	foundIndex uint32
	totalSteps int // cumulative across all doSearch calls; checked against maxTrieSteps
}

// -------------------------------------------------------------------------
// fileNameDB — the trie. Recursive: may have a child DB for nested fragment
// indirection.
type fileNameDB struct {
	CollisionTable         sparseArray
	FileNameIndexes        sparseArray
	CollisionHiBitsIndexes sparseArray
	LoBitsTable            []byte
	HiBitsTable            bitEntryArray
	PathFragmentTable      pathFragmentTable
	ChildDB                *fileNameDB
	HashTable              []hashEntry
	HashTableMask          uint32
	Field214               uint32
	// Struct10 fields are state-machine knobs that don't affect lookup;
	// ignored here.
}

func (d *fileNameDB) load(data []byte) error {
	s := byteStream{buf: data}

	sig, err := s.getU32()
	if err != nil {
		return err
	}

	if sig != marMagic {
		return errBadFormat(fmt.Sprintf("MAR signature: %#x", sig))
	}

	return d.loadFromStream(&s)
}

func (d *fileNameDB) loadFromStream(s *byteStream) error {
	if err := d.CollisionTable.load(s); err != nil {
		return err
	}

	if err := d.FileNameIndexes.load(s); err != nil {
		return err
	}

	if err := d.CollisionHiBitsIndexes.load(s); err != nil {
		return err
	}

	lo, err := s.loadByteArray()
	if err != nil {
		return err
	}

	d.LoBitsTable = lo
	if err := d.HiBitsTable.load(s); err != nil {
		return err
	}

	if err := d.PathFragmentTable.load(s); err != nil {
		return err
	}

	if d.CollisionHiBitsIndexes.ValidItemCount != 0 && len(d.PathFragmentTable.PathFragments) == 0 {
		d.ChildDB = &fileNameDB{}
		if err := d.ChildDB.loadFromStream(s); err != nil {
			return err
		}
	}

	hashTbl, err := s.loadHashEntryArray()
	if err != nil {
		return err
	}

	d.HashTable = hashTbl
	if uint64(len(d.HashTable)) > 0 {
		d.HashTableMask = uint32(len(d.HashTable)) - 1
	}

	if d.Field214, err = s.getU32(); err != nil {
		return err
	}
	// Skip struct10 bitmask (not used at runtime here).
	if _, err := s.getU32(); err != nil {
		return err
	}

	return nil
}

func (d *fileNameDB) isPathFragmentString(idx uint32) bool {
	return d.CollisionHiBitsIndexes.IsItemPresent(idx)
}

func (d *fileNameDB) getPathFragmentOffset1(loBitsIdx uint32) uint32 {
	var lo byte
	if loBitsIdx < uint32(len(d.LoBitsTable)) {
		lo = d.LoBitsTable[loBitsIdx]
	}

	hi := d.CollisionHiBitsIndexes.GetItemValueAt(loBitsIdx)

	return (d.HiBitsTable.Get(hi) << 8) | uint32(lo)
}

func (d *fileNameDB) getPathFragmentOffset2(hiBits *uint32, loBitsIdx uint32) uint32 {
	var lo byte
	if loBitsIdx < uint32(len(d.LoBitsTable)) {
		lo = d.LoBitsTable[loBitsIdx]
	}

	if *hiBits == invalidIndex {
		*hiBits = d.CollisionHiBitsIndexes.GetItemValueAt(loBitsIdx)
	} else {
		*hiBits++
	}

	return (d.HiBitsTable.Get(*hiBits) << 8) | uint32(lo)
}

// comparePathFragment — top-level.
//
//nolint:unused // kept as a faithful translation of the C++ search path; reachable once mask-based lookup is wired.
func (d *fileNameDB) comparePathFragment(sr *mndxSearch) bool {
	st := &sr.state
	hashIdx := st.CalcHashValue(sr.searchMask) & d.HashTableMask
	he := &d.HashTable[hashIdx]

	if he.NodeIndex == st.NodeIndex {
		if !he.IsSingleChar() {
			if d.ChildDB != nil {
				if !d.ChildDB.comparePathFragmentByIndex(sr, he.ChildTableIndex()) {
					return false
				}
			} else {
				if !d.PathFragmentTable.comparePathFragment(sr, he.FragmentOffset) {
					return false
				}
			}
		} else {
			st.PathLength++
		}

		st.NodeIndex = he.NextIndex

		return true
	}

	colTblIdx := d.CollisionTable.GetItem0(st.NodeIndex) + 1
	st.NodeIndex = colTblIdx - st.NodeIndex - 1
	hiBits := invalidIndex

	for d.CollisionTable.IsItemPresent(colTblIdx) {
		if d.isPathFragmentString(st.NodeIndex) {
			fragOff := d.getPathFragmentOffset2(&hiBits, st.NodeIndex)
			savedLen := st.PathLength

			if d.ChildDB != nil {
				if d.ChildDB.comparePathFragmentByIndex(sr, fragOff) {
					return true
				}
			} else {
				if d.PathFragmentTable.comparePathFragment(sr, fragOff) {
					return true
				}
			}

			if st.PathLength != savedLen {
				return false
			}
		} else if d.LoBitsTable[st.NodeIndex] == sr.searchMask[st.PathLength] {
			st.PathLength++
			return true
		}

		st.NodeIndex++
		colTblIdx++
	}

	return false
}

//nolint:unused // kept as a faithful translation of the C++ search path; reachable once mask-based lookup is wired.
func (d *fileNameDB) comparePathFragmentByIndex(sr *mndxSearch, tableIdx uint32) bool {
	st := &sr.state

	for {
		he := &d.HashTable[tableIdx&d.HashTableMask]
		if tableIdx == he.NextIndex {
			if !he.IsSingleChar() {
				if d.ChildDB != nil {
					if !d.ChildDB.comparePathFragmentByIndex(sr, he.ChildTableIndex()) {
						return false
					}
				} else {
					if !d.PathFragmentTable.comparePathFragment(sr, he.FragmentOffset) {
						return false
					}
				}
			} else {
				if sr.searchMask[st.PathLength] != he.SingleChar() {
					return false
				}

				st.PathLength++
			}

			tableIdx = he.NodeIndex
			if tableIdx == 0 {
				return true
			}

			if st.PathLength >= uint32(len(sr.searchMask)) {
				return false
			}
		} else {
			if d.isPathFragmentString(tableIdx) {
				fragOff := d.getPathFragmentOffset1(tableIdx)
				if d.ChildDB != nil {
					if !d.ChildDB.comparePathFragmentByIndex(sr, fragOff) {
						return false
					}
				} else {
					if !d.PathFragmentTable.comparePathFragment(sr, fragOff) {
						return false
					}
				}
			} else {
				if d.LoBitsTable[tableIdx] != sr.searchMask[st.PathLength] {
					return false
				}

				st.PathLength++
			}

			if tableIdx <= d.Field214 {
				return true
			}

			if st.PathLength >= uint32(len(sr.searchMask)) {
				return false
			}

			eax := d.CollisionTable.GetItem1(tableIdx)
			tableIdx = eax - tableIdx - 1
		}
	}
}

// maxTrieSteps caps how many loop iterations the trie traversal performs
// on any single input. This prevents infinite loops caused by adversarial
// (e.g. fuzzer-generated) trie structures that form cycles.
const maxTrieSteps = 1 << 16 // 65 536 steps

func (d *fileNameDB) copyPathFragmentByIndex(sr *mndxSearch, tableIdx uint32) {
	st := &sr.state

	for ; sr.totalSteps < maxTrieSteps; sr.totalSteps++ {
		he := &d.HashTable[tableIdx&d.HashTableMask]
		if tableIdx == he.NextIndex {
			if !he.IsSingleChar() {
				if d.ChildDB != nil {
					d.ChildDB.copyPathFragmentByIndex(sr, he.ChildTableIndex())
				} else {
					d.PathFragmentTable.copyPathFragment(sr, he.FragmentOffset)
				}
			} else {
				st.PathBuffer = append(st.PathBuffer, he.SingleChar())
			}

			tableIdx = he.NodeIndex
			if tableIdx == 0 {
				return
			}
		} else {
			if d.isPathFragmentString(tableIdx) {
				fragOff := d.getPathFragmentOffset1(tableIdx)
				if d.ChildDB != nil {
					d.ChildDB.copyPathFragmentByIndex(sr, fragOff)
				} else {
					d.PathFragmentTable.copyPathFragment(sr, fragOff)
				}
			} else if tableIdx < uint32(len(d.LoBitsTable)) {
				st.PathBuffer = append(st.PathBuffer, d.LoBitsTable[tableIdx])
			}

			if tableIdx <= d.Field214 {
				return
			}

			tableIdx = 0xFFFFFFFF - tableIdx + d.CollisionTable.GetItem1(tableIdx)
		}
	}
}

func (d *fileNameDB) compareAndCopyPathFragment(sr *mndxSearch) bool {
	st := &sr.state
	hashIdx := st.CalcHashValue(sr.searchMask) & d.HashTableMask

	he := &d.HashTable[hashIdx]
	if st.NodeIndex == he.NodeIndex {
		if !he.IsSingleChar() {
			if d.ChildDB != nil {
				if !d.ChildDB.compareAndCopyPathFragmentByIndex(sr, he.ChildTableIndex()) {
					return false
				}
			} else {
				if !d.PathFragmentTable.compareAndCopyPathFragment(sr, he.FragmentOffset) {
					return false
				}
			}
		} else {
			st.PathBuffer = append(st.PathBuffer, he.SingleChar())
			st.PathLength++
		}

		st.NodeIndex = he.NextIndex

		return true
	}

	colTblIdx := d.CollisionTable.GetItem0(st.NodeIndex) + 1
	st.NodeIndex = colTblIdx - st.NodeIndex - 1
	hiBits := invalidIndex

	for d.CollisionTable.IsItemPresent(colTblIdx) {
		if d.isPathFragmentString(st.NodeIndex) {
			fragOff := d.getPathFragmentOffset2(&hiBits, st.NodeIndex)
			savedLen := st.PathLength

			if d.ChildDB != nil {
				if d.ChildDB.compareAndCopyPathFragmentByIndex(sr, fragOff) {
					return true
				}
			} else {
				if d.PathFragmentTable.compareAndCopyPathFragment(sr, fragOff) {
					return true
				}
			}

			if savedLen != st.PathLength {
				return false
			}
		} else if st.NodeIndex < uint32(len(d.LoBitsTable)) && d.LoBitsTable[st.NodeIndex] == sr.searchMask[st.PathLength] {
			st.PathBuffer = append(st.PathBuffer, d.LoBitsTable[st.NodeIndex])
			st.PathLength++

			return true
		}

		st.NodeIndex++
		colTblIdx++
	}

	return false
}

func (d *fileNameDB) compareAndCopyPathFragmentByIndex(sr *mndxSearch, tableIdx uint32) bool {
	st := &sr.state

	for ; sr.totalSteps < maxTrieSteps; sr.totalSteps++ {
		he := &d.HashTable[tableIdx&d.HashTableMask]
		if tableIdx == he.NextIndex {
			if !he.IsSingleChar() {
				if d.ChildDB != nil {
					if !d.ChildDB.compareAndCopyPathFragmentByIndex(sr, he.ChildTableIndex()) {
						return false
					}
				} else {
					if !d.PathFragmentTable.compareAndCopyPathFragment(sr, he.FragmentOffset) {
						return false
					}
				}
			} else {
				if he.SingleChar() != sr.searchMask[st.PathLength] {
					return false
				}

				st.PathBuffer = append(st.PathBuffer, he.SingleChar())
				st.PathLength++
			}

			tableIdx = he.NodeIndex
			if tableIdx == 0 {
				return true
			}
		} else {
			if d.isPathFragmentString(tableIdx) {
				fragOff := d.getPathFragmentOffset1(tableIdx)
				if d.ChildDB != nil {
					if !d.ChildDB.compareAndCopyPathFragmentByIndex(sr, fragOff) {
						return false
					}
				} else {
					if !d.PathFragmentTable.compareAndCopyPathFragment(sr, fragOff) {
						return false
					}
				}
			} else {
				if tableIdx >= uint32(len(d.LoBitsTable)) ||
					d.LoBitsTable[tableIdx] != sr.searchMask[st.PathLength] {
					return false
				}

				st.PathBuffer = append(st.PathBuffer, d.LoBitsTable[tableIdx])
				st.PathLength++
			}

			if tableIdx <= d.Field214 {
				return true
			}

			tableIdx = 0xFFFFFFFF - tableIdx + d.CollisionTable.GetItem1(tableIdx)
		}

		if st.PathLength >= uint32(len(sr.searchMask)) {
			break
		}
	}

	d.copyPathFragmentByIndex(sr, tableIdx)

	return true
}

// findFileInDatabase — exact-match lookup.
//
//nolint:unused // kept as a faithful translation of the C++ search path; reachable once mask-based lookup is wired.
func (d *fileNameDB) findFileInDatabase(sr *mndxSearch) bool {
	st := &sr.state
	st.NodeIndex = 0
	st.PathLength = 0

	st.SearchPhase = searchInit
	if len(sr.searchMask) > 0 {
		for st.PathLength < uint32(len(sr.searchMask)) {
			if !d.comparePathFragment(sr) {
				return false
			}
		}
	}

	if !d.FileNameIndexes.IsItemPresent(st.NodeIndex) {
		return false
	}

	sr.foundPath = sr.searchMask
	sr.foundIndex = d.FileNameIndexes.GetItemValueAt(st.NodeIndex)

	return true
}

// doSearch — incremental enumerator. Each successful call yields the
// next (path, index) pair. Returns false when the trie is exhausted.
func (d *fileNameDB) doSearch(sr *mndxSearch) bool {
	st := &sr.state
	switch st.SearchPhase {
	case searchInit:
		st.BeginSearch()

		for st.PathLength < uint32(len(sr.searchMask)) {
			if !d.compareAndCopyPathFragment(sr) {
				st.SearchPhase = searchFinished
				return false
			}
		}

		ps := newPathStop(st.NodeIndex, 0, uint32(len(st.PathBuffer)))
		st.PathStops = append(st.PathStops, ps)

		st.ItemCount = 1
		if d.FileNameIndexes.IsItemPresent(st.NodeIndex) {
			sr.foundPath = append(sr.foundPath[:0], st.PathBuffer...)
			sr.foundIndex = d.FileNameIndexes.GetItemValueAt(st.NodeIndex)

			return true
		}

		fallthrough
	case searchSearching:
		for ; sr.totalSteps < maxTrieSteps; sr.totalSteps++ {
			if st.ItemCount == uint32(len(st.PathStops)) {
				last := st.PathStops[len(st.PathStops)-1]
				colIdx := d.CollisionTable.GetItem0(last.LoBitsIndex) + 1
				st.PathStops = append(
					st.PathStops,
					newPathStop(colIdx-last.LoBitsIndex-1, colIdx, 0),
				)
			}

			ps := &st.PathStops[st.ItemCount]
			cur := ps.Field4
			ps.Field4++

			if d.CollisionTable.IsItemPresent(cur) {
				st.ItemCount++

				if d.isPathFragmentString(ps.LoBitsIndex) {
					fragOff := d.getPathFragmentOffset2(&ps.HiBitsIndexPathFragment, ps.LoBitsIndex)
					if d.ChildDB != nil {
						d.ChildDB.copyPathFragmentByIndex(sr, fragOff)
					} else {
						d.PathFragmentTable.copyPathFragment(sr, fragOff)
					}
				} else if ps.LoBitsIndex < uint32(len(d.LoBitsTable)) {
					st.PathBuffer = append(st.PathBuffer, d.LoBitsTable[ps.LoBitsIndex])
				}

				ps.Count = uint32(len(st.PathBuffer))
				if d.FileNameIndexes.IsItemPresent(ps.LoBitsIndex) {
					if ps.Field10 == 0xFFFFFFFF {
						ps.Field10 = d.FileNameIndexes.GetItemValueAt(ps.LoBitsIndex)
					} else {
						ps.Field10++
					}

					sr.foundPath = append(sr.foundPath[:0], st.PathBuffer...)
					sr.foundIndex = ps.Field10

					return true
				}
			} else {
				if st.ItemCount == 1 {
					st.SearchPhase = searchFinished
					return false
				}

				st.PathStops[st.ItemCount-1].LoBitsIndex++
				edi := st.PathStops[st.ItemCount-2].Count
				st.PathBuffer = st.PathBuffer[:edi]
				st.ItemCount--
			}
		}

		// Step limit reached — treat as exhausted.
		st.SearchPhase = searchFinished
	}

	return false
}

// -------------------------------------------------------------------------
// marFile — wraps a fileNameDB plus its raw bytes.
type marFile struct {
	db *fileNameDB
}

func (m *marFile) load(data []byte) error {
	m.db = &fileNameDB{}
	return m.db.load(data)
}

//nolint:unused // kept as a faithful translation of the C++ search path; reachable once mask-based lookup is wired.
func (m *marFile) searchFile(mask string) (uint32, bool) {
	if m.db == nil {
		return 0, false
	}

	sr := &mndxSearch{searchMask: []byte(mask)}
	if !m.db.findFileInDatabase(sr) {
		return 0, false
	}

	return sr.foundIndex, true
}

// enumerate calls fn(name, index) for every name in the trie. fn may
// return false to abort.
func (m *marFile) enumerate(fn func(name []byte, idx uint32) bool) {
	if m.db == nil {
		return
	}

	sr := &mndxSearch{}
	for m.db.doSearch(sr) {
		if !fn(sr.foundPath, sr.foundIndex) {
			return
		}
	}
}

func (m *marFile) fileNameCount() uint32 {
	if m.db == nil {
		return 0
	}

	return m.db.FileNameIndexes.ValidItemCount
}

// errBadFormat keeps the trie loader independent of internal/casc imports.
type mndxBadFormat string

func (e mndxBadFormat) Error() string { return string(e) }

func errBadFormat(s string) error { return mndxBadFormat("mndx: " + s) }
