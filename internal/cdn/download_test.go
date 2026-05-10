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

package cdn

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func buildDownload(version byte, entryHasChecksum bool, flagBytes byte, entries int, tagCount int) []byte {
	var buf bytes.Buffer
	tmp2 := make([]byte, 2)
	tmp4 := make([]byte, 4)

	binary.LittleEndian.PutUint16(tmp2, downloadMagic)
	buf.Write(tmp2)
	buf.WriteByte(version)
	buf.WriteByte(16) // EKeyLength
	if entryHasChecksum {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	binary.BigEndian.PutUint32(tmp4, uint32(entries))
	buf.Write(tmp4)
	binary.BigEndian.PutUint16(tmp2, uint16(tagCount))
	buf.Write(tmp2)
	if version >= 2 {
		buf.WriteByte(flagBytes)
	}
	if version >= 3 {
		buf.WriteByte(0) // BasePriority
		buf.Write([]byte{0, 0, 0})
	}

	// Entries.
	for i := 0; i < entries; i++ {
		ek := make([]byte, 16)
		ek[0] = byte(i + 1)
		buf.Write(ek)
		// 5-byte BE size = 1024.
		buf.Write([]byte{0, 0, 0, 4, 0})
		buf.WriteByte(byte(i)) // priority
		if entryHasChecksum {
			binary.BigEndian.PutUint32(tmp4, uint32(0xC0DE0000)|uint32(i))
			buf.Write(tmp4)
		}
		for j := byte(0); j < flagBytes; j++ {
			buf.WriteByte(0xAA)
		}
	}

	// Tags.
	bitmapLen := (entries + 7) / 8
	for i := 0; i < tagCount; i++ {
		buf.WriteString("Tag")
		buf.WriteByte(byte('A' + i))
		buf.WriteByte(0) // null terminator
		binary.BigEndian.PutUint16(tmp2, uint16(i+1))
		buf.Write(tmp2)
		bm := make([]byte, bitmapLen)
		for k := range bm {
			bm[k] = 0xFF
		}
		buf.Write(bm)
	}
	return buf.Bytes()
}

func TestParseDownloadV1(t *testing.T) {
	data := buildDownload(1, false, 0, 3, 1)
	man, err := ParseDownload(data)
	if err != nil {
		t.Fatalf("ParseDownload: %v", err)
	}
	if man.Header.Version != 1 || man.Header.EntryCount != 3 || man.Header.TagCount != 1 {
		t.Errorf("hdr = %+v", man.Header)
	}
	if len(man.Entries) != 3 || man.Entries[0].EncodedSize != 1024 {
		t.Errorf("entries = %+v", man.Entries)
	}
	if len(man.Tags) != 1 || man.Tags[0].Name != "TagA" {
		t.Errorf("tags = %+v", man.Tags)
	}
}

func TestParseDownloadV2WithChecksumAndFlags(t *testing.T) {
	data := buildDownload(2, true, 1, 2, 2)
	man, err := ParseDownload(data)
	if err != nil {
		t.Fatalf("ParseDownload: %v", err)
	}
	if man.Header.FlagByteSize != 1 {
		t.Errorf("FlagByteSize = %d", man.Header.FlagByteSize)
	}
	if !man.Header.EntryHasChecksum {
		t.Error("expected EntryHasChecksum")
	}
	if man.Entries[0].Checksum&0xFFFF0000 != 0xC0DE0000 {
		t.Errorf("checksum = %#x", man.Entries[0].Checksum)
	}
	if man.Entries[0].Flags != 0xAA {
		t.Errorf("flags = %#x", man.Entries[0].Flags)
	}
	if len(man.Tags) != 2 {
		t.Errorf("tag count = %d", len(man.Tags))
	}
}

func TestParseDownloadV3(t *testing.T) {
	data := buildDownload(3, true, 2, 1, 0)
	man, err := ParseDownload(data)
	if err != nil {
		t.Fatalf("ParseDownload: %v", err)
	}
	if man.Header.Version != 3 || man.Header.EntryCount != 1 {
		t.Errorf("hdr = %+v", man.Header)
	}
}

func TestParseDownloadRejectsBadMagic(t *testing.T) {
	if _, err := ParseDownload(make([]byte, 32)); err == nil {
		t.Fatal("expected error")
	}
}

func TestPathFor(t *testing.T) {
	got := PathFor("tpr/wow", "data", "abcdef0123456789")
	want := "tpr/wow/data/ab/cd/abcdef0123456789"
	if got != want {
		t.Errorf("PathFor = %q, want %q", got, want)
	}
}
