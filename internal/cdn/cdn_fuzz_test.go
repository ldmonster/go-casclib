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

import "testing"

func FuzzParseDownload(f *testing.F) {
	// Empty + minimum-shaped headers.
	f.Add([]byte{})
	v1 := []byte{
		'D', 'L', // magic
		1, // version
		16, 0,
		0, 0, 0, 0, // entry count
		0, 0, // tag count
	}
	f.Add(v1)

	v3 := []byte{
		'D', 'L',
		3,
		16, 0,
		0, 0, 0, 0,
		0, 0,
		0,          // FlagByteSize
		0, 0, 0, 0, // BasePriority + 3 unknown
	}
	f.Add(v3)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseDownload(data)
	})
}

func FuzzParseArchiveIndex(f *testing.F) {
	// Valid 1-entry index (round-tripped through the encoder).
	footer := ArchiveIndexFooter{
		PageSizeKB: 4, OffsetBytes: 4, SizeBytes: 4, EKeyLength: 16, FooterHashBytes: 8,
	}
	good := EncodeArchiveIndex(footer, []ArchiveIndexEntry{{EncodedSize: 1}})
	f.Add(good)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseArchiveIndex(data)
	})
}
