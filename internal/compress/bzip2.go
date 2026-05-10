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
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
)

// Unbzip2 decompresses a bzip2 stream and returns the uncompressed bytes.
// The optional expected length, if non-zero, sets the initial buffer capacity.
func Unbzip2(in []byte, expected int) ([]byte, error) {
	zr := bzip2.NewReader(bytes.NewReader(in))

	var buf bytes.Buffer
	if expected > 0 {
		buf.Grow(expected)
	}

	if _, err := io.Copy(&buf, zr); err != nil {
		return nil, fmt.Errorf("bzip2 read: %w", err)
	}

	return buf.Bytes(), nil
}
