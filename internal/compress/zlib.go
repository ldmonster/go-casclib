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
	"compress/zlib"
	"fmt"
	"io"
)

// Inflate decompresses a zlib stream and returns the uncompressed bytes.
// The optional expected length, if non-zero, sets the initial buffer
// capacity. If the inflated data is shorter than expected, the result is
// returned as-is — callers may zero-pad.
func Inflate(in []byte, expected int) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, fmt.Errorf("zlib new reader: %w", err)
	}
	defer zr.Close()

	var buf bytes.Buffer
	if expected > 0 {
		buf.Grow(expected)
	}

	if _, err := io.Copy(&buf, zr); err != nil {
		return nil, fmt.Errorf("zlib read: %w", err)
	}

	return buf.Bytes(), nil
}

// Deflate compresses data with default zlib settings. Used for tests.
func Deflate(in []byte) ([]byte, error) {
	var buf bytes.Buffer

	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(in); err != nil {
		zw.Close()
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
