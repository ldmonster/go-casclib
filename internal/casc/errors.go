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

package casc

import "errors"

// Sentinel errors used throughout the library. These map roughly to the
// Win32 error codes returned by upstream CascLib (ERROR_FILE_NOT_FOUND,
// ERROR_BAD_FORMAT, etc.) but are designed for idiomatic errors.Is checks.
var (
	ErrFileNotFound       = errors.New("casc: file not found")
	ErrInvalidParameter   = errors.New("casc: invalid parameter")
	ErrInvalidHandle      = errors.New("casc: invalid handle")
	ErrBadFormat          = errors.New("casc: bad file format")
	ErrFileCorrupt        = errors.New("casc: file is corrupt")
	ErrNotSupported       = errors.New("casc: feature not supported")
	ErrEncrypted          = errors.New("casc: file is encrypted with unknown key")
	ErrAlreadyExists      = errors.New("casc: file already exists")
	ErrInsufficientBuffer = errors.New("casc: insufficient buffer")
	ErrCancelled          = errors.New("casc: operation cancelled")
	ErrEndOfFile          = errors.New("casc: end of file")
)
