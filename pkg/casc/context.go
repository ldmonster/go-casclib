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

// Context-aware variants of OpenFile / FindFiles. These wrap the
// non-context APIs and propagate ctx through internal/storage and
// internal/cdn so HTTP fetches honour cancellation deadlines.

package casc

import "context"

// OpenFileContext is OpenFile with an explicit cancellation context.
func (s *Storage) OpenFileContext(ctx context.Context, name string) (*File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return s.openFile(ctx, name)
}

// OpenFileByCKeyContext is OpenFileByCKey with an explicit context.
func (s *Storage) OpenFileByCKeyContext(ctx context.Context, ckey [16]byte) (*File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return s.openFileByCKey(ctx, ckey)
}

// OpenFileByEKeyContext is OpenFileByEKey with an explicit context.
func (s *Storage) OpenFileByEKeyContext(ctx context.Context, ekey [16]byte) (*File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return s.openFileByEKey(ctx, ekey)
}

// OpenFileByIDContext is OpenFileByID with an explicit context.
func (s *Storage) OpenFileByIDContext(ctx context.Context, fileDataID uint32) (*File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return s.openFileByID(ctx, fileDataID)
}

// FindFilesContext drives FindFiles with cancellation. The callback is
// invoked synchronously; iteration stops as soon as ctx is cancelled.
func (s *Storage) FindFilesContext(
	ctx context.Context,
	pattern string,
	fn func(name string, info FileInfo) bool,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var ctxErr error

	wrap := func(name string, info FileInfo) bool {
		if err := ctx.Err(); err != nil {
			ctxErr = err
			return false
		}

		return fn(name, info)
	}

	if err := s.FindFiles(pattern, wrap); err != nil {
		return err
	}

	return ctxErr
}
