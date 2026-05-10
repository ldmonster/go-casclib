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

// Package cdn HTTP client.
//
// CDN (Content Delivery Network) endpoints are listed in the .build.info
// file under the "CDN Hosts" + "CDN Path" columns. Blobs are addressed by
// the hex form of an EKey, sharded into "ab/cd/abcdef..." paths. This file
// implements a thin client that fetches such blobs over HTTPS.
//
// CASC's online mode is optional and unused by default; the parser-side
// DOWNLOAD manifest decoding (download.go) is the more frequently exercised
// portion of this package.
package cdn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client fetches blobs from one or more CDN hosts.
type Client struct {
	HTTP    *http.Client
	Hosts   []string // bare hostnames, e.g. ["us.patch.battle.net"]
	BaseDir string   // CDN path prefix, e.g. "tpr/wow"
	Region  string   // optional region tag, e.g. "us"
}

// NewClient constructs a CDN client with sensible defaults.
func NewClient(hosts []string, baseDir string) *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
		},
		Hosts:   append([]string(nil), hosts...),
		BaseDir: baseDir,
	}
}

// PathFor returns the canonical CDN path for the given content type and
// hex-encoded hash. ctype is one of "data", "config", "patch".
func PathFor(baseDir, ctype, hexHash string) string {
	if len(hexHash) < 4 {
		return ""
	}

	hexHash = strings.ToLower(hexHash)

	return fmt.Sprintf("%s/%s/%s/%s/%s",
		strings.Trim(baseDir, "/"),
		ctype,
		hexHash[0:2],
		hexHash[2:4],
		hexHash,
	)
}

// Fetch retrieves the named blob, trying each configured host in order.
func (c *Client) Fetch(ctx context.Context, ctype, hexHash string) ([]byte, error) {
	return c.fetch(ctx, ctype, hexHash, -1, -1)
}

// FetchRange retrieves a half-open byte range [offset, offset+length) of
// the named blob using HTTP Range. CDN-archive-backed reads use this to
// pull just the encoded span an EKey resolves to.
func (c *Client) FetchRange(
	ctx context.Context,
	ctype, hexHash string,
	offset, length int64,
) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("cdn: zero/negative range length")
	}

	return c.fetch(ctx, ctype, hexHash, offset, length)
}

func (c *Client) fetch(
	ctx context.Context,
	ctype, hexHash string,
	offset, length int64,
) ([]byte, error) {
	if len(c.Hosts) == 0 {
		return nil, errors.New("cdn: no hosts configured")
	}

	path := PathFor(c.BaseDir, ctype, hexHash)
	if path == "" {
		return nil, errors.New("cdn: invalid hash")
	}

	var lastErr error

	for _, host := range c.Hosts {
		u := fmt.Sprintf("http://%s/%s", host, path)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}

		if length > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
		}

		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = err
			continue
		}

		ok := resp.StatusCode == http.StatusOK ||
			(length > 0 && resp.StatusCode == http.StatusPartialContent)
		if !ok {
			lastErr = fmt.Errorf("cdn: %s -> HTTP %d", u, resp.StatusCode)
			continue
		}

		return body, nil
	}

	return nil, lastErr
}
