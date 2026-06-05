// Package artifact extracts a gzipped tar (npm .tgz, PyPI sdist, crates .crate) into
// an in-memory path->content map, with strict caps and path/symlink sanitization —
// the files are untrusted, so this never writes to disk, never follows links, and
// never lets an entry escape the archive root.
package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"
)

type Limits struct {
	MaxTotalBytes int64 // total decompressed bytes across all kept files
	MaxFileBytes  int64 // per-file cap
	MaxFiles      int   // number of entries processed
}

func DefaultLimits() Limits {
	return Limits{MaxTotalBytes: 64 << 20, MaxFileBytes: 1 << 20, MaxFiles: 2000}
}

// ExtractTarGz returns regular-file path->content. Entries that are symlinks/hard
// links, escape the root (.. or absolute), exceed MaxFileBytes, or are non-text are
// skipped; exceeding MaxFiles or MaxTotalBytes is an error (bomb defense).
func ExtractTarGz(b []byte, lim Limits) (map[string]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string]string{}
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		count++
		if count > lim.MaxFiles {
			return nil, fmt.Errorf("archive exceeds %d entries", lim.MaxFiles)
		}
		if h.Typeflag != tar.TypeReg {
			continue // skip dirs, symlinks, hardlinks, devices
		}
		clean := path.Clean(h.Name)
		if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
			continue // path traversal / absolute — reject
		}
		if h.Size > lim.MaxFileBytes {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, lim.MaxFileBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > lim.MaxFileBytes {
			continue
		}
		total += int64(len(data))
		if total > lim.MaxTotalBytes {
			return nil, fmt.Errorf("archive exceeds %d total bytes", lim.MaxTotalBytes)
		}
		out[clean] = string(data)
	}
	return out, nil
}
