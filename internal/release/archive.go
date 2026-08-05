// Package release builds deterministic, auditable release artifacts.
package release

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// File is one file embedded in a release archive.
type File struct {
	Name string
	Path string
	Mode os.FileMode
}

// Digest describes one immutable release artifact.
type Digest struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// TarGz writes a byte-stable gzip-compressed tar archive.
func TarGz(path, root string, epoch time.Time, files []File) error {
	return writeAtomically(path, func(output io.Writer) error {
		gzipWriter, err := gzip.NewWriterLevel(output, gzip.BestCompression)
		if err != nil {
			return err
		}
		gzipWriter.ModTime = epoch.UTC()
		gzipWriter.OS = 255
		tarWriter := tar.NewWriter(gzipWriter)
		for _, file := range sortedFiles(files) {
			if err := writeTarFile(tarWriter, root, epoch, file); err != nil {
				_ = tarWriter.Close()
				_ = gzipWriter.Close()
				return err
			}
		}
		if err := tarWriter.Close(); err != nil {
			_ = gzipWriter.Close()
			return err
		}
		return gzipWriter.Close()
	})
}

// Zip writes a byte-stable ZIP archive suitable for Windows releases.
func Zip(path, root string, epoch time.Time, files []File) error {
	return writeAtomically(path, func(output io.Writer) error {
		writer := zip.NewWriter(output)
		for _, file := range sortedFiles(files) {
			data, err := os.ReadFile(file.Path)
			if err != nil {
				_ = writer.Close()
				return fmt.Errorf("read archive input %q: %w", file.Path, err)
			}
			header := &zip.FileHeader{Name: filepath.ToSlash(filepath.Join(root, file.Name)), Method: zip.Deflate}
			header.SetMode(file.Mode.Perm())
			header.Modified = zipTime(epoch)
			entry, err := writer.CreateHeader(header)
			if err != nil {
				_ = writer.Close()
				return err
			}
			if _, err := entry.Write(data); err != nil {
				_ = writer.Close()
				return err
			}
		}
		return writer.Close()
	})
}

// FileDigest calculates the SHA-256 and size of one artifact.
func FileDigest(path string) (Digest, error) {
	// #nosec G304 -- the release caller explicitly selects artifact paths.
	file, err := os.Open(path)
	if err != nil {
		return Digest{}, err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return Digest{}, err
	}
	return Digest{Name: filepath.Base(path), SHA256: hex.EncodeToString(hash.Sum(nil)), Size: size}, nil
}

// WriteChecksums writes a sorted sha256sum-compatible checksum file.
func WriteChecksums(path string, digests []Digest) error {
	values := append([]Digest(nil), digests...)
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	var output strings.Builder
	for _, digest := range values {
		if strings.ContainsAny(digest.Name, "\r\n") {
			return fmt.Errorf("invalid artifact name %q", digest.Name)
		}
		fmt.Fprintf(&output, "%s  %s\n", digest.SHA256, digest.Name)
	}
	return writeAtomically(path, func(writer io.Writer) error {
		_, err := io.WriteString(writer, output.String())
		return err
	})
}

func writeTarFile(writer *tar.Writer, root string, epoch time.Time, file File) error {
	input, err := os.Open(file.Path)
	if err != nil {
		return fmt.Errorf("open archive input %q: %w", file.Path, err)
	}
	defer func() { _ = input.Close() }()
	stat, err := input.Stat()
	if err != nil {
		return err
	}
	header := &tar.Header{
		Name: filepath.ToSlash(filepath.Join(root, file.Name)), Mode: int64(file.Mode.Perm()), Size: stat.Size(),
		ModTime: epoch.UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{}, Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatPAX,
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(writer, input)
	return err
}

func sortedFiles(files []File) []File {
	result := append([]File(nil), files...)
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func zipTime(value time.Time) time.Time {
	minimum := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	if value.Before(minimum) {
		return minimum
	}
	return value.UTC().Truncate(2 * time.Second)
}

func writeAtomically(path string, write func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".rbacviz-release-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := write(temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keep = true
	return nil
}
