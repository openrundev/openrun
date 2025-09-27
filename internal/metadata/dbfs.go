// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/types"
)

type DbFs struct {
	*types.Logger
	fileStore *FileStore
	fileInfo  map[string]DbFileInfo
	specFiles types.SpecFiles
}

var _ appfs.ReadableFS = (*DbFs)(nil)

func NewDbFs(logger *types.Logger, fileStore *FileStore, specFiles types.SpecFiles) (*DbFs, error) {
	fileInfo, error := fileStore.getFileInfo()
	if error != nil {
		return nil, error
	}
	return &DbFs{
		Logger:    logger,
		fileStore: fileStore,
		fileInfo:  fileInfo,
		specFiles: specFiles,
	}, nil
}

type DbFile struct {
	name   string
	fi     DbFileInfo
	reader *DbFileReader
}

var _ fs.File = (*DbFile)(nil)

func NewDBFile(name string, compressionType string, data []byte, fi DbFileInfo) *DbFile {
	reader := NewDbFileReader(compressionType, data)
	return &DbFile{name: name, fi: fi, reader: reader}
}

func (f *DbFile) Read(dst []byte) (int, error) {
	return f.reader.Read(dst)
}

func (f *DbFile) Name() string {
	return f.name
}

func (f *DbFile) Stat() (fs.FileInfo, error) {
	return &f.fi, nil
}

func (f *DbFile) Seek(offset int64, whence int) (int64, error) {
	// Seek is called by http.ServeContent in source_fs for the unoptimized case only
	// The data is decompressed and then recompressed if required in the unoptimized case
	return f.reader.Seek(offset, whence)
}

func (f *DbFile) ReadCompressed() ([]byte, string, error) {
	return f.reader.ReadCompressed()
}

func (f *DbFile) Close() error {
	return nil
}

type DbFileReader struct {
	compressionType    string
	compressedReader   *bytes.Reader
	uncompressedReader *bytes.Reader
}

var _ io.ReadSeeker = (*DbFileReader)(nil)
var _ appfs.CompressedReader = (*DbFileReader)(nil)

func NewDbFileReader(compressionType string, data []byte) *DbFileReader {
	compressedReader := bytes.NewReader(data)
	return &DbFileReader{compressionType: compressionType, compressedReader: compressedReader}
}

func (f *DbFileReader) uncompress() error {
	switch f.compressionType {
	case "":
		f.uncompressedReader = f.compressedReader
	case appfs.COMPRESSION_TYPE:
		br := brotli.NewReader(f.compressedReader)
		uncompressed, err := io.ReadAll(br)
		if err != nil {
			return err
		}
		f.uncompressedReader = bytes.NewReader(uncompressed)
	default:
		return fmt.Errorf("unsupported compression type: %s", f.compressionType)
	}
	return nil
}

func (f *DbFileReader) Seek(offset int64, whence int) (int64, error) {
	if f.uncompressedReader == nil {
		if err := f.uncompress(); err != nil {
			return 0, err
		}
	}

	return f.uncompressedReader.Seek(offset, whence)
}

func (f *DbFileReader) Read(dst []byte) (int, error) {
	if f.uncompressedReader == nil {
		if err := f.uncompress(); err != nil {
			return 0, err
		}
	}

	return f.uncompressedReader.Read(dst)
}

func (f *DbFileReader) ReadCompressed() ([]byte, string, error) {
	data, err := io.ReadAll(f.compressedReader)
	return data, f.compressionType, err
}

type DbFileInfo struct {
	name    string
	len     int64
	sha     string
	modTime time.Time
}

var _ fs.FileInfo = (*DbFileInfo)(nil)

func (fi *DbFileInfo) Name() string {
	return fi.name
}

func (fi *DbFileInfo) Size() int64 {
	return fi.len
}
func (fi *DbFileInfo) Mode() fs.FileMode {
	return 0
}
func (fi *DbFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi *DbFileInfo) IsDir() bool {
	return false
}
func (fi *DbFileInfo) Sys() any {
	return nil
}

func computeSha(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (d *DbFs) Open(name string) (fs.File, error) {
	fi, ok := d.fileInfo[name]
	if !ok {
		// Check if the spec files has it
		if _, ok = d.specFiles[name]; ok {
			return &DbFile{
				name: name,
				fi: DbFileInfo{
					name:    name,
					len:     int64(len(d.specFiles[name])),
					sha:     computeSha(d.specFiles[name]),
					modTime: time.Time{}},
				reader: NewDbFileReader("", []byte(d.specFiles[name])),
			}, nil
		}
		return nil, fs.ErrNotExist
	}
	fileBytes, compressionType, err := d.fileStore.GetFileBySha(fi.sha)
	if err != nil {
		return nil, err
	}
	return NewDBFile(name, compressionType, fileBytes, fi), nil
}

func (d *DbFs) ReadFile(name string) ([]byte, error) {
	fi, ok := d.fileInfo[name]
	if !ok {
		// Check if the spec files has it
		if _, ok = d.specFiles[name]; ok {
			return []byte(d.specFiles[name]), nil
		}
		return nil, fs.ErrNotExist
	}
	fileBytes, compressionType, err := d.fileStore.GetFileBySha(fi.sha)
	if err != nil {
		return nil, err
	}
	if compressionType != "" {
		if compressionType != appfs.COMPRESSION_TYPE {
			return nil, fmt.Errorf("unsupported compression type: %s", compressionType)
		}
		gz := brotli.NewReader(bytes.NewReader(fileBytes))
		fileBytes, err = io.ReadAll(gz)
		if err != nil {
			return nil, err
		}
	}

	return fileBytes, err

}

func (d *DbFs) Stat(name string) (fs.FileInfo, error) {
	fi, ok := d.fileInfo[name]
	if !ok {
		// Check if the spec files has it
		if _, ok = d.specFiles[name]; ok {
			return &DbFileInfo{name: name,
				len:     int64(len(d.specFiles[name])),
				sha:     computeSha(d.specFiles[name]),
				modTime: time.Time{}}, nil
		}
		return nil, fs.ErrNotExist
	}
	return &fi, nil
}

func (d *DbFs) StatNoSpec(name string) (fs.FileInfo, error) {
	fi, ok := d.fileInfo[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return &fi, nil
}

func (d *DbFs) Glob(pattern string) (matches []string, err error) {
	matchedFiles := []string{}
	for name := range d.fileInfo {
		if matched, _ := path.Match(pattern, name); matched {
			matchedFiles = append(matchedFiles, name)
		}
	}

	return matchedFiles, nil
}

func (d *DbFs) StaticFiles() []string {
	staticFiles := []string{}
	for name := range d.fileInfo {
		if strings.HasPrefix(name, "static/") || strings.HasPrefix(name, "static_root/") {
			staticFiles = append(staticFiles, name)
		}
	}
	return staticFiles
}

// GlobMatch returns true if the file name matches any of the patterns
func GlobMatch(patterns []string, fileName string) (bool, error) {
	for _, pattern := range patterns {
		matched, err := doublestar.Match(pattern, fileName)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}

	return false, nil
}

// FileHash returns a hash of the file names and their corresponding sha256 hashes
func (d *DbFs) FileHash(excludeGlob []string) (string, error) {
	fileNames := []string{}
	for name := range d.fileInfo {
		matched, err := GlobMatch(excludeGlob, name)
		if err != nil {
			return "", err
		}
		if matched {
			// Name is excluded from the hash, must be a file used by the openrun hypermedia based UI
			// We don't want a UI only change to cause a container rebuild
			continue
		}
		fileNames = append(fileNames, name)
	}
	slices.Sort(fileNames)

	hashBuilder := strings.Builder{}
	for _, name := range fileNames {
		hashBuilder.WriteString(name)
		hashBuilder.WriteByte(0)
		hashBuilder.WriteString(d.fileInfo[name].sha)
		hashBuilder.WriteByte(0)
	}

	specFileNames := []string{}
	for name := range d.specFiles {
		matched, err := GlobMatch(excludeGlob, name)
		if err != nil {
			return "", err
		}
		if matched {
			// Name is excluded from the hash, must be a file used by the openrun hypermedia based UI
			// We don't want a UI only change to cause a container rebuild
			continue
		}

		specFileNames = append(specFileNames, name)
	}
	slices.Sort(specFileNames)

	for _, name := range specFileNames {
		if _, ok := d.fileInfo[name]; !ok {
			// Only include spec files that are not already in the file info
			hashBuilder.WriteString(name)
			hashBuilder.WriteByte(0)
			hashBuilder.WriteString(computeSha(d.specFiles[name]))
			hashBuilder.WriteByte(0)
		}
	}

	sha := sha256.New()
	if _, err := sha.Write([]byte(hashBuilder.String())); err != nil {
		return "", err
	}

	return hex.EncodeToString(sha.Sum(nil)), nil
}

func (d *DbFs) CreateTempSourceDir() (string, error) {
	tmpDir, err := os.MkdirTemp("", "cl_source")
	if err != nil {
		return "", fmt.Errorf("error creating temp source dir: %w", err)
	}

	for name := range d.fileInfo {
		fileBytes, err := d.ReadFile(name)
		if err != nil {
			return "", err
		}
		filePath := path.Join(tmpDir, name)

		if err := os.MkdirAll(path.Dir(filePath), 0700); err != nil {
			return "", fmt.Errorf("error creating directory %s : %w", path.Dir(filePath), err)
		}

		if err := os.WriteFile(filePath, fileBytes, 0700); err != nil {
			return "", fmt.Errorf("error writing file %s : %w", filePath, err)
		}
	}

	for name := range d.specFiles {
		if _, ok := d.fileInfo[name]; ok {
			// Skip files that are already in the file info
			continue
		}

		filePath := path.Join(tmpDir, name)
		if err := os.MkdirAll(path.Dir(filePath), 0700); err != nil {
			return "", fmt.Errorf("error creating directory %s : %w", path.Dir(filePath), err)
		}

		if err := os.WriteFile(filePath, []byte(d.specFiles[name]), 0700); err != nil {
			return "", fmt.Errorf("error writing file %s : %w", filePath, err)
		}
	}

	return tmpDir, nil
}

func (d *DbFs) Reset() {
	d.fileStore.Reset()
}
