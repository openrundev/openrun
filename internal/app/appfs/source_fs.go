// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package appfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ReadableFS is the interface for the file system used by app to read source files
type ReadableFS interface {
	fs.FS
	fs.ReadFileFS
	fs.GlobFS
	// Stat returns the stats for the named file.
	Stat(name string) (fs.FileInfo, error)
	StatNoSpec(name string) (fs.FileInfo, error)   // Stat the FS without looking at spec files
	Reset()                                        // Used to reset the file system transaction for the DbFs, no-op for others
	StaticFiles() []string                         // Return list of static files
	FileHash(excludeGlob []string) (string, error) // Return a hash of the source file contents
	CreateTempSourceDir() (string, error)          // Create a temporary directory with source files
}

type CompressedReader interface {
	ReadCompressed() (data []byte, compressionType string, err error)
}

// WritableFS is the interface for the writable underlying file system used by AppFS
type WritableFS interface {
	ReadableFS
	Write(name string, bytes []byte) error
	Remove(name string) error
}

// SourceFs is the implementation of source file system
type SourceFs struct {
	ReadableFS
	Root  string
	isDev bool

	staticFiles []string
	mu          sync.RWMutex
	nameToHash  map[string]string    // lookup (path to hash path)
	hashToName  map[string][2]string // reverse lookup (hash path to path)
}

var _ ReadableFS = (*SourceFs)(nil)

type WritableSourceFs struct {
	*SourceFs
}

var _ WritableFS = (*WritableSourceFs)(nil)

func (w *WritableSourceFs) Write(name string, bytes []byte) error {
	if !w.isDev {
		return fmt.Errorf("cannot write to source fs")
	}
	wfs, ok := w.ReadableFS.(WritableFS)
	if !ok {
		return fmt.Errorf("cannot write to source fs (not writable mode)")
	}
	return wfs.Write(name, bytes)
}

func (w *WritableSourceFs) Remove(name string) error {
	if !w.isDev {
		return fmt.Errorf("cannot remove file from source fs")
	}
	wfs, ok := w.ReadableFS.(WritableFS)
	if !ok {
		return fmt.Errorf("cannot remove file from source fs (not writable mode)")
	}
	return wfs.Remove(name)
}

func NewSourceFs(dir string, fs ReadableFS, isDev bool) (*SourceFs, error) {
	staticFiles := fs.StaticFiles()

	return &SourceFs{
		Root:        dir,
		ReadableFS:  fs,
		isDev:       isDev,
		staticFiles: staticFiles,

		// File hashing code based on https://github.com/benbjohnson/hashfs/blob/main/hashfs.go
		// Copyright (c) 2020 Ben Johnson. MIT License
		nameToHash: make(map[string]string),
		hashToName: make(map[string][2]string)}, nil
}

func (f *SourceFs) StaticFiles() []string {
	return f.staticFiles
}

func (f *SourceFs) ClearCache() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.nameToHash)
	clear(f.hashToName)
}

func (f *SourceFs) Glob(pattern string) ([]string, error) {
	return fs.Glob(f.ReadableFS, pattern)
}

func (f *SourceFs) ParseFS(funcMap template.FuncMap, patterns ...string) (*template.Template, error) {
	return template.New("openrunapp").Funcs(funcMap).ParseFS(f.ReadableFS, patterns...)
}

func (f *SourceFs) Stat(name string) (fs.FileInfo, error) {
	return f.ReadableFS.Stat(name)
}

// Open returns a reference to the named file.
// If name is a hash name then the underlying file is used.
func (f *SourceFs) Open(name string) (fs.File, error) {
	fi, _, err := f.open(name)
	return fi, err
}

func (f *SourceFs) open(name string) (_ fs.File, hash string, err error) {
	// Parse filename to see if it contains a hash.
	// If so, check if hash name matches.
	base, hash := f.ParseName(name)
	if hash != "" && f.HashName(base) == name {
		name = base
	}

	fi, err := f.ReadableFS.Open(name)
	return fi, hash, err
}

// HashName returns the hash name for a path, if exists.
// Otherwise returns the original path.
func (f *SourceFs) HashName(name string) string {
	// Lookup cached formatted name, if exists.
	f.mu.RLock()
	if s := f.nameToHash[name]; s != "" {
		f.mu.RUnlock()
		return s
	}
	f.mu.RUnlock()

	// Read file contents. Return original filename if we receive an error.
	buf, err := fs.ReadFile(f.ReadableFS, name)
	if err != nil {
		fmt.Printf("HashName readfile error: %s %s\n", err, name) //TODO: log
		return name
	}

	// Compute hash and build filename.
	hash := sha256.Sum256(buf)
	hashhex := hex.EncodeToString(hash[:])
	hashname := FormatName(name, hashhex)

	// Store in lookups.
	f.mu.Lock()
	f.nameToHash[name] = hashname
	f.hashToName[hashname] = [2]string{name, hashhex}
	f.mu.Unlock()

	return hashname
}

// FormatName returns a hash name that inserts hash before the filename's
// extension. If no extension exists on filename then the hash is appended.
// Returns blank string the original filename if hash is blank. Returns a blank
// string if the filename is blank.
func FormatName(filename, hash string) string {
	if filename == "" {
		return ""
	} else if hash == "" {
		return filename
	}

	dir, base := path.Split(filename)
	if i := strings.Index(base, "."); i != -1 {
		return path.Join(dir, fmt.Sprintf("%s-%s%s", base[:i], hash, base[i:]))
	}
	return path.Join(dir, fmt.Sprintf("%s-%s", base, hash))
}

// ParseName splits formatted hash filename into its base & hash components.
func (f *SourceFs) ParseName(filename string) (base, hash string) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if hashed, ok := f.hashToName[filename]; ok {
		return hashed[0], hashed[1]
	}

	return ParseName(filename)
}

// ParseName splits formatted hash filename into its base & hash components.
func ParseName(filename string) (base, hash string) {
	if filename == "" {
		return "", ""
	}

	dir, base := path.Split(filename)

	// Extract pre-hash & extension.
	pre, ext := base, ""
	if i := strings.Index(base, "."); i != -1 {
		pre = base[:i]
		ext = base[i:]
	}

	// If prehash doesn't contain the hash, then exit.
	if !hashSuffixRegex.MatchString(pre) {
		return filename, ""
	}

	return path.Join(dir, pre[:len(pre)-65]+ext), pre[len(pre)-64:]
}

var hashSuffixRegex = regexp.MustCompile(`-[0-9a-f]{64}`)

// FileServer returns an http.Handler for serving FS files. It provides a
// simplified implementation of http.FileServer which is used to aggressively
// cache files on the client since the file hash is in the filename.
//
// Because FileServer is focused on small known path files, several features
// of http.FileServer have been removed including canonicalizing directories,
// defaulting index.html pages, precondition checks, & content range headers.
func FileServer(fsys *SourceFs, indexPage string) http.Handler {
	return &fsHandler{fsys: fsys, indexPage: indexPage}
}

func FileServerSingle(fsys *SourceFs, indexPage string) http.Handler {
	return &fsHandler{fsys: fsys, indexPage: indexPage, singleFile: true}
}

type fsHandler struct {
	fsys       *SourceFs
	indexPage  string
	singleFile bool
}

func (h *fsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Clean up filename based on URL path.
	filename := r.URL.Path
	filename = strings.TrimPrefix(filename, "/")
	filename = path.Clean(filename)
	if filename == "/" || filename == "." {
		filename = h.indexPage
	}

	if h.singleFile && filename != h.indexPage {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	// Read file from attached file system.
	f, hash, err := h.fsys.open(filename)
	if os.IsNotExist(err) {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "500 Error serving static file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close() //nolint:errcheck

	// Fetch file info. Disallow directories from being displayed.
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	} else if fi.IsDir() {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// Cache the file aggressively if the file contains a hash.
	if hash != "" {
		w.Header().Set("Cache-Control", `public, max-age=31536000`)
		w.Header().Set("ETag", "\""+hash+"\"")
	}

	seeker, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "500 Filesystem does not implement Seek interface", http.StatusInternalServerError)
		return
	}

	// If this is a request without Range headers and brotli encoding is accepted,
	// Return the data which is already in a compressed form
	served, err := h.serveCompressed(w, r, filename, fi.ModTime(), seeker)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if served {
		return
	}

	http.ServeContent(w, r, filename, fi.ModTime(), seeker)
}

const COMPRESSION_TYPE = "br" // brotli uses br as the encoding type

func (h *fsHandler) canServeCompressed(r *http.Request) bool {
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		// Range headers are being used, fallback to http.ServeContent
		return false
	}

	encodingHeader := r.Header.Get("Accept-Encoding")
	acceptedEncodings := strings.Split(strings.ToLower(encodingHeader), ",")
	brotliMatchFound := false

	for _, acceptedEncoding := range acceptedEncodings {
		if strings.TrimSpace(acceptedEncoding) == COMPRESSION_TYPE {
			brotliMatchFound = true
			break
		}
	}

	return brotliMatchFound
}

var unixEpochTime = time.Unix(0, 0)

// serveCompressed checks if the compressed file data can be streamed directly to the client, without
// the need to decompress and then recompress. If the client accepts brotli compressed data and there are no
// range headers, then this optimization can be used.
func (h *fsHandler) serveCompressed(w http.ResponseWriter, r *http.Request, filename string, modtime time.Time, content io.ReadSeeker) (bool, error) {
	if !h.canServeCompressed(r) {
		return false, nil
	}
	compressedReader, ok := content.(CompressedReader)
	if !ok {
		return false, nil
	}

	data, compressionType, err := compressedReader.ReadCompressed()
	if err != nil {
		return false, err
	}

	if compressionType != COMPRESSION_TYPE {
		// the data is not compressed with brotli, fallback to http.ServeContent
		return false, nil
	}

	contentType := mime.TypeByExtension(filepath.Ext(filename))
	if contentType == "" {
		return false, nil
	}

	if !modtime.IsZero() && !modtime.Equal(unixEpochTime) {
		w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Encoding", COMPRESSION_TYPE)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("X-OpenRun-Compressed", "true")
	w.Header().Add("Vary", "Accept-Encoding")
	w.WriteHeader(http.StatusOK)
	w.Write(data) //nolint:errcheck

	return true, nil
}
