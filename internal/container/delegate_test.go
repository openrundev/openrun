package container

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
)

func TestSendDelegateBuild(t *testing.T) {
	t.Run("streams meta and build context", func(t *testing.T) {
		srcDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(srcDir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
			t.Fatalf("write Dockerfile: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(srcDir, "app"), 0o755); err != nil {
			t.Fatalf("mkdir app dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(srcDir, "app", "main.txt"), []byte("hello"), 0o644); err != nil {
			t.Fatalf("write app file: %v", err)
		}

		var gotMeta DelegateRequest
		var gotTarContainsDockerfile bool
		var gotTarContainsAppFile bool

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %q, want POST", r.Method)
			}
			if r.URL.Path != "/_openrun/delegate_build" {
				t.Fatalf("path = %q, want /_openrun/delegate_build", r.URL.Path)
			}

			mr, err := r.MultipartReader()
			if err != nil {
				t.Fatalf("multipart reader: %v", err)
			}

			for {
				part, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("next multipart part: %v", err)
				}

				switch part.FormName() {
				case "meta":
					if err := json.NewDecoder(part).Decode(&gotMeta); err != nil {
						t.Fatalf("decode meta: %v", err)
					}
				case "file":
					fileBytes, err := io.ReadAll(part)
					if err != nil {
						t.Fatalf("read file part: %v", err)
					}

					gzr, err := gzip.NewReader(bytes.NewReader(fileBytes))
					if err != nil {
						t.Fatalf("gzip reader: %v", err)
					}
					tr := tar.NewReader(gzr)
					for {
						hdr, err := tr.Next()
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Fatalf("read tar header: %v", err)
						}
						if hdr.Name == "Dockerfile" {
							gotTarContainsDockerfile = true
						}
						if hdr.Name == filepath.Join("app", "main.txt") {
							gotTarContainsAppFile = true
						}
					}
					_ = gzr.Close()
				}

				_ = part.Close()
			}

			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		req := DelegateRequest{
			ImageTag:      "sample:latest",
			ContainerFile: "Dockerfile",
			ContainerArgs: map[string]string{"FOO": "BAR"},
			RegistryConfig: &types.RegistryConfig{
				URL: "registry.example.com",
			},
		}

		if err := sendDelegateBuild(srv.URL, req, srcDir); err != nil {
			t.Fatalf("sendDelegateBuild returned error: %v", err)
		}

		if gotMeta.ImageTag != req.ImageTag {
			t.Fatalf("meta ImageTag = %q, want %q", gotMeta.ImageTag, req.ImageTag)
		}
		if gotMeta.ContainerFile != req.ContainerFile {
			t.Fatalf("meta ContainerFile = %q, want %q", gotMeta.ContainerFile, req.ContainerFile)
		}
		if gotMeta.RegistryConfig == nil || gotMeta.RegistryConfig.URL != req.RegistryConfig.URL {
			t.Fatalf("meta RegistryConfig = %#v, want URL %q", gotMeta.RegistryConfig, req.RegistryConfig.URL)
		}
		if !gotTarContainsDockerfile || !gotTarContainsAppFile {
			t.Fatalf("tar content mismatch: Dockerfile=%v app/main.txt=%v", gotTarContainsDockerfile, gotTarContainsAppFile)
		}
	})

	t.Run("returns response status and body on non-2xx", func(t *testing.T) {
		srcDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(srcDir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
			t.Fatalf("write Dockerfile: %v", err)
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream error"))
		}))
		defer srv.Close()

		err := sendDelegateBuild(srv.URL, DelegateRequest{
			ImageTag:      "sample:latest",
			ContainerFile: "Dockerfile",
		}, srcDir)
		if err == nil {
			t.Fatal("sendDelegateBuild should fail for non-2xx response")
		}
		if !strings.Contains(err.Error(), "status 502") {
			t.Fatalf("error = %q, want status code detail", err)
		}
		if !strings.Contains(err.Error(), "upstream error") {
			t.Fatalf("error = %q, want response body detail", err)
		}
	})
}

func TestDelegateHandler(t *testing.T) {
	baseConfig := &types.ServerConfig{
		Builder: types.BuilderConfig{Mode: "auto"},
	}
	logger := newTestLogger()

	t.Run("rejects non-POST requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/_openrun/delegate_build", nil)
		rr := httptest.NewRecorder()

		DelegateHandler(rr, req, baseConfig, logger)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
		}
		if !strings.Contains(rr.Body.String(), "only POST allowed") {
			t.Fatalf("body = %q, want method error", rr.Body.String())
		}
	})

	t.Run("rejects unsupported builder mode", func(t *testing.T) {
		cfg := &types.ServerConfig{
			Builder: types.BuilderConfig{Mode: "kaniko"},
		}
		req := httptest.NewRequest(http.MethodPost, "/_openrun/delegate_build", nil)
		rr := httptest.NewRecorder()

		DelegateHandler(rr, req, cfg, logger)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
		if !strings.Contains(rr.Body.String(), "deleted builder mode not supported") {
			t.Fatalf("body = %q, want unsupported mode error", rr.Body.String())
		}
	})

	t.Run("rejects non-multipart requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/_openrun/delegate_build", strings.NewReader(`{"a":"b"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		DelegateHandler(rr, req, baseConfig, logger)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rr.Body.String(), "expected multipart/form-data") {
			t.Fatalf("body = %q, want multipart error", rr.Body.String())
		}
	})

	t.Run("requires registry url in meta", func(t *testing.T) {
		body, contentType := buildDelegateMultipartBody(t, DelegateRequest{
			ImageTag:      "sample:latest",
			ContainerFile: "Dockerfile",
			RegistryConfig: &types.RegistryConfig{
				URL: "",
			},
		}, true)

		req := httptest.NewRequest(http.MethodPost, "/_openrun/delegate_build", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()

		DelegateHandler(rr, req, baseConfig, logger)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
		if !strings.Contains(rr.Body.String(), "registry url needs to be set on the sender") {
			t.Fatalf("body = %q, want registry URL error", rr.Body.String())
		}
	})

	t.Run("returns bad request when file part is missing", func(t *testing.T) {
		body, contentType := buildDelegateMultipartBody(t, DelegateRequest{
			ImageTag:      "sample:latest",
			ContainerFile: "Dockerfile",
			RegistryConfig: &types.RegistryConfig{
				URL: "registry.example.com",
			},
		}, false)

		req := httptest.NewRequest(http.MethodPost, "/_openrun/delegate_build", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()

		DelegateHandler(rr, req, baseConfig, logger)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rr.Body.String(), "missing meta or file part") {
			t.Fatalf("body = %q, want missing part error", rr.Body.String())
		}
	})

	t.Run("rejects invalid meta json", func(t *testing.T) {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		metaPart, err := writer.CreateFormField("meta")
		if err != nil {
			t.Fatalf("create meta field: %v", err)
		}
		if _, err := io.WriteString(metaPart, "{not-json"); err != nil {
			t.Fatalf("write invalid meta json: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart writer: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/_openrun/delegate_build", &buf)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		rr := httptest.NewRecorder()

		DelegateHandler(rr, req, baseConfig, logger)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rr.Body.String(), "invalid meta json") {
			t.Fatalf("body = %q, want invalid json error", rr.Body.String())
		}
	})
}

func TestExtractTarGzToTemp(t *testing.T) {
	t.Run("extracts regular files and directories", func(t *testing.T) {
		tarPath := filepath.Join(t.TempDir(), "context.tar.gz")
		if err := writeTarGz(tarPath, []testTarEntry{
			{name: "nested", typ: tar.TypeDir, mode: 0o755},
			{name: "nested/file.txt", body: "hello", typ: tar.TypeReg, mode: 0o644},
			{name: "Dockerfile", body: "FROM scratch\n", typ: tar.TypeReg, mode: 0o644},
		}); err != nil {
			t.Fatalf("write tar.gz: %v", err)
		}

		destDir, err := extractTarGzToTemp(tarPath)
		if err != nil {
			t.Fatalf("extractTarGzToTemp returned error: %v", err)
		}
		defer os.RemoveAll(destDir) // nolint:errcheck

		gotNested, err := os.ReadFile(filepath.Join(destDir, "nested", "file.txt"))
		if err != nil {
			t.Fatalf("read extracted nested file: %v", err)
		}
		if string(gotNested) != "hello" {
			t.Fatalf("nested file content = %q, want %q", string(gotNested), "hello")
		}

		gotDockerfile, err := os.ReadFile(filepath.Join(destDir, "Dockerfile"))
		if err != nil {
			t.Fatalf("read extracted Dockerfile: %v", err)
		}
		if string(gotDockerfile) != "FROM scratch\n" {
			t.Fatalf("Dockerfile content = %q, want %q", string(gotDockerfile), "FROM scratch\n")
		}
	})

	t.Run("rejects traversal paths", func(t *testing.T) {
		tarPath := filepath.Join(t.TempDir(), "context.tar.gz")
		if err := writeTarGz(tarPath, []testTarEntry{
			{name: "../evil.txt", body: "bad", typ: tar.TypeReg, mode: 0o644},
		}); err != nil {
			t.Fatalf("write tar.gz: %v", err)
		}

		_, err := extractTarGzToTemp(tarPath)
		if err == nil {
			t.Fatal("extractTarGzToTemp should fail for traversal entries")
		}
		if !strings.Contains(err.Error(), "invalid tar entry path") {
			t.Fatalf("error = %q, want traversal path error", err)
		}
	})
}

type testTarEntry struct {
	name string
	body string
	typ  byte
	mode int64
}

func writeTarGz(path string, entries []testTarEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close() // nolint:errcheck

	gzw := gzip.NewWriter(f)
	defer gzw.Close() // nolint:errcheck

	tw := tar.NewWriter(gzw)
	defer tw.Close() // nolint:errcheck

	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     entry.name,
			Typeflag: entry.typ,
			Mode:     entry.mode,
			Size:     int64(len(entry.body)),
		}
		if entry.typ == tar.TypeDir {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if entry.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(entry.body)); err != nil {
				return err
			}
		}
	}

	return nil
}

func buildDelegateMultipartBody(t *testing.T, meta DelegateRequest, includeFile bool) (*bytes.Buffer, string) {
	t.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	metaPart, err := writer.CreateFormField("meta")
	if err != nil {
		t.Fatalf("create meta field: %v", err)
	}
	if err := json.NewEncoder(metaPart).Encode(meta); err != nil {
		t.Fatalf("encode meta: %v", err)
	}

	if includeFile {
		filePart, err := writer.CreateFormFile("file", "context.tar.gz")
		if err != nil {
			t.Fatalf("create file field: %v", err)
		}
		if _, err := io.WriteString(filePart, "placeholder"); err != nil {
			t.Fatalf("write file field: %v", err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}

	return &buf, writer.FormDataContentType()
}
