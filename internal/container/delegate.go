// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/openrundev/openrun/internal/types"
)

type DelegateRequest struct {
	ImageTag       string
	ContainerFile  string
	ContainerArgs  map[string]string
	RegistryConfig *types.RegistryConfig
}

func sendDelegateBuild(url string, data DelegateRequest, sourcePath string) error {
	url += "/_openrun/delegate_build"
	// Create a pipe: writer feeds the HTTP request, reader is used as the body
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	// We need the content-type string for the request header *before* we close the writer.
	contentType := writer.FormDataContentType()

	// Build the multipart body in a goroutine so it streams
	go func() {
		// Any error should close the pipe with that error
		defer func() {
			// Close the multipart writer first (writes the final boundary)
			if err := writer.Close(); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			// Then close the pipe writer
			_ = pw.Close()
		}()

		// JSON part
		jsonHdr := textproto.MIMEHeader{}
		jsonHdr.Set("Content-Disposition", `form-data; name="meta"`)
		jsonHdr.Set("Content-Type", "application/json")

		jsonPart, err := writer.CreatePart(jsonHdr)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := json.NewEncoder(jsonPart).Encode(data); err != nil {
			_ = pw.CloseWithError(err)
			return
		}

		// File part (streamed)
		tarStream, err := tarGzDir(sourcePath)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer tarStream.Close() // nolint: errcheck

		filePart, err := writer.CreateFormFile("file", data.ImageTag+"-context.tar.gz")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}

		if _, err := io.Copy(filePart, tarStream); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		// After this, the deferred writer.Close + pw.Close run and finish the body.
	}()

	// Create the request with the pipe reader as body
	req, err := http.NewRequest("POST", url, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)

	// Send it
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close() // nolint: errcheck

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// Read body for debugging
		bodyBytes, _ := io.ReadAll(res.Body)
		return fmt.Errorf("delegated build failed with status %d: %s", res.StatusCode, string(bodyBytes))
	}

	return nil
}

// DelegateHandler is the handler for the delegated build API
func DelegateHandler(w http.ResponseWriter, r *http.Request, config *types.ServerConfig, logger *types.Logger) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	if config.Builder.Mode != "auto" && config.Builder.Mode != "command" {
		http.Error(w, fmt.Sprintf("deleted builder mode not supported: %s", config.Builder.Mode), http.StatusInternalServerError)
		return
	}

	// Parse Content-Type to get boundary
	ct := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		http.Error(w, "expected multipart/form-data", http.StatusBadRequest)
		return
	}

	boundary, ok := params["boundary"]
	if !ok {
		http.Error(w, "missing multipart boundary", http.StatusBadRequest)
		return
	}

	mr := multipart.NewReader(r.Body, boundary)

	var (
		data      DelegateRequest
		gotMeta   bool
		gotFile   bool
		savedFile string
	)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("reading part: %v", err), http.StatusInternalServerError)
			return
		}

		name := part.FormName()

		switch name {
		case "meta":
			// Stream-decode JSON for meta
			if err := json.NewDecoder(part).Decode(&data); err != nil {
				http.Error(w, fmt.Sprintf("invalid meta json: %v", err), http.StatusBadRequest)
				_ = part.Close()
				return
			}
			gotMeta = true

		case "file":
			// Stream file to disk (or wherever you want)
			filename := part.FileName()
			if filename == "" {
				filename = "uploaded.bin"
			}
			dstPath := filepath.Join(os.TempDir(), filename)

			dst, err := os.Create(dstPath)
			if err != nil {
				http.Error(w, fmt.Sprintf("error creating file: %v", err), http.StatusInternalServerError)
				_ = part.Close()
				return
			}

			if _, err := io.Copy(dst, part); err != nil {
				_ = dst.Close()
				http.Error(w, fmt.Sprintf("error saving file: %v", err), http.StatusInternalServerError)
				_ = part.Close()
				return
			}
			_ = dst.Close()

			savedFile = dstPath
			gotFile = true

		default:
			// Ignore any extra fields; just drain them
			_, _ = io.Copy(io.Discard, part)
		}

		_ = part.Close()
	}

	if data.RegistryConfig.URL == "" {
		http.Error(w, "registry url needs to be set on the sender for delegated builds", http.StatusInternalServerError)
		return
	}

	if !gotMeta || !gotFile {
		http.Error(w, "missing meta or file part", http.StatusBadRequest)
		return
	}
	logger.Debug().Msgf("DelegateHandler called for build %s", data.ImageTag)
	defer func() {
		if err := os.Remove(savedFile); err != nil {
			http.Error(w, fmt.Sprintf("error removing file: %v", err), http.StatusInternalServerError)
			return
		}
	}()

	err = delegateBuild(r.Context(), logger, config, data, savedFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("error delegating build: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func delegateBuild(ctx context.Context, logger *types.Logger, config *types.ServerConfig, data DelegateRequest, filePath string) error {
	destDir, err := extractTarGzToTemp(filePath)
	if err != nil {
		return fmt.Errorf("extract tar.gz: %w", err)
	}
	defer os.RemoveAll(destDir) // nolint: errcheck

	releaseLock, err := acquireBuildLock(context.Background(), &config.System, data.ImageTag)
	if err != nil {
		return fmt.Errorf("error acquiring build lock: %w", err)
	}
	defer releaseLock()

	logger.Debug().Msgf("Building image %s from %s with %s", data.ImageTag, data.ContainerFile, destDir)
	args := []string{config.System.ContainerCommand, "build", "-t", data.ImageTag, "-f", data.ContainerFile}

	for k, v := range data.ContainerArgs {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, ".")
	cmd := exec.Command(args[0], args[1:]...)

	logger.Debug().Msgf("Running command: %s", cmd.String())
	cmd.Dir = destDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error building image: %s : %s", output, err)
	}

	remoteTag := data.RegistryConfig.URL + "/" + data.ImageTag
	if config.Registry.Project != "" {
		remoteTag = data.RegistryConfig.URL + "/" + data.RegistryConfig.Project + "/" + data.ImageTag
	}

	srcRef, err := name.ParseReference(data.ImageTag) // local tags don’t need Insecure
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}

	localImg, err := daemon.Image(srcRef, daemon.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("read image from docker daemon: %w", err)
	}

	logger.Debug().Msgf("Getting remote registry config for %s", data.ImageTag)
	remoteRef, remoteOpts, err := GetDockerConfig(ctx, data.ImageTag, data.RegistryConfig)
	if err != nil {
		return fmt.Errorf("get remote registry config: %w", err)
	}

	err = remote.Write(remoteRef, localImg, remoteOpts...)
	if err != nil {
		logger.Error().Msgf("write image to remote registry: %v", err)
		return fmt.Errorf("write image to remote registry: %w", err)
	}

	logger.Info().Msgf("Image %s written to remote registry %s", data.ImageTag, remoteTag)
	return nil
}

// extractTarGzToTemp extracts the given .tar.gz file into a new temp directory.
// It returns the temp directory path on success.
func extractTarGzToTemp(tarGzPath string) (string, error) {
	// Open the input file
	f, err := os.Open(tarGzPath)
	if err != nil {
		return "", fmt.Errorf("open tar.gz: %w", err)
	}
	defer f.Close() // nolint: errcheck

	// Wrap in gzip reader
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("new gzip reader: %w", err)
	}
	defer gzr.Close() // nolint: errcheck

	// Create a temp directory
	destDir, err := os.MkdirTemp("", "delegate-build-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	// If we error later, clean up the temp dir
	cleanupOnErr := true
	defer func() {
		if cleanupOnErr {
			_ = os.RemoveAll(destDir)
		}
	}()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // done
		}
		if err != nil {
			return "", fmt.Errorf("read tar header: %w", err)
		}
		if hdr == nil {
			continue
		}

		// Clean and join the path to avoid traversal attacks
		relPath := filepath.Clean(hdr.Name)
		if relPath == "." {
			continue
		}

		targetPath := filepath.Join(destDir, relPath)

		// Ensure targetPath is still under destDir
		if !strings.HasPrefix(targetPath, destDir+string(os.PathSeparator)) && targetPath != destDir {
			return "", fmt.Errorf("invalid tar entry path: %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(hdr.Mode)); err != nil {
				return "", fmt.Errorf("mkdir %s: %w", targetPath, err)
			}

		case tar.TypeReg:
			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return "", fmt.Errorf("mkdir for file %s: %w", targetPath, err)
			}

			out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return "", fmt.Errorf("create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return "", fmt.Errorf("write file %s: %w", targetPath, err)
			}
			_ = out.Close()

		default:
			// For now, ignore other entry types.
		}
	}

	// Success: do not remove temp dir
	cleanupOnErr = false
	return destDir, nil
}
