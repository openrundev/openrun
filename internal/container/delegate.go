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
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/telemetry"
	"github.com/openrundev/openrun/internal/types"
)

type DelegateRequest struct {
	ImageTag       string
	ContainerFile  string
	ContainerArgs  map[string]string
	RegistryConfig *types.RegistryConfig
}

func sendDelegateBuild(url string, data DelegateRequest, sourcePath string, builderAuthToken string) error {
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
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", builderAuthToken))

	// Send it
	client := &http.Client{Transport: telemetry.WrapTransport(http.DefaultTransport)}
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
func DelegateHandler(r *http.Request, config *types.ServerConfig, logger *types.Logger) (any, error) {
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("only POST allowed")
	}

	if config.Builder.Mode != "delegate_server" {
		return nil, fmt.Errorf("delegated builder mode not supported: %s", config.Builder.Mode)
	}

	// Parse Content-Type to get boundary
	ct := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return nil, fmt.Errorf("expected multipart/form-data")
	}

	boundary, ok := params["boundary"]
	if !ok {
		return nil, fmt.Errorf("missing multipart boundary")
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
			return nil, fmt.Errorf("reading part: %v", err)
		}

		name := part.FormName()

		switch name {
		case "meta":
			// Stream-decode JSON for meta
			if err := json.NewDecoder(part).Decode(&data); err != nil {
				_ = part.Close()
				return nil, fmt.Errorf("invalid meta json: %v", err)
			}
			gotMeta = true

		case "file":
			dst, err := os.CreateTemp("", "delegate-build-*.tar.gz")
			if err != nil {
				_ = part.Close()
				return nil, fmt.Errorf("error creating file: %v", err)
			}

			if _, err := io.Copy(dst, part); err != nil {
				_ = dst.Close()
				_ = part.Close()
				return nil, fmt.Errorf("error saving file: %v", err)
			}
			_ = dst.Close()

			savedFile = dst.Name()
			gotFile = true

		default:
			// Ignore any extra fields; just drain them
			_, _ = io.Copy(io.Discard, part)
		}

		_ = part.Close()
	}

	if data.RegistryConfig.URL == "" {
		return nil, fmt.Errorf("registry url needs to be set on the sender for delegated builds")
	}

	if !gotMeta || !gotFile {
		return nil, fmt.Errorf("missing meta or file part")
	}
	logger.Debug().Msgf("DelegateHandler called for build %s", data.ImageTag)
	defer func() {
		if err := os.Remove(savedFile); err != nil {
			logger.Error().Err(err).Msg("error removing file")
			return
		}
	}()

	err = delegateBuild(r.Context(), logger, config, data, savedFile)
	if err != nil {
		return nil, fmt.Errorf("error delegating build: %v", err)
	}

	return nil, nil
}

func delegateBuild(ctx context.Context, logger *types.Logger, config *types.ServerConfig, data DelegateRequest, filePath string) error {
	destDir, err := extractTarGzToTemp(filePath)
	if err != nil {
		return fmt.Errorf("extract tar.gz: %w", err)
	}
	defer os.RemoveAll(destDir) // nolint: errcheck

	cleanFile, err := system.CleanRelativeLocalPath(data.ContainerFile)
	if err != nil {
		return fmt.Errorf("invalid container file path %q: %w", data.ContainerFile, err)
	}

	releaseLock, err := acquireBuildLock(context.Background(), &config.System, data.ImageTag)
	if err != nil {
		return fmt.Errorf("error acquiring build lock: %w", err)
	}
	defer releaseLock()

	logger.Debug().Msgf("Building image %s from %s with %s", data.ImageTag, cleanFile, destDir)
	args := []string{"build", "-t", data.ImageTag, "-f", cleanFile}

	for k, v := range data.ContainerArgs {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, ".")
	cmd := exec.Command(config.System.ContainerCommand, args...)

	logger.Debug().Msgf("Running command: %s %s", config.System.ContainerCommand, cmd.String())
	cmd.Dir = destDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error building image: %s : %s", output, err)
	}

	err = pushToRemoteRegistry(ctx, logger, config, data.ImageTag, data.RegistryConfig)
	if err != nil {
		return fmt.Errorf("error pushing image to remote registry: %w", err)
	}

	return nil
}

func pushToRemoteRegistry(ctx context.Context, logger *types.Logger, config *types.ServerConfig, imageTag string, registryConfig *types.RegistryConfig) error {
	remoteTag := registryConfig.URL + "/" + imageTag
	if config.Registry.Project != "" {
		remoteTag = registryConfig.URL + "/" + registryConfig.Project + "/" + imageTag
	}

	srcRef, err := name.ParseReference(imageTag)
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}

	localImg, err := daemon.Image(srcRef, daemon.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("read image from docker daemon: %w", err)
	}

	logger.Debug().Msgf("Getting remote registry config for %s", imageTag)
	remoteRef, remoteOpts, err := GetDockerConfig(ctx, imageTag, registryConfig)
	if err != nil {
		return fmt.Errorf("get remote registry config: %w", err)
	}

	err = remote.Write(remoteRef, localImg, remoteOpts...)
	if err != nil {
		logger.Error().Msgf("write image to remote registry: %v", err)
		return fmt.Errorf("write image to remote registry: %w", err)
	}

	logger.Info().Msgf("Image %s written to remote registry %s", imageTag, remoteTag)
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

		targetPath, err := system.PathInDir(destDir, hdr.Name)
		if err != nil {
			return "", fmt.Errorf("invalid tar entry path %q: %w", hdr.Name, err)
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
