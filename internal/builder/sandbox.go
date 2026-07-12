// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sandboxLabel        = "openrun-agent"
	sandboxSessionLabel = "openrun-agent-session"
	buildTimeout        = 15 * time.Minute

	// SandboxLabelFilter selects agent containers in docker/podman ps
	// (used by the console containers view). "Agent" is the term for the
	// app builder's AI containers everywhere in code and APIs; "builder"
	// alone refers to the feature (and kaniko image builds elsewhere)
	SandboxLabelFilter = sandboxLabel + "=1"
	// SandboxSessionLabel carries the owning builder session id
	SandboxSessionLabel = sandboxSessionLabel
)

func contentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

// imageExists checks whether the image tag is present in the local runtime
func imageExists(ctx context.Context, cli, tag string) bool {
	cmd := exec.CommandContext(ctx, cli, "image", "inspect", tag)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// buildImage builds the profile's sandbox image if the content-hash tag is
// not already present. Returns the image tag and the build output on failure
func buildImage(ctx context.Context, cli string, p *profile) (string, error) {
	tag := p.imageTag()
	if imageExists(ctx, cli, tag) {
		return tag, nil
	}

	buildDir, err := os.MkdirTemp("", "openrun-builder-img")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(buildDir) //nolint:errcheck

	if err := os.WriteFile(filepath.Join(buildDir, "Dockerfile"), p.dockerfile, 0600); err != nil {
		return "", err
	}

	buildCtx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(buildCtx, cli, "build", "-t", tag, buildDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("building sandbox image %s: %w\n%s", tag, err, tailBytes(output, 4000))
	}
	return tag, nil
}

func tailBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

// sandbox is one running agent container. Its stdin/stdout carry the ACP
// JSON-RPC stream; stderr is retained (bounded) for diagnostics
type sandbox struct {
	cli           string
	containerName string
	cmd           *exec.Cmd
	stdin         io.WriteCloser
	stdout        io.ReadCloser
	stderrMu      sync.Mutex
	stderrTail    bytes.Buffer
	exited        chan struct{}
}

// startSandbox runs the sandbox container with the session workspace mounted
// at /workspace and the profile's config files mounted at their container
// paths. Secrets in env are passed via the client process environment
// ("-e KEY" form), not on the command line
func startSandbox(cli, image, sessionId, workspace string, p *profile, env map[string]string) (*sandbox, error) {
	containerName := "openrun_agent_" + strings.TrimPrefix(sessionId, "bld_ses_")
	args := []string{
		"run", "-i", "--rm",
		"--name", containerName,
		"--label", sandboxLabel + "=1",
		"--label", sandboxSessionLabel + "=" + sessionId,
		"-v", workspace + ":/workspace",
		"-w", "/workspace",
	}
	for _, mount := range p.configs {
		if _, err := os.Stat(mount.host); err != nil {
			return nil, fmt.Errorf("config file %s not found: %w", mount.host, err)
		}
		volume := mount.host + ":" + mount.container
		if mount.readOnly {
			volume += ":ro"
		}
		args = append(args, "-v", volume)
	}

	cmd := exec.Command(cli, append(append(args, envArgs(env)...), append([]string{image}, p.command...)...)...)
	cmd.Env = append(os.Environ(), envValues(env)...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	s := &sandbox{cli: cli, containerName: containerName, cmd: cmd, stdin: stdin, stdout: stdout, exited: make(chan struct{})}
	cmd.Stderr = &boundedWriter{buf: &s.stderrTail, mu: &s.stderrMu, limit: 16 * 1024}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting sandbox container: %w", err)
	}
	go func() {
		_ = cmd.Wait() // reap; the exit reason is reported via stderrTail
		close(s.exited)
	}()
	return s, nil
}

// envArgs returns "-e KEY" flags (no values, docker/podman read them from the
// client process env, keeping secrets off the command line)
func envArgs(env map[string]string) []string {
	args := make([]string, 0, len(env)*2)
	for key := range env {
		args = append(args, "-e", key)
	}
	return args
}

func envValues(env map[string]string) []string {
	values := make([]string, 0, len(env))
	for key, value := range env {
		values = append(values, key+"="+value)
	}
	return values
}

// stop force-removes the container and waits for the client process to exit
func (s *sandbox) stop() {
	cmd := exec.Command(s.cli, "rm", "-f", s.containerName)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
	s.stdin.Close() //nolint:errcheck
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
	}
}

func (s *sandbox) stderr() string {
	s.stderrMu.Lock()
	defer s.stderrMu.Unlock()
	return s.stderrTail.String()
}

// StopOrphanSandboxes removes any builder sandbox containers left over from
// a previous server run (matched by label)
func StopOrphanSandboxes(ctx context.Context, cli string) error {
	list := exec.CommandContext(ctx, cli, "ps", "-aq", "--filter", "label="+sandboxLabel+"=1")
	output, err := list.Output()
	if err != nil {
		return fmt.Errorf("listing builder containers: %w", err)
	}
	ids := strings.Fields(string(output))
	if len(ids) == 0 {
		return nil
	}
	rm := exec.CommandContext(ctx, cli, append([]string{"rm", "-f"}, ids...)...)
	rm.Stdout = io.Discard
	rm.Stderr = io.Discard
	return rm.Run()
}

// boundedWriter keeps the last limit bytes written
type boundedWriter struct {
	buf   *bytes.Buffer
	mu    *sync.Mutex
	limit int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if w.buf.Len() > w.limit {
		data := w.buf.Bytes()
		trimmed := make([]byte, w.limit/2)
		copy(trimmed, data[len(data)-w.limit/2:])
		w.buf.Reset()
		w.buf.Write(trimmed)
	}
	return len(p), nil
}
