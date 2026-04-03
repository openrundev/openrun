// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const defaultTestContainerCommand = "docker"

// StartPostgresContainer starts a Postgres container through the local container CLI.
func StartPostgresContainer(ctx context.Context, image, database, username, password string) (string, func(), error) {
	containerCommand := os.Getenv("OPENRUN_TEST_CONTAINER_COMMAND")
	if containerCommand == "" {
		containerCommand = defaultTestContainerCommand
	}

	name, err := randomContainerName()
	if err != nil {
		return "", nil, fmt.Errorf("create container name: %w", err)
	}

	args := []string{
		"run",
		"--detach",
		"--rm",
		"--name", name,
		"--publish", "127.0.0.1::5432",
		"--env", "POSTGRES_DB=" + database,
		"--env", "POSTGRES_USER=" + username,
		"--env", "POSTGRES_PASSWORD=" + password,
		image,
	}

	output, err := exec.CommandContext(ctx, containerCommand, args...).CombinedOutput()
	if err != nil {
		return "", nil, fmt.Errorf("start postgres container with %s: %w: %s",
			containerCommand, err, strings.TrimSpace(string(output)))
	}

	containerID := strings.TrimSpace(string(output))
	cleanup := containerCleanup(containerCommand, containerID)

	port, err := waitForPublishedPort(ctx, containerCommand, containerID)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	connStr := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		url.QueryEscape(username), url.QueryEscape(password), port, url.PathEscape(database))

	return connStr, cleanup, nil
}

func randomContainerName() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "openrun-postgres-test-" + hex.EncodeToString(buf), nil
}

func containerCleanup(containerCommand, containerID string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = exec.Command(containerCommand, "rm", "-f", containerID).Run()
		})
	}
}

func waitForPublishedPort(ctx context.Context, containerCommand, containerID string) (string, error) {
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		port, err := inspectPublishedPort(ctx, containerCommand, containerID)
		if err == nil && port != "" {
			return port, nil
		}

		select {
		case <-ctx.Done():
			if err != nil {
				return "", fmt.Errorf("inspect postgres container port: %w", err)
			}
			return "", ctx.Err()
		case <-deadline.C:
			if err != nil {
				return "", fmt.Errorf("inspect postgres container port: %w", err)
			}
			return "", fmt.Errorf("postgres container port was not published in time")
		case <-ticker.C:
		}
	}
}

func inspectPublishedPort(ctx context.Context, containerCommand, containerID string) (string, error) {
	output, err := exec.CommandContext(ctx,
		containerCommand,
		"inspect",
		"--format",
		`{{with index .NetworkSettings.Ports "5432/tcp"}}{{(index . 0).HostPort}}{{end}}`,
		containerID,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}

	return strings.TrimSpace(string(output)), nil
}
