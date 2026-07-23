// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestCommandOptionArgsAllowedExactAndRegex(t *testing.T) {
	got, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{
			"init":  "",
			"label": "team=platform",
		},
	}, map[string]string{
		"init":  "",
		"label": "regex:^team=platform$",
	})
	if err != nil {
		t.Fatalf("CommandOptionArgs returned error: %v", err)
	}

	want := []string{"--init", "--label=team=platform"}
	if !slices.Equal(got, want) {
		t.Fatalf("CommandOptionArgs = %#v, want %#v", got, want)
	}
}

func TestLocalhostBindingHostname(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{name: "docker", command: "docker", want: DockerLocalhostBindingHostname},
		{name: "docker path", command: "/usr/local/bin/docker", want: DockerLocalhostBindingHostname},
		{name: "windows docker exe path", command: `C:\Program Files\Docker\Docker\resources\bin\docker.exe`, want: DockerLocalhostBindingHostname},
		{name: "windows docker mixed case", command: `C:\Program Files\Docker\Docker\resources\bin\Docker.EXE`, want: DockerLocalhostBindingHostname},
		{name: "podman", command: "podman", want: OtherLocalhostBindingHostname},
		{name: "windows podman exe path", command: `C:\Program Files\RedHat\Podman\podman.exe`, want: OtherLocalhostBindingHostname},
		{name: "other command", command: "nerdctl", want: OtherLocalhostBindingHostname},
		{name: "kubernetes", command: types.CONTAINER_KUBERNETES, want: ""},
		{name: "empty", command: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LocalhostBindingHostname(tt.command); got != tt.want {
				t.Fatalf("LocalhostBindingHostname(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestLocalhostHostGatewayArgs(t *testing.T) {
	got := LocalhostHostGatewayArgs("/usr/local/bin/docker")
	want := []string{"--add-host", "host.docker.internal:host-gateway"}
	if !slices.Equal(got, want) {
		t.Fatalf("LocalhostHostGatewayArgs(docker) = %#v, want %#v", got, want)
	}

	got = LocalhostHostGatewayArgs(`C:\Program Files\Docker\Docker\resources\bin\docker.exe`)
	if !slices.Equal(got, want) {
		t.Fatalf("LocalhostHostGatewayArgs(windows docker) = %#v, want %#v", got, want)
	}

	if got := LocalhostHostGatewayArgs("podman"); len(got) != 0 {
		t.Fatalf("LocalhostHostGatewayArgs(podman) = %#v, want empty", got)
	}
}

func TestParseCommandOptionsFiltersByContainerCommand(t *testing.T) {
	got, err := ParseCommandOptions("/usr/local/bin/docker", map[string]string{
		"docker.init":    "",
		"command.label":  "team=platform",
		"podman.ignored": "",
		"ignored.option": "ignored",
	})
	if err != nil {
		t.Fatalf("ParseCommandOptions returned error: %v", err)
	}

	if got.Other["init"] != "" {
		t.Fatalf("Other[init] = %#v, want empty string", got.Other["init"])
	}
	if got.Other["label"] != "team=platform" {
		t.Fatalf("Other[label] = %#v, want %q", got.Other["label"], "team=platform")
	}
	if _, ok := got.Other["ignored"]; ok {
		t.Fatalf("podman option should not be decoded, got %#v", got.Other["ignored"])
	}
	if _, ok := got.Other["ignored.option"]; ok {
		t.Fatalf("unprefixed unknown option should not be decoded, got %#v", got.Other["ignored.option"])
	}
}

func TestParseCommandOptionsNormalizesWindowsCommandPath(t *testing.T) {
	got, err := ParseCommandOptions(`C:\Program Files\Docker\Docker\resources\bin\docker.exe`, map[string]string{
		"docker.init":   "",
		"docker.memory": "512m",
	})
	if err != nil {
		t.Fatalf("ParseCommandOptions returned error: %v", err)
	}

	if got.Memory != "512m" {
		t.Fatalf("Memory = %q, want 512m", got.Memory)
	}
	if got.Other["init"] != "" {
		t.Fatalf("Other[init] = %#v, want empty string", got.Other["init"])
	}
}

func TestCommandCMImageExistsUsesQuietImageListForDockerAndPodman(t *testing.T) {
	for _, commandName := range []string{"docker", "podman"} {
		t.Run(commandName, func(t *testing.T) {
			commandPath := filepath.Join(t.TempDir(), commandName)
			script := `#!/bin/sh
if [ "$1" != "image" ] || [ "$2" != "ls" ] || [ "$3" != "--quiet" ]; then
	echo "unexpected args: $*" >&2
	exit 64
fi

case "$4" in
	present:latest)
		echo 'sha256:abc'
		exit 0
		;;
	missing:latest)
		exit 0
		;;
	fail:latest)
		echo "daemon unavailable" >&2
		exit 65
		;;
	*)
		echo "unexpected image: $4" >&2
		exit 65
		;;
esac
`
			if err := os.WriteFile(commandPath, []byte(script), 0o755); err != nil {
				t.Fatalf("write fake container command: %v", err)
			}

			manager := NewCommandCM(testutil.TestLogger(), &types.ServerConfig{
				System: types.SystemConfig{ContainerCommand: commandPath},
			}, "", "")

			exists, err := manager.ImageExists(context.Background(), ImageName("present:latest"))
			if err != nil {
				t.Fatalf("ImageExists present returned error: %v", err)
			}
			if !exists {
				t.Fatal("ImageExists present = false, want true")
			}

			exists, err = manager.ImageExists(context.Background(), ImageName("missing:latest"))
			if err != nil {
				t.Fatalf("ImageExists missing returned error: %v", err)
			}
			if exists {
				t.Fatal("ImageExists missing = true, want false")
			}

			exists, err = manager.ImageExists(context.Background(), ImageName("fail:latest"))
			if err == nil {
				t.Fatal("ImageExists command failure returned nil error")
			}
			if exists {
				t.Fatal("ImageExists command failure = true, want false")
			}
		})
	}
}

func TestContainerHasLabelSupportsDockerAndPodmanFormats(t *testing.T) {
	t.Parallel()

	const key = LABEL_PREFIX + DEV_HASH_LABEL
	for _, tt := range []struct {
		name      string
		container Container
	}{
		{
			name:      "docker",
			container: Container{LabelString: "other=value," + key + "=run-hash,third=value"},
		},
		{
			name:      "podman",
			container: Container{Labels: map[string]string{key: "run-hash"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.container.HasLabel(key, "run-hash") {
				t.Fatalf("HasLabel(%q, %q) = false", key, "run-hash")
			}
			if tt.container.HasLabel(key, "different") {
				t.Fatalf("HasLabel(%q, %q) = true", key, "different")
			}
		})
	}
}

func TestCommandCMGetDevContainerInfoDockerAndPodman(t *testing.T) {
	const (
		name    = "clc-dev-test"
		runHash = "run-hash"
	)

	tests := []struct {
		name     string
		output   string
		wantPort string
	}{
		{
			name:     "docker",
			output:   `{"ID":"abc","Names":"clc-dev-test","Image":"img","State":"running","Status":"Up","Ports":"127.0.0.1:49152->5000/tcp","Labels":"other=value,dev.openrun.dev.hash=run-hash"}`,
			wantPort: "127.0.0.1:49152",
		},
		{
			name:     "podman",
			output:   `[{"ID":"abc","Names":["clc-dev-test"],"Image":"img","State":"running","Status":"Up","Ports":[{"host_port":49153}],"Labels":{"dev.openrun.dev.hash":"run-hash"}}]`,
			wantPort: "127.0.0.1:49153",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commandPath := filepath.Join(t.TempDir(), tt.name)
			script := `#!/bin/sh
if [ "$1" != "ps" ] || [ "$2" != "--format" ] || [ "$3" != "json" ] || [ "$4" != "--filter" ] || [ "$5" != "name=clc-dev-test" ] || [ "$6" != "--all" ] || [ -n "$7" ]; then
	echo "unexpected args: $*" >&2
	exit 64
fi
echo '` + tt.output + `'
`
			if err := os.WriteFile(commandPath, []byte(script), 0o755); err != nil {
				t.Fatalf("write fake container command: %v", err)
			}

			manager := NewCommandCM(testutil.TestLogger(), &types.ServerConfig{
				System: types.SystemConfig{ContainerCommand: commandPath},
			}, "", "")

			exists, matches, hostPort, running, err := manager.GetDevContainerInfo(context.Background(), name, runHash)
			if err != nil {
				t.Fatalf("GetDevContainerInfo returned error: %v", err)
			}
			if !exists || !matches || !running || hostPort != tt.wantPort {
				t.Fatalf("GetDevContainerInfo = (%t, %t, %q, %t), want (true, true, %q, true)", exists, matches, hostPort, running, tt.wantPort)
			}

			exists, matches, _, _, err = manager.GetDevContainerInfo(context.Background(), name, "different")
			if err != nil {
				t.Fatalf("GetDevContainerInfo with different hash returned error: %v", err)
			}
			if !exists || matches {
				t.Fatalf("GetDevContainerInfo with different hash = exists:%t matches:%t, want true/false", exists, matches)
			}
		})
	}
}

func TestCommandCMFastDevLifecycleCommands(t *testing.T) {
	t.Parallel()

	commandPath := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
case "$1" in
restart)
	[ "$2" = "-t" ] && [ "$3" = "0" ] && [ "$4" = "clc-dev-test" ] && [ -z "$5" ] || exit 64
	;;
rm)
	[ "$2" = "--force" ] && [ "$3" = "clc-dev-test" ] && [ -z "$4" ] || exit 65
	;;
*)
	echo "unexpected args: $*" >&2
	exit 66
	;;
esac
`
	if err := os.WriteFile(commandPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake container command: %v", err)
	}

	manager := NewCommandCM(testutil.TestLogger(), &types.ServerConfig{
		System: types.SystemConfig{ContainerCommand: commandPath},
	}, "", "")
	if err := manager.RestartDevContainer(context.Background(), "clc-dev-test"); err != nil {
		t.Fatalf("RestartDevContainer returned error: %v", err)
	}
	if err := manager.RemoveContainer(context.Background(), "clc-dev-test"); err != nil {
		t.Fatalf("RemoveContainer returned error: %v", err)
	}
}

func TestCommandByOpenRunLabel(t *testing.T) {
	// The listing must be scoped to containers started by THIS server
	// installation (server.home ownership label) - a sweep filtered on the
	// generic app.id label would stop other servers' containers on a shared
	// container daemon
	home := t.TempDir()
	t.Setenv(types.OPENRUN_HOME, home)
	commandPath := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
if [ "$1" != "ps" ] || [ "$2" != "--format" ] || [ "$3" != "json" ] || [ "$4" != "--filter" ] || [ "$5" != "label=dev.openrun.server.home=` + home + `" ]; then
	echo "unexpected args: $*" >&2
	exit 64
fi
if [ "$6" != "" ]; then
	echo "unexpected extra args: $*" >&2
	exit 64
fi
echo '{"ID":"abc","Names":"clc-app-current","Image":"img","State":"running","Status":"Up","Ports":""}'
`
	if err := os.WriteFile(commandPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake container command: %v", err)
	}

	manager := NewCommandCM(testutil.TestLogger(), &types.ServerConfig{
		System: types.SystemConfig{ContainerCommand: commandPath},
	}, "", "")

	containers, err := manager.ListOpenRunContainers(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRunContainers returned error: %v", err)
	}
	if len(containers) != 1 || containers[0].Names != "clc-app-current" {
		t.Fatalf("ListOpenRunContainers = %#v", containers)
	}
}

func TestImagePull(t *testing.T) {
	commandPath := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
case "$1" in
	pull)
		if [ "$2" = "mycompany/jp-app:latest" ]; then
			echo "Status: Image is up to date"
			exit 0
		fi
		echo "unexpected pull arg: $2" >&2
		exit 65
		;;
	image)
		if [ "$2" = "inspect" ] && [ "$3" = "--format" ] && [ "$5" = "mycompany/jp-app:latest" ]; then
			echo "mycompany/jp-app@sha256:abc123"
			exit 0
		fi
		echo "unexpected inspect args: $*" >&2
		exit 65
		;;
esac
echo "unexpected args: $*" >&2
exit 64
`
	if err := os.WriteFile(commandPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake container command: %v", err)
	}

	manager := NewCommandCM(testutil.TestLogger(), &types.ServerConfig{
		System: types.SystemConfig{ContainerCommand: commandPath},
	}, "", "")
	got, err := manager.RefreshImage(context.Background(), ImageName("mycompany/jp-app:latest"))
	if err != nil {
		t.Fatalf("RefreshImage returned error: %v", err)
	}
	if got != "sha256:abc123" {
		t.Fatalf("RefreshImage digest = %q, want %q", got, "sha256:abc123")
	}
}

func TestImagePullFallback(t *testing.T) {
	commandPath := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
case "$1" in
	pull)
		echo "ok"
		exit 0
		;;
	image)
		if [ "$2" = "inspect" ]; then
			echo "sha256:configdigest"
			exit 0
		fi
		;;
esac
echo "unexpected args: $*" >&2
exit 64
`
	if err := os.WriteFile(commandPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake container command: %v", err)
	}

	manager := NewCommandCM(testutil.TestLogger(), &types.ServerConfig{
		System: types.SystemConfig{ContainerCommand: commandPath},
	}, "", "")
	got, err := manager.RefreshImage(context.Background(), ImageName("local/built:dev"))
	if err != nil {
		t.Fatalf("RefreshImage returned error: %v", err)
	}
	if got != "sha256:configdigest" {
		t.Fatalf("RefreshImage digest = %q, want %q", got, "sha256:configdigest")
	}
}

func TestImagePullFailure(t *testing.T) {
	commandPath := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
if [ "$1" = "pull" ]; then
	echo "denied: unauthorized" >&2
	exit 1
fi
echo "unexpected args: $*" >&2
exit 64
`
	if err := os.WriteFile(commandPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake container command: %v", err)
	}

	manager := NewCommandCM(testutil.TestLogger(), &types.ServerConfig{
		System: types.SystemConfig{ContainerCommand: commandPath},
	}, "", "")
	_, err := manager.RefreshImage(context.Background(), ImageName("private/image:latest"))
	if err == nil {
		t.Fatal("RefreshImage should fail when pull fails")
	}
	if !strings.Contains(err.Error(), "error pulling image") {
		t.Fatalf("RefreshImage error = %q, want pull error", err.Error())
	}
}

func TestCommandOptionArgsRejectsDisallowedArg(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"privileged": ""},
	}, map[string]string{"init": ""})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject disallowed arg")
	}
	if !strings.Contains(err.Error(), `container argument "privileged" is not allowed`) {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsAllowsExactValue(t *testing.T) {
	got, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"security-opt": "label=disable"},
	}, map[string]string{"security-opt": "label=disable"})
	if err != nil {
		t.Fatalf("CommandOptionArgs returned error: %v", err)
	}

	want := []string{"--security-opt=label=disable"}
	if !slices.Equal(got, want) {
		t.Fatalf("CommandOptionArgs = %#v, want %#v", got, want)
	}
}

func TestCommandOptionArgsRejectsInvalidRegex(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"init": ""},
	}, map[string]string{"init": "regex:["})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject invalid regex")
	}
	if !strings.Contains(err.Error(), "invalid allowed container arg") {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsRejectsValueForValuelessArg(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"init": "true"},
	}, map[string]string{"init": ""})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject value for valueless arg")
	}
	if !strings.Contains(err.Error(), `container argument "init" does not allow a value`) {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsRejectsWrongValue(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{
		Other: map[string]any{"security-opt": "apparmor=unconfined"},
	}, map[string]string{"security-opt": "label=disable"})
	if err == nil {
		t.Fatal("expected CommandOptionArgs to reject wrong value")
	}
	if !strings.Contains(err.Error(), `container argument "security-opt" value "apparmor=unconfined" is not allowed`) {
		t.Fatalf("CommandOptionArgs error = %q", err.Error())
	}
}

func TestCommandOptionArgsParsesBuiltInLimits(t *testing.T) {
	got, err := CommandOptionArgs(CommandOptions{
		Cpus:   "500m",
		Memory: "512m",
	}, nil)
	if err != nil {
		t.Fatalf("CommandOptionArgs returned error: %v", err)
	}

	want := []string{"--cpus", "0.5", "--memory", "536870912"}
	if !slices.Equal(got, want) {
		t.Fatalf("CommandOptionArgs = %#v, want %#v", got, want)
	}
}

func TestCommandOptionArgsRejectsInvalidBuiltInLimits(t *testing.T) {
	_, err := CommandOptionArgs(CommandOptions{Cpus: "not-cpu"}, nil)
	if err == nil || !strings.Contains(err.Error(), "error parsing cpus value") {
		t.Fatalf("CommandOptionArgs cpu error = %v, want cpu parse error", err)
	}

	_, err = CommandOptionArgs(CommandOptions{Memory: "not-memory"}, nil)
	if err == nil || !strings.Contains(err.Error(), "error parsing memory value") {
		t.Fatalf("CommandOptionArgs memory error = %v, want memory parse error", err)
	}
}

func TestParseCommandOptionsKeepsBuiltInLimitsOutOfOther(t *testing.T) {
	got, err := ParseCommandOptions("docker", map[string]string{
		"docker.cpus":    "0.5",
		"command.memory": "512m",
	})
	if err != nil {
		t.Fatalf("parseCommandOptions returned error: %v", err)
	}
	if got.Cpus != "0.5" {
		t.Fatalf("Cpus = %q, want %q", got.Cpus, "0.5")
	}
	if got.Memory != "512m" {
		t.Fatalf("Memory = %q, want %q", got.Memory, "512m")
	}
	if len(got.Other) != 0 {
		t.Fatalf("Other = %#v, want empty", got.Other)
	}
}
