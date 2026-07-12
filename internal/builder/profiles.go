// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/openrundev/openrun/internal/types"
)

//go:embed dockerfiles/Dockerfile.*
var dockerfilesFS embed.FS

const AgentTypeCustom = "custom"

// agentCommands maps a builder agent type to the command inside the sandbox
// that speaks ACP on stdio
var agentCommands = map[string][]string{
	"opencode": {"opencode", "acp"},
	"claude":   {"claude-code-acp"},
	"codex":    {"codex-acp"},
	"pi":       {"pi-acp"},
}

// AgentTypes lists the predefined agent types with embedded Dockerfiles
func AgentTypes() []string {
	return []string{"opencode", "claude", "codex", "pi"}
}

// EmbeddedDockerfile returns the embedded Dockerfile content for a predefined
// agent type
func EmbeddedDockerfile(agentType string) ([]byte, error) {
	data, err := dockerfilesFS.ReadFile("dockerfiles/Dockerfile." + agentType)
	if err != nil {
		return nil, fmt.Errorf("no embedded Dockerfile for agent type %s", agentType)
	}
	return data, nil
}

// profile is a resolved agent profile: the config entry with the embedded
// defaults for its type applied
type profile struct {
	name       string
	agentType  string
	dockerfile []byte   // Dockerfile content
	command    []string // ACP command inside the sandbox
	env        map[string]string
	configs    []configMount
}

type configMount struct {
	host      string
	container string
	readOnly  bool
}

// AgentTypeFromName infers the agent type from the [builder_agent.*] entry
// name, like auth entries: the part before the first underscore must be a
// predefined type or "custom" (opencode, opencode_dev, pi, custom_myagent)
func AgentTypeFromName(name string) (string, error) {
	prefix := strings.SplitN(name, "_", 2)[0]
	if _, predefined := agentCommands[prefix]; predefined || prefix == AgentTypeCustom {
		return prefix, nil
	}
	return "", fmt.Errorf("builder agent name %q must be a type or start with type_: %s or %s (e.g. opencode_dev, custom_myagent)",
		name, strings.Join(AgentTypes(), ", "), AgentTypeCustom)
}

// resolveProfile validates one [builder_agent.*] entry and applies the
// embedded Dockerfile and command defaults for its type. The type comes
// from the entry name; an explicit type field must agree
func resolveProfile(name string, config types.BuilderAgentConfig, readFile func(string) ([]byte, error)) (*profile, error) {
	agentType, err := AgentTypeFromName(name)
	if err != nil {
		return nil, err
	}
	if explicit := strings.TrimSpace(config.Type); explicit != "" && explicit != agentType {
		return nil, fmt.Errorf("builder agent %s: type %q does not match the type inferred from the name (%s)",
			name, explicit, agentType)
	}

	p := &profile{name: name, agentType: agentType, env: config.Env, command: config.Command}

	if len(p.command) == 0 {
		if agentType == AgentTypeCustom {
			return nil, fmt.Errorf("builder agent %s: type custom requires command", name)
		}
		p.command = agentCommands[agentType]
	}

	if config.Dockerfile != "" {
		content, err := readFile(config.Dockerfile)
		if err != nil {
			return nil, fmt.Errorf("builder agent %s: reading dockerfile: %w", name, err)
		}
		p.dockerfile = content
	} else {
		if agentType == AgentTypeCustom {
			return nil, fmt.Errorf("builder agent %s: type custom requires dockerfile", name)
		}
		content, err := EmbeddedDockerfile(agentType)
		if err != nil {
			return nil, err
		}
		p.dockerfile = content
	}

	for _, entry := range config.ConfigFiles {
		mount, err := parseConfigMount(entry)
		if err != nil {
			return nil, fmt.Errorf("builder agent %s: %w", name, err)
		}
		p.configs = append(p.configs, mount)
	}
	return p, nil
}

// parseConfigMount parses a "host:container[:ro]" config file mount entry
func parseConfigMount(entry string) (configMount, error) {
	parts := strings.Split(entry, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return configMount{}, fmt.Errorf("invalid config_files entry %q, expected host:container[:ro]", entry)
	}
	mount := configMount{host: parts[0], container: parts[1]}
	if len(parts) == 3 {
		if parts[2] != "ro" {
			return configMount{}, fmt.Errorf("invalid config_files option %q in %q, only ro is supported", parts[2], entry)
		}
		mount.readOnly = true
	}
	if !strings.HasPrefix(mount.container, "/") {
		return configMount{}, fmt.Errorf("config_files container path %q must be absolute", mount.container)
	}
	return mount, nil
}

var imageNameSanitizer = regexp.MustCompile(`[^a-z0-9_.-]`)

// imageTag returns the local image tag for a profile: the profile name plus a
// content hash of the Dockerfile, so editing the Dockerfile triggers a rebuild
func (p *profile) imageTag() string {
	name := imageNameSanitizer.ReplaceAllString(strings.ToLower(p.name), "_")
	return fmt.Sprintf("openrun_agent_%s:%s", name, contentHash(p.dockerfile))
}
