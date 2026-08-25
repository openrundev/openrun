// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strings"
)

// SidecarSpec is the declaration of one sidecar container of a container app:
// a background worker running the app's own image with a different command,
// or a companion service (cache, queue) from a foreign image. The same JSON
// document is accepted from app.star (container.sidecar), the CLI --sidecar
// flag, app update metadata and apps.star sync entries.
//
// On Kubernetes a sidecar is a native sidecar container in the app's pod; on
// docker/podman it is a container on the app's private network. Sidecars
// start, in declaration order, before the app container and are part of the
// app version (a spec change rolls the app).
type SidecarSpec struct {
	// Name identifies the sidecar within the app: container name suffix and
	// the CL_SIDECAR_<NAME>_ADDR env var fragment. Lower case letters,
	// digits and dashes
	Name string `json:"name"`
	// Image is "image:<ref>" for a foreign image. Empty runs the app's own
	// image (the built Containerfile image or the app's image: source)
	Image string `json:"image,omitempty,omitzero"`
	// Command overrides the image entrypoint. Required for app image sidecars
	// (the image default command is the app's web server)
	Command []string `json:"command,omitempty,omitzero"`
	// Args are passed to the command (or to the image entrypoint)
	Args []string `json:"args,omitempty,omitzero"`
	// Env is the sidecar's own env, overlaid on the inherited app env
	Env map[string]string `json:"env,omitempty,omitzero"`
	// InheritEnv copies the app's env (params, bindings, CL_* vars) into the
	// sidecar. Defaults to true for app image sidecars and false for foreign
	// images, which should not see the app's secrets unless asked to
	InheritEnv *bool `json:"inherit_env,omitempty,omitzero"`
	// Port is the port the sidecar listens on. Port'd sidecars are readiness
	// gated before the app starts and addressable through
	// CL_SIDECAR_<NAME>_ADDR
	Port int32 `json:"port,omitempty,omitzero"`
	// Health is the readiness probe for port'd sidecars: empty is a TCP
	// connect to Port, "http:/path" an HTTP GET expecting 200
	Health string `json:"health,omitempty,omitzero"`
	// Volumes use the container.config volumes grammar. A named volume also
	// used by the app is the same volume
	Volumes []string `json:"volumes,omitempty,omitzero"`
	// AlwaysOn keeps the sidecar running when the app container is stopped
	// for idleness (docker/podman only). Defaults to true for sidecars
	// without a port (workers), false for port'd sidecars
	AlwaysOn *bool `json:"always_on,omitempty,omitzero"`
	// Options are container options for the sidecar, same keys as the app
	// container options (kubernetes.cpus, kubernetes.memory, ...)
	Options map[string]string `json:"options,omitempty,omitzero"`
}

var sidecarNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,19}$`)

// ParseSidecarSpec parses one sidecar JSON document. Unknown fields are
// rejected so a typo in a field name fails instead of being ignored.
func ParseSidecarSpec(data string) (SidecarSpec, error) {
	var spec SidecarSpec
	if err := json.Unmarshal([]byte(data), &spec, json.RejectUnknownMembers(true)); err != nil {
		return SidecarSpec{}, fmt.Errorf("invalid sidecar definition %s: %w", data, err)
	}
	if err := spec.Validate(); err != nil {
		return SidecarSpec{}, err
	}
	return spec, nil
}

// ParseSidecarSpecs parses a list of sidecar JSON documents, rejecting
// duplicate names.
func ParseSidecarSpecs(entries []string) ([]SidecarSpec, error) {
	ret := make([]SidecarSpec, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		spec, err := ParseSidecarSpec(entry)
		if err != nil {
			return nil, err
		}
		if seen[spec.Name] {
			return nil, fmt.Errorf("duplicate sidecar name %q", spec.Name)
		}
		seen[spec.Name] = true
		ret = append(ret, spec)
	}
	return ret, nil
}

// String returns the canonical JSON form of the spec, the form stored in the
// app metadata.
func (s SidecarSpec) String() string {
	data, err := json.Marshal(s, json.Deterministic(true))
	if err != nil {
		return fmt.Sprintf("%+v", struct{ SidecarSpec }{s})
	}
	return string(data)
}

// Validate checks the definition time constraints of a sidecar spec.
func (s SidecarSpec) Validate() error {
	if !sidecarNameRegex.MatchString(s.Name) {
		return fmt.Errorf("invalid sidecar name %q: use 1-20 lower case letters, digits or dashes, starting with a letter or digit", s.Name)
	}
	if s.Image != "" && !strings.HasPrefix(s.Image, CONTAINER_SOURCE_IMAGE_PREFIX) {
		return fmt.Errorf("sidecar %s: image must be %q followed by the image reference, or empty for the app image", s.Name, CONTAINER_SOURCE_IMAGE_PREFIX)
	}
	if s.Image != "" && strings.TrimPrefix(s.Image, CONTAINER_SOURCE_IMAGE_PREFIX) == "" {
		return fmt.Errorf("sidecar %s: image reference is empty", s.Name)
	}
	if s.IsAppImage() && len(s.Command) == 0 {
		// The image default command is the app's web server, which would bind
		// the app's port inside the shared pod
		return fmt.Errorf("sidecar %s uses the app image and must set command", s.Name)
	}
	if s.Port < 0 || s.Port > 65535 {
		return fmt.Errorf("sidecar %s: invalid port %d", s.Name, s.Port)
	}
	if s.Health != "" {
		if s.Port == 0 {
			return fmt.Errorf("sidecar %s: health requires port", s.Name)
		}
		if !strings.HasPrefix(s.Health, "http:/") {
			return fmt.Errorf("sidecar %s: health must be \"http:/<path>\" (default is a TCP check on the port)", s.Name)
		}
	}
	for k := range s.Env {
		if k == "" || strings.ContainsAny(k, "= \t\n") {
			return fmt.Errorf("sidecar %s: invalid env name %q", s.Name, k)
		}
	}
	return nil
}

// IsAppImage reports whether the sidecar runs the app's own image.
func (s SidecarSpec) IsAppImage() bool {
	return s.Image == ""
}

// ImageRef returns the foreign image reference without the image: prefix,
// empty for app image sidecars.
func (s SidecarSpec) ImageRef() string {
	return strings.TrimPrefix(s.Image, CONTAINER_SOURCE_IMAGE_PREFIX)
}

// InheritsEnv resolves the inherit_env default: app image sidecars inherit
// the app env, foreign images do not.
func (s SidecarSpec) InheritsEnv() bool {
	if s.InheritEnv != nil {
		return *s.InheritEnv
	}
	return s.IsAppImage()
}

// IsAlwaysOn resolves the always_on default: sidecars without a port keep
// running across app idle shutdowns.
func (s SidecarSpec) IsAlwaysOn() bool {
	if s.AlwaysOn != nil {
		return *s.AlwaysOn
	}
	return s.Port == 0
}

// EnvName returns the env var fragment for the sidecar name: upper cased,
// dashes replaced with underscores (api-cache -> API_CACHE).
func (s SidecarSpec) EnvName() string {
	return strings.ToUpper(strings.ReplaceAll(s.Name, "-", "_"))
}

// SidecarAddrEnvName returns the app env var carrying a port'd sidecar's
// address, CL_SIDECAR_<NAME>_ADDR.
func SidecarAddrEnvName(sidecarName string) string {
	return "CL_SIDECAR_" + strings.ToUpper(strings.ReplaceAll(sidecarName, "-", "_")) + "_ADDR"
}

// MergeSidecarSpecs combines the app definition sidecars with the app
// metadata sidecars: a metadata sidecar replaces a same-name definition
// sidecar entirely (no field merge), definition sidecars keep their order
// and metadata-only sidecars are appended. Ports must be unique across the
// app port and all sidecars.
func MergeSidecarSpecs(fromApp, fromMetadata []SidecarSpec, appPort int32) ([]SidecarSpec, error) {
	byName := make(map[string]SidecarSpec, len(fromMetadata))
	for _, spec := range fromMetadata {
		byName[spec.Name] = spec
	}
	ret := make([]SidecarSpec, 0, len(fromApp)+len(fromMetadata))
	seen := map[string]bool{}
	for _, spec := range fromApp {
		if seen[spec.Name] {
			return nil, fmt.Errorf("duplicate sidecar name %q", spec.Name)
		}
		seen[spec.Name] = true
		if override, ok := byName[spec.Name]; ok {
			spec = override
		}
		ret = append(ret, spec)
	}
	for _, spec := range fromMetadata {
		if seen[spec.Name] {
			continue
		}
		seen[spec.Name] = true
		ret = append(ret, spec)
	}

	ports := map[int32]string{}
	for _, spec := range ret {
		if err := spec.Validate(); err != nil {
			return nil, err
		}
		if spec.Port == 0 {
			continue
		}
		if spec.Port == appPort {
			return nil, fmt.Errorf("sidecar %s port %d conflicts with the app port", spec.Name, spec.Port)
		}
		if other, ok := ports[spec.Port]; ok {
			return nil, fmt.Errorf("sidecars %s and %s both use port %d", other, spec.Name, spec.Port)
		}
		ports[spec.Port] = spec.Name
	}
	return ret, nil
}

// SidecarImageAllowed checks a foreign sidecar image reference against the
// server allow list (security.allowed_sidecar_images): exact match or
// regex: entries. An empty list allows every image.
func SidecarImageAllowed(allowed []string, imageRef string) (bool, error) {
	if len(allowed) == 0 {
		return true, nil
	}
	for _, entry := range allowed {
		if entry == imageRef {
			return true, nil
		}
		match, err := RegexMatch(entry, imageRef)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}
