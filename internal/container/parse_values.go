// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	dockerunits "github.com/docker/go-units"
	"k8s.io/apimachinery/pkg/api/resource"
)

var (
	reIntOnly     = regexp.MustCompile(`^\d+$`)
	reDockerLike  = regexp.MustCompile(`^\d+(\.\d+)?\s*[bkmgte]b?\s*$`) // e.g. 512m, 1g, 1gb, 0.5g (case-insensitive handled below)
	KNOWN_OPTIONS = []string{"cpus", "memory"}
)

// BytesString parses s and returns bytes as a base-10 integer string.
//
// Rules:
// 1) If already an integer string (bytes), return as-is.
// 2) If docker-like (e.g., 512m, 1g), parse via Docker and return bytes.
// 3) Otherwise parse as k8s Quantity (e.g., 512Mi, 1Gi, 500M) and return bytes.
func BytesString(s string) (string, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return "", fmt.Errorf("empty value")
	}

	// already integer bytes
	if reIntOnly.MatchString(in) {
		return in, nil
	}

	// docker-like,  avoids treating "512m" as k8s milli-bytes
	low := strings.ToLower(in)
	if reDockerLike.MatchString(low) {
		b, err := dockerunits.RAMInBytes(low)
		if err == nil && b >= 0 {
			return strconv.FormatInt(b, 10), nil
		}
		// fall through to try k8s (in case it wasn't really docker)
	}

	// k8s quantity -> bytes
	q, err := resource.ParseQuantity(in)
	if err != nil {
		return "", fmt.Errorf("not a valid docker or k8s memory value %q: %w", in, err)
	}
	return strconv.FormatInt(q.Value(), 10), nil
}

// CPUString converts CPU from either docker-like ("0.5", "2") or k8s-like ("500m", "1")
// into a string that "makes sense" for the target.
//   - targetIsDocker=true  => return cores as decimal string (e.g. "0.5", "2")
//   - targetIsDocker=false => return millicores as integer string (e.g. "500", "2000")
//
// Notes:
//   - Bare "1" is treated as 1 core (not 1 millicore).
//   - For millicores input, use "m" suffix: "500m".
func CPUString(s string, targetIsDocker bool) (string, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return "", fmt.Errorf("empty cpu value")
	}

	q, err := resource.ParseQuantity(in)
	if err != nil {
		return "", fmt.Errorf("invalid cpu quantity %q: %w", in, err)
	}

	milli := q.MilliValue() // integer millicores (ceil for fractional smaller than 1m)

	if targetIsDocker {
		return formatCoresFromMilli(milli), nil
	}
	return strconv.FormatInt(milli, 10), nil
}

func formatCoresFromMilli(m int64) string {
	if m%1000 == 0 {
		return strconv.FormatInt(m/1000, 10)
	}
	whole := m / 1000
	frac := m % 1000
	// exact 3-decimal formatting, then trim trailing zeros
	s := fmt.Sprintf("%d.%03d", whole, frac)
	for strings.HasSuffix(s, "0") {
		s = strings.TrimSuffix(s, "0")
	}
	s = strings.TrimSuffix(s, ".")
	return s
}
