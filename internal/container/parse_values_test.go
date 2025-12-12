// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"testing"
)

func TestBytesString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Integer bytes (pass-through)
		{"integer bytes", "1024", "1024", false},
		{"zero bytes", "0", "0", false},
		{"large integer", "1073741824", "1073741824", false},

		// Docker-like values
		{"docker 512m", "512m", "536870912", false},
		{"docker 1g", "1g", "1073741824", false},
		{"docker 1gb", "1gb", "1073741824", false},
		{"docker 2gb", "2gb", "2147483648", false},
		{"docker 0.5g", "0.5g", "536870912", false},
		{"docker 1k", "1k", "1024", false},
		{"docker 1kb", "1kb", "1024", false},
		{"docker 1mb", "1mb", "1048576", false},
		{"docker uppercase 512M", "512M", "536870912", false},
		{"docker uppercase 1G", "1G", "1073741824", false},
		{"docker uppercase 1GB", "1GB", "1073741824", false},

		// Kubernetes Quantity values
		{"k8s 512Mi", "512Mi", "536870912", false},
		{"k8s 1Gi", "1Gi", "1073741824", false},
		{"k8s 2Gi", "2Gi", "2147483648", false},
		{"k8s 1Ki", "1Ki", "1024", false},
		{"k8s 500M parsed as docker", "500M", "524288000", false}, // matches docker-like regex first
		{"k8s 1G", "1G", "1073741824", false},

		// Whitespace handling
		{"leading space", "  512m", "536870912", false},
		{"trailing space", "512m  ", "536870912", false},
		{"both spaces", "  512m  ", "536870912", false},

		// Error cases
		{"empty string", "", "", true},
		{"whitespace only", "   ", "", true},
		{"invalid value", "invalid", "", true},

		// Edge cases - negative values are accepted by k8s quantity parser
		{"negative k8s value", "-1", "-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BytesString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("BytesString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BytesString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCPUString(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		targetIsDocker bool
		want           string
		wantErr        bool
	}{
		// Integer cores - Docker target (returns decimal cores)
		{"1 core docker", "1", true, "1", false},
		{"2 cores docker", "2", true, "2", false},
		{"4 cores docker", "4", true, "4", false},

		// Integer cores - K8s target (returns millicores)
		{"1 core k8s", "1", false, "1000", false},
		{"2 cores k8s", "2", false, "2000", false},
		{"4 cores k8s", "4", false, "4000", false},

		// Decimal cores - Docker target
		{"0.5 cores docker", "0.5", true, "0.5", false},
		{"0.25 cores docker", "0.25", true, "0.25", false},
		{"1.5 cores docker", "1.5", true, "1.5", false},
		{"0.1 cores docker", "0.1", true, "0.1", false},
		{"0.125 cores docker", "0.125", true, "0.125", false},

		// Decimal cores - K8s target
		{"0.5 cores k8s", "0.5", false, "500", false},
		{"0.25 cores k8s", "0.25", false, "250", false},
		{"1.5 cores k8s", "1.5", false, "1500", false},
		{"0.1 cores k8s", "0.1", false, "100", false},
		{"0.125 cores k8s", "0.125", false, "125", false},

		// Millicores with m suffix - Docker target
		{"500m docker", "500m", true, "0.5", false},
		{"250m docker", "250m", true, "0.25", false},
		{"1000m docker", "1000m", true, "1", false},
		{"1500m docker", "1500m", true, "1.5", false},
		{"100m docker", "100m", true, "0.1", false},
		{"2000m docker", "2000m", true, "2", false},
		{"125m docker", "125m", true, "0.125", false},
		{"333m docker", "333m", true, "0.333", false},

		// Millicores with m suffix - K8s target
		{"500m k8s", "500m", false, "500", false},
		{"250m k8s", "250m", false, "250", false},
		{"1000m k8s", "1000m", false, "1000", false},
		{"1500m k8s", "1500m", false, "1500", false},
		{"100m k8s", "100m", false, "100", false},
		{"2000m k8s", "2000m", false, "2000", false},

		// Whitespace handling
		{"leading space docker", "  0.5", true, "0.5", false},
		{"trailing space docker", "0.5  ", true, "0.5", false},
		{"both spaces docker", "  0.5  ", true, "0.5", false},
		{"leading space k8s", "  500m", false, "500", false},
		{"trailing space k8s", "500m  ", false, "500", false},

		// Error cases
		{"empty string docker", "", true, "", true},
		{"empty string k8s", "", false, "", true},
		{"whitespace only docker", "   ", true, "", true},
		{"whitespace only k8s", "   ", false, "", true},
		{"invalid value docker", "invalid", true, "", true},
		{"invalid value k8s", "invalid", false, "", true},
		{"invalid suffix docker", "500x", true, "", true},

		// Edge cases
		{"zero docker", "0", true, "0", false},
		{"zero k8s", "0", false, "0", false},
		{"very small 1m docker", "1m", true, "0.001", false},
		{"very small 1m k8s", "1m", false, "1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CPUString(tt.input, tt.targetIsDocker)
			if (err != nil) != tt.wantErr {
				t.Errorf("CPUString(%q, %v) error = %v, wantErr %v", tt.input, tt.targetIsDocker, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CPUString(%q, %v) = %v, want %v", tt.input, tt.targetIsDocker, got, tt.want)
			}
		})
	}
}
