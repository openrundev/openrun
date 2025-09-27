// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import "strings"

// IsGit returns true if the sourceURL is a git URL
func IsGit(url string) bool {
	if url == "" {
		return false
	}
	if url[0] == '/' || url[0] == '.' || url[0] == '~' {
		return false
	}
	if strings.HasPrefix(url, "git@") ||
		strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		return true // Git URL
	}
	split := strings.Split(url, "/")
	if !strings.Contains(split[0], ".") {
		return false // No dot in the first part, assume not a git URL
	}

	if len(split) < 3 {
		return false // Not enough parts to be a git URL
	}
	return true
}
