// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"os"
	"testing"
)

var configTestData = `
fileLevel = Init # test comment
fileSize=17
keep=50
#keep=10
# keep=10
# ignored =10
#
#=

fileLevel =   Final#`

func TestLoadProperties(t *testing.T) {
	tmpFile := "./prop_test_tmp.prop"
	defer os.Remove(tmpFile) //nolint:errcheck
	err := os.WriteFile(tmpFile, []byte(configTestData), 0644)
	if err != nil {
		t.Fatal("Error while writing properties file")
	}

	c, err := LoadProperties(tmpFile)
	if err != nil {
		t.Fatal("Error while reading properties file")
	}

	expected := map[string]string{
		"fileLevel": "Final",
		"fileSize":  "17",
		"keep":      "50",
	}

	if len(c) != len(expected) {
		t.Errorf("Expected len %d, got %d", len(expected), len(c))
	}

	for k, v := range expected {
		if pv, ok := c[k]; !ok || pv != v {
			t.Errorf("Expected val %s, got %s, ok %v", v, pv, ok)
		}
	}

}
