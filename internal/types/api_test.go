// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json/v2"
	"testing"
)

func TestUserUpdateRequestGroupsWireSemantics(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   string
	}{
		{name: "nil keeps groups", want: `{"password":"hash","groups":null}`},
		{name: "empty clears groups", groups: []string{}, want: `{"password":"hash","groups":[]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(UserUpdateRequest{Password: "hash", Groups: tt.groups})
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("Marshal() = %s, want %s", got, tt.want)
			}
		})
	}
}
