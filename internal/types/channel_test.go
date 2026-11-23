// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"strings"
	"testing"
)

// The CHANNEL file is read by the release tooling as well as embedded here,
// so its content has to stay one of the two channel names
func TestChannelFile(t *testing.T) {
	channel := strings.TrimSpace(channelFile)
	if channel != CHANNEL_TIP && channel != CHANNEL_PRO {
		t.Fatalf("CHANNEL file holds %q, want %q or %q", channel, CHANNEL_TIP, CHANNEL_PRO)
	}
	if got := GetChannel(); got != channel {
		t.Errorf("GetChannel() = %q, want %q", got, channel)
	}
	wantLicense := LICENSE_TIP
	if channel == CHANNEL_PRO {
		wantLicense = LICENSE_PRO
	}
	if got := GetLicense(); got != wantLicense {
		t.Errorf("GetLicense() = %q, want %q", got, wantLicense)
	}
}

func TestChannelOverride(t *testing.T) {
	origChannel, origLicense, origFile := gitChannel, gitLicense, channelFile
	defer func() { gitChannel, gitLicense, channelFile = origChannel, origLicense, origFile }()

	gitChannel, gitLicense, channelFile = "", "", "pro\n"
	if GetChannel() != CHANNEL_PRO || GetLicense() != LICENSE_PRO {
		t.Errorf("pro file: got %q %q", GetChannel(), GetLicense())
	}
	channelFile = ""
	if GetChannel() != CHANNEL_TIP || GetLicense() != LICENSE_TIP {
		t.Errorf("empty file: got %q %q", GetChannel(), GetLicense())
	}
	gitChannel, gitLicense = "pro", "Custom"
	if GetChannel() != CHANNEL_PRO || GetLicense() != "Custom" {
		t.Errorf("ldflags override: got %q %q", GetChannel(), GetLicense())
	}
}
