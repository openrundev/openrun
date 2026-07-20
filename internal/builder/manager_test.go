// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"strings"
	"testing"
)

func TestCancelTurnStates(t *testing.T) {
	m := &Manager{}
	ls := newLiveSession("bld_ses_test", "user")

	// idle session: nothing to cancel
	err := m.cancelTurn(ls)
	if err == nil || !strings.Contains(err.Error(), "no agent turn is running") {
		t.Fatalf("expected the no-turn error, got %v", err)
	}

	// the first turn is claimed while the sandbox launches (conn not up
	// yet): the error must direct the user to stop the session instead
	ls.turnActive = true
	err = m.cancelTurn(ls)
	if err == nil || !strings.Contains(err.Error(), "still starting") {
		t.Fatalf("expected the still-starting error, got %v", err)
	}
	if ls.turnCancelled {
		t.Fatal("a rejected cancel must not mark the turn cancelled (it would cancel pending permission requests of the coming turn)")
	}
}
