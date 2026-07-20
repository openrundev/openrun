// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"testing"

	acp "github.com/coder/acp-go-sdk"
)

func TestRequestPermissionCancelledOutcome(t *testing.T) {
	ls := newLiveSession("bld_ses_test", "user")
	ls.turnCancelled = true
	d := &driverClient{session: ls}

	resp, err := d.RequestPermission(context.Background(), acp.RequestPermissionRequest{
		Options: []acp.PermissionOption{
			{OptionId: "allow", Kind: acp.PermissionOptionKindAllowAlways},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Outcome.Cancelled == nil {
		t.Fatal("expected the cancelled outcome after session/cancel was sent")
	}
	if resp.Outcome.Selected != nil {
		t.Fatal("a cancelled turn must not auto-approve permission requests")
	}
}

func TestRequestPermissionAutoApproves(t *testing.T) {
	ls := newLiveSession("bld_ses_test", "user")
	d := &driverClient{session: ls}

	resp, err := d.RequestPermission(context.Background(), acp.RequestPermissionRequest{
		Options: []acp.PermissionOption{
			{OptionId: "once", Kind: acp.PermissionOptionKindAllowOnce},
			{OptionId: "always", Kind: acp.PermissionOptionKindAllowAlways},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Outcome.Selected == nil || resp.Outcome.Selected.OptionId != "always" {
		t.Fatalf("expected allow-always to be selected, got %+v", resp.Outcome)
	}
}

func TestToolCallUpdateTitleFallback(t *testing.T) {
	ls := newLiveSession("bld_ses_test", "user")
	ls.toolTitles["tc1"] = "Run tests"
	d := &driverClient{session: ls}

	events, cancel := ls.subscribe()
	defer cancel()

	status := acp.ToolCallStatusCompleted
	err := d.SessionUpdate(context.Background(), acp.SessionNotification{
		SessionId: "s1",
		Update: acp.SessionUpdate{
			ToolCallUpdate: &acp.SessionToolCallUpdate{ToolCallId: "tc1", Status: &status},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := <-events
	if event.Kind != "tool_call_update" {
		t.Fatalf("expected tool_call_update event, got %s", event.Kind)
	}
	if event.Title != "Run tests" {
		t.Fatalf("expected the last known title as fallback, got %q", event.Title)
	}
	if event.ToolStatus != "completed" {
		t.Fatalf("expected completed status, got %q", event.ToolStatus)
	}
}

func TestSessionUpdateSuppressedWhileRestoring(t *testing.T) {
	ls := newLiveSession("bld_ses_test", "user")
	ls.restoring = true
	d := &driverClient{session: ls}
	events, cancel := ls.subscribe()
	defer cancel()

	// session/load replays history as updates; while restoring they must
	// not reach subscribers (the transcript already shows them)
	text := "replayed"
	err := d.SessionUpdate(context.Background(), acp.SessionNotification{
		SessionId: "s1",
		Update: acp.SessionUpdate{
			AgentMessageChunk: &acp.SessionUpdateAgentMessageChunk{Content: acp.ContentBlock{Text: &acp.ContentBlockText{Text: text}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		t.Fatalf("replayed update reached subscribers: %+v", event)
	default:
	}
}
