// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"context"
	"fmt"
	"strings"
	"testing"

	acp "github.com/coder/acp-go-sdk"
)

type fakeSetter struct {
	calls []acp.SetSessionConfigOptionValueId
	err   error
}

func (f *fakeSetter) SetSessionConfigOption(ctx context.Context, params acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	f.calls = append(f.calls, *params.ValueId)
	return acp.SetSessionConfigOptionResponse{}, f.err
}

func selectOption(id string, category *acp.SessionConfigOptionCategory, values ...string) acp.SessionConfigOption {
	opts := make(acp.SessionConfigSelectOptionsUngrouped, 0, len(values))
	for _, v := range values {
		opts = append(opts, acp.SessionConfigSelectOption{Name: v, Value: acp.SessionConfigValueId(v)})
	}
	return acp.SessionConfigOption{Select: &acp.SessionConfigOptionSelect{
		Id:       acp.SessionConfigId(id),
		Category: category,
		Options:  acp.SessionConfigSelectOptions{Ungrouped: &opts},
	}}
}

func TestApplySessionConfigSetsModelAndEffort(t *testing.T) {
	setter := &fakeSetter{}
	options := []acp.SessionConfigOption{
		selectOption("model", nil, "anthropic/claude-opus-4-8", "anthropic/claude-fable-5"),
		selectOption("reasoningEffort", nil, "low", "medium", "high"),
	}
	warnings := applySessionConfig(context.Background(), setter, "ses1", options, "anthropic/claude-fable-5", "high")
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(setter.calls) != 2 {
		t.Fatalf("expected 2 set calls, got %d", len(setter.calls))
	}
	if setter.calls[0].ConfigId != "model" || setter.calls[0].Value != "anthropic/claude-fable-5" || setter.calls[0].SessionId != "ses1" {
		t.Errorf("bad model call: %+v", setter.calls[0])
	}
	if setter.calls[1].ConfigId != "reasoningEffort" || setter.calls[1].Value != "high" {
		t.Errorf("bad effort call: %+v", setter.calls[1])
	}
}

func TestApplySessionConfigSuffixAndCategoryMatch(t *testing.T) {
	setter := &fakeSetter{}
	modelCat := acp.SessionConfigOptionCategoryModel
	thoughtCat := acp.SessionConfigOptionCategoryThoughtLevel
	options := []acp.SessionConfigOption{
		selectOption("llm", &modelCat, "anthropic/claude-fable-5", "openai/gpt-5"),
		selectOption("level", &thoughtCat, "low", "high"),
	}
	// bare model name matches via the provider/ suffix rule
	warnings := applySessionConfig(context.Background(), setter, "ses1", options, "claude-fable-5", "high")
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(setter.calls) != 2 || setter.calls[0].Value != "anthropic/claude-fable-5" || setter.calls[1].ConfigId != "level" {
		t.Errorf("bad calls: %+v", setter.calls)
	}
}

func TestApplySessionConfigWarnings(t *testing.T) {
	// no options advertised at all
	warnings := applySessionConfig(context.Background(), &fakeSetter{}, "ses1", nil, "m1", "high")
	if len(warnings) != 2 || !strings.Contains(warnings[0], "does not advertise") {
		t.Errorf("expected 2 not-advertised warnings, got %v", warnings)
	}

	// model option advertised but the value is unknown
	options := []acp.SessionConfigOption{selectOption("model", nil, "a/m1", "a/m2")}
	warnings = applySessionConfig(context.Background(), &fakeSetter{}, "ses1", options, "nosuch", "")
	if len(warnings) != 1 || !strings.Contains(warnings[0], "agent offers: a/m1, a/m2") {
		t.Errorf("expected unknown value warning, got %v", warnings)
	}

	// set call fails: warning, not error
	setter := &fakeSetter{err: fmt.Errorf("boom")}
	warnings = applySessionConfig(context.Background(), setter, "ses1", options, "a/m1", "")
	if len(warnings) != 1 || !strings.Contains(warnings[0], "boom") {
		t.Errorf("expected set failure warning, got %v", warnings)
	}

	// nothing configured: no calls, no warnings
	warnings = applySessionConfig(context.Background(), setter, "ses1", options, "", "")
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %v", warnings)
	}
}
