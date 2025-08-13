// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package apptype

type CodeConfig struct {
	Routing RouteConfig `json:"routing"`
	Htmx    HtmxConfig  `json:"htmx"`
}

type RouteConfig struct {
	TemplateLocations []string `json:"template_locations"`
	BaseTemplates     string   `json:"base_templates"`
	PushEvents        bool     `json:"push_events"`
	EarlyHints        bool     `json:"early_hints"`

	// glob patterns for files which are excluded from container content change check
	ContainerExclude []string `json:"container_exclude"`
}

type HtmxConfig struct {
	Version string `json:"version"`
}

// NewCodeConfig creates an CodeConfig with default values. This config is used when lock
// file is not present. The config file load order is
//
//	DefaultCodeConfig -> StarlarkCodeConfig
func NewCodeConfig() *CodeConfig {
	return &CodeConfig{
		Routing: RouteConfig{
			TemplateLocations: []string{"*.go.html"},
			BaseTemplates:     "base_templates",
			PushEvents:        false,
			EarlyHints:        true,
			ContainerExclude:  []string{"static/**/*", "static_root/**/*", "base_templates/**/*", "*.go.html", "*.star", "config_gen.lock"},
		},
		Htmx: HtmxConfig{
			Version: "2.0.3",
		},
	}
}

// NewCompatibleCodeConfig creates an CodeConfig focused on maintaining backward compatibility.
// This is used when the app is created from a source url where the source has the config lock file
// present. The configs are read in the order
//
// CompatibleCodeConfig -> LockFile -> StarlarkCodeConfig
//
// The goal is that if the application has a lock file, then all settings will attempt to be locked
// such that there should not be any change in behavior when the OpenRun version is updated.
// Removing the lock file will result in new config defaults getting applied, which can be
// done when the app developer wants to do an application refresh. Refresh will require additional
// testing to ensure that UI functionality is not changed..
func NewCompatibleCodeConfig() *CodeConfig {
	config := NewCodeConfig()
	config.Htmx.Version = "1.9.1"
	return config
}
