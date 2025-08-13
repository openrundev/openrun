// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"

	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/app/appfs"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

const (
	STYLE_FILE_PATH = "static/gen/css/style.css"
)

const (
	TailwindCSS types.StyleType = "tailwindcss"
	DaisyUI     types.StyleType = "daisyui"
	Other       types.StyleType = "other"
	None        types.StyleType = ""
)

// AppStyle is the style related configuration and state for an app. It is created
// when the App is loaded. It keeps track of the watcher process required to rebuild the
// CSS file when the tailwind/daisy config changes. The reload mutex lock in App is used to
// ensure only one call to the watcher is done at a time, no locking is implemented in AppStyle
type AppStyle struct {
	appId          types.AppId
	library        types.StyleType
	themes         []string
	libraryUrl     string
	DisableWatcher bool
	watcher        *exec.Cmd
	watcherState   *WatcherState
	watcherStdout  *os.File
	Light          string
	Dark           string
}

// WatcherState is the state of the watcher process as of when it was last started.
type WatcherState struct {
	library           types.StyleType
	templateLocations []string
}

// Init initializes the AppStyle object from the app definition
func (s *AppStyle) Init(appId types.AppId, appDef *starlarkstruct.Struct) error {
	var ok bool
	var err error

	s.appId = appId

	var styleAttr starlark.Value
	if styleAttr, err = appDef.Attr("style"); err != nil {
		// No style defined
		s.library = None
		s.libraryUrl = ""
		s.DisableWatcher = true
		return nil
	}

	var styleDef *starlarkstruct.Struct
	if styleDef, ok = styleAttr.(*starlarkstruct.Struct); !ok {
		return fmt.Errorf("style attr is not a struct")
	}

	var library string
	var themes []string
	var disableWatcher bool
	if library, err = apptype.GetStringAttr(styleDef, "library"); err != nil {
		return err
	}
	if s.Light, err = apptype.GetStringAttr(styleDef, "light"); err != nil {
		return err
	}
	if s.Dark, err = apptype.GetStringAttr(styleDef, "dark"); err != nil {
		return err
	}
	if themes, err = apptype.GetListStringAttr(styleDef, "themes", true); err != nil {
		return err
	}
	if disableWatcher, err = apptype.GetBoolAttr(styleDef, "disable_watcher"); err != nil {
		return err
	}
	themes = append(themes, s.Light, s.Dark)
	slices.Sort(themes)
	themes = slices.Compact(themes)
	s.DisableWatcher = disableWatcher

	libType := strings.ToLower(library)
	s.themes = themes
	switch libType {
	case string(None):
		s.library = None
		s.libraryUrl = ""
	case string(TailwindCSS):
		s.library = TailwindCSS
		s.libraryUrl = ""
	case string(DaisyUI):
		s.library = DaisyUI
		s.libraryUrl = ""
	default:
		if strings.HasPrefix(libType, "http://") || strings.HasPrefix(libType, "https://") {
			s.libraryUrl = libType
			s.library = Other
		} else {
			return fmt.Errorf("invalid style library config : %s", libType)
		}
	}

	return nil
}

// Setup sets up the style library for the app. This is called when the app is reloaded.
func (s *AppStyle) Setup(dev *AppDev) error {
	switch s.library {
	case None:
		// Empty out the style.css file
		return dev.sourceFS.Write(STYLE_FILE_PATH, []byte(""))
	case TailwindCSS:
		fallthrough
	case DaisyUI:
		// Generate the tailwind/daisyui config files
		return s.setupTailwindConfig(dev.Config.Routing.TemplateLocations, dev.sourceFS, dev.workFS)
	case Other:
		// Download style.css from url
		return dev.downloadFile(s.libraryUrl, dev.sourceFS, STYLE_FILE_PATH)
	default:
		return fmt.Errorf("invalid style library type : %s", s.library)
	}
}

const (
	// TODO: allow custom config file to be specified
	TAILWIND_CONFIG_FILE     = "tailwind.config.js"
	TAILWIND_CONFIG_CONTENTS = `
	module.exports = {
		content: [%s],
		theme: {
		  extend: {},
		},
	  
		plugins: [
		  %s
		],
		%s
	}`

	TAILWIND_INPUT_CONTENTS = `
	@tailwind base;
	@tailwind components;
	@tailwind utilities;
	`
)

func (s *AppStyle) setupTailwindConfig(templateLocations []string, sourceFS *appfs.WritableSourceFs, workFS *appfs.WorkFs) error {
	configPath := fmt.Sprintf("style/%s", TAILWIND_CONFIG_FILE)
	inputPath := fmt.Sprintf("style/%s", "input.css")

	daisyPlugin := ""
	daisyThemes := ""
	if s.library == DaisyUI {
		daisyPlugin = `require("daisyui")`
		if len(s.themes) > 0 {
			quotedThemes := strings.Builder{}
			for i, theme := range s.themes {
				if i > 0 {
					quotedThemes.WriteString(", ")
				}
				quotedThemes.WriteString(fmt.Sprintf("\"%s\"", theme))
			}

			daisyThemes = fmt.Sprintf("  daisyui: { themes: [%s], },", quotedThemes.String())
		}
	}

	// Add the action templates to the input list
	var buf strings.Builder
	embededFiles, err := action.GetEmbeddedTemplates()
	if err != nil {
		return fmt.Errorf("error getting embedded templates : %s", err)
	}
	for name, data := range embededFiles {
		filePath := fmt.Sprintf("action/%s", name)
		_, err := workFS.Stat(filePath)
		if err == nil {
			// File already exists, skip
			continue
		}
		if err := workFS.Write(filePath, data); err != nil {
			return fmt.Errorf("error writing embedded template file : %s", err)
		}
	}
	buf.WriteString(fmt.Sprintf("'%s'", path.Join(workFS.Root, "action", "*.go.html")))

	templateLocations = append(templateLocations, "base_templates/*.go.html")
	// Add the template locations to the input list
	for _, loc := range templateLocations {
		buf.WriteString(", ")
		buf.WriteString(fmt.Sprintf("'%s'", path.Join(sourceFS.Root, loc)))
	}

	buf.WriteString(", ")
	buf.WriteString(fmt.Sprintf("'%s'", path.Join(sourceFS.Root, "static", "*.js")))

	configContents := fmt.Sprintf(TAILWIND_CONFIG_CONTENTS, buf.String(), daisyPlugin, daisyThemes)
	if err := workFS.Write(configPath, []byte(configContents)); err != nil {
		return fmt.Errorf("error writing tailwind config file : %s", err)
	}
	if err := workFS.Write(inputPath, []byte(TAILWIND_INPUT_CONTENTS)); err != nil {
		return fmt.Errorf("error writing tailwind input file : %s", err)
	}

	return nil
}

// StartWatcher starts the watcher process for the app. This is called when the app is reloaded.
func (s *AppStyle) StartWatcher(dev *AppDev) error {
	switch s.library {
	case None:
		fallthrough
	case Other:
		// If config is being switched from tailwind/daisy to other/none, stop any current watcher
		return s.StopWatcher()
	case TailwindCSS:
		fallthrough
	case DaisyUI:
		if s.DisableWatcher {
			return s.StopWatcher()
		}
		return s.startTailwindWatcher(dev.Config.Routing.TemplateLocations, dev.sourceFS, dev.workFS, dev.systemConfig)
	default:
		return fmt.Errorf("invalid style library type : %s", s.library)
	}
}

func (s *AppStyle) startTailwindWatcher(templateLocations []string, sourceFS *appfs.WritableSourceFs, workFS *appfs.WorkFs, systemConfig *types.SystemConfig) error {
	tailwindCmd := strings.TrimSpace(systemConfig.TailwindCSSCommand)
	if tailwindCmd == "" {
		fmt.Println("Warning: tailwindcss command not configured. Skipping tailwindcss watcher") // TODO: log
		return nil
	}

	if s.watcher != nil {
		if s.watcherState != nil && s.watcherState.library == s.library && slices.Equal(s.watcherState.templateLocations, templateLocations) {
			fmt.Println("Warning: tailwindcss watcher already running with current config. Skipping tailwindcss watcher") // TODO: log
			return nil
		}
		fmt.Printf("Warning: tailwindcss watcher already running with older config. Stopping previous watcher %#v %#v %#v", s.watcherState, s.library, templateLocations) // TODO: log
		if err := s.StopWatcher(); err != nil {
			return err
		}
	}
	s.watcherState = &WatcherState{library: s.library, templateLocations: templateLocations}

	split := strings.Split(tailwindCmd, " ")
	args := []string{}
	if len(split) > 1 {
		args = split[1:]
	}

	// Since the watcher process creates the file, the unit test framework (in memory filesystem)
	// can't be used to test the watcher functionality)
	targetFile := path.Join(sourceFS.Root, STYLE_FILE_PATH)
	targetDir := path.Dir(targetFile)
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("error creating directory %s : %s", targetDir, err)
	}
	args = append(args, "--watch")
	args = append(args, "-c", path.Join(workFS.Root, "style", TAILWIND_CONFIG_FILE))
	args = append(args, "-i", path.Join(workFS.Root, "style", "input.css"))
	args = append(args, "-o", targetFile)
	fmt.Printf("Running command %s args %#v\n", split[0], args) // TODO: log

	// Setup stdin/stdout for watcher process
	if s.watcherStdout != nil {
		_ = s.watcherStdout.Close()
	}
	var err error
	s.watcherStdout, err = os.Create(path.Join(workFS.Root, "tailwindcss.log"))
	if err != nil {
		return fmt.Errorf("error creating tailwindcss log file : %s", err)
	}

	// Start watcher process, wait async for it to complete
	s.watcher = exec.Command(split[0], args...)
	system.SetProcessGroup(s.watcher) // // ensure process group

	s.watcher.Stdin = os.Stdin // this seems to be required for the process to start
	s.watcher.Stdout = s.watcherStdout
	s.watcher.Stderr = s.watcherStdout
	if err := s.watcher.Start(); err != nil {
		return fmt.Errorf("error starting tailwind watcher : %s", err)
	}
	go func() {
		if err := s.watcher.Wait(); err != nil {
			fmt.Printf("error waiting for tailwind watcher : %s\n", err) // TODO: log
		}
	}()

	return nil
}

func (s *AppStyle) StopWatcher() error {
	if s.watcher != nil && s.watcher.Process != nil {
		fmt.Println("Stopping watcher")
		if err := system.KillGroup(s.watcher.Process); err != nil {
			fmt.Printf("error killing previous watcher process : %s\n", err)
		}
		s.watcher = nil
	}
	return nil
}

func (s *AppStyle) GetStyleType() types.StyleType {
	return s.library
}
