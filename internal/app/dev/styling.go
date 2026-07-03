// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package dev

import (
	"cmp"
	"crypto/sha256"
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

	// The standalone tailwindcss v4 CLI does not bundle daisyui; @plugin "daisyui"
	// is resolved through node_modules, walking up from the input.css directory.
	// To avoid requiring any node_modules setup, the prebundled daisyui plugin is
	// downloaded next to the generated input.css and referenced by relative path.
	// The download urls are configured with daisyui_url and daisyui_theme_url in
	// the [system] server config.
	DAISYUI_MODULE_REF       = "daisyui"       // node_modules based plugin reference
	DAISYUI_THEME_MODULE_REF = "daisyui/theme" // node_modules based theme plugin reference
)

// DaisyUIPluginFile is the work dir file name for the prebundled daisyui
// plugin downloaded from url. The name includes a hash of the url so that a
// url (version) change triggers a fresh download.
func DaisyUIPluginFile(url string) string {
	return pluginFileName("daisyui", url)
}

// DaisyUIThemePluginFile is the work dir file name for the prebundled daisyui
// theme plugin (used for custom themes) downloaded from url.
func DaisyUIThemePluginFile(url string) string {
	return pluginFileName("daisyui-theme", url)
}

func pluginFileName(prefix, url string) string {
	hash := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%s-%x.js", prefix, hash[:4])
}

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
// CustomTheme is a daisyui custom theme: the theme name and its CSS
// properties (color-scheme, --color-* etc), in declaration order
type CustomTheme struct {
	Name  string
	Props [][2]string
}

type AppStyle struct {
	appId                 types.AppId
	library               types.StyleType
	themes                []string
	customThemes          []CustomTheme
	libraryUrl            string
	DisableWatcher        bool
	watcher               *exec.Cmd
	watcherState          *WatcherState
	watcherStdout         *os.File
	Light                 string
	Dark                  string
	daisyUIPluginRef      string // plugin reference to use in the generated input.css
	daisyUIThemePluginRef string // theme plugin reference for custom themes
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
	if s.customThemes, err = getCustomThemes(styleDef); err != nil {
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

// getCustomThemes reads the custom_themes style attribute: a dict of theme
// name to a dict of CSS properties. Declaration order is preserved so the
// generated input.css is stable across reloads.
func getCustomThemes(styleDef *starlarkstruct.Struct) ([]CustomTheme, error) {
	customAttr, err := styleDef.Attr("custom_themes")
	if err != nil || customAttr == nil {
		return nil, nil // custom_themes not defined
	}

	customDict, ok := customAttr.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("custom_themes must be a dict of theme name to theme properties")
	}

	customThemes := make([]CustomTheme, 0, customDict.Len())
	for _, item := range customDict.Items() {
		name, ok := item[0].(starlark.String)
		if !ok || name.GoString() == "" {
			return nil, fmt.Errorf("custom_themes keys must be non-empty theme name strings")
		}

		propsDict, ok := item[1].(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("custom theme %s must be a dict of CSS properties", name.GoString())
		}

		theme := CustomTheme{Name: name.GoString(), Props: make([][2]string, 0, propsDict.Len())}
		for _, prop := range propsDict.Items() {
			propName, ok := prop[0].(starlark.String)
			if !ok || propName.GoString() == "" {
				return nil, fmt.Errorf("custom theme %s property names must be non-empty strings", theme.Name)
			}
			propValue, ok := prop[1].(starlark.String)
			if !ok {
				return nil, fmt.Errorf("custom theme %s property %s value must be a string", theme.Name, propName.GoString())
			}
			theme.Props = append(theme.Props, [2]string{propName.GoString(), propValue.GoString()})
		}
		customThemes = append(customThemes, theme)
	}

	return customThemes, nil
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
		if s.library == DaisyUI {
			if tailwindVersion(dev.systemConfig) == types.TailwindVersionLegacy {
				if len(s.customThemes) > 0 {
					return fmt.Errorf("custom_themes require tailwind_version %d", types.TailwindVersionCurrent)
				}
			} else {
				url := dev.systemConfig.DaisyUIURL
				s.daisyUIPluginRef = s.resolvePluginFile(dev, DaisyUIPluginFile(url), url, DAISYUI_MODULE_REF)
				if len(s.customThemes) > 0 {
					themeUrl := dev.systemConfig.DaisyUIThemeURL
					s.daisyUIThemePluginRef = s.resolvePluginFile(dev, DaisyUIThemePluginFile(themeUrl), themeUrl, DAISYUI_THEME_MODULE_REF)
				}
			}
		}
		// Generate the tailwind/daisyui config files
		return s.setupTailwindConfig(dev.Config.Routing.TemplateLocations, dev.sourceFS, dev.workFS, tailwindVersion(dev.systemConfig))
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

	TAILWIND_INPUT_LEGACY_CONTENTS = `
	@tailwind base;
	@tailwind components;
	@tailwind utilities;
	`

	TAILWIND_INPUT_CONTENTS = `
	@import "tailwindcss" source(none);
	%s
	%s
	`
)

func tailwindVersion(systemConfig *types.SystemConfig) int {
	if systemConfig == nil || systemConfig.TailwindVersion == 0 {
		return types.TailwindVersionDefault
	}
	return systemConfig.TailwindVersion
}

func (s *AppStyle) setupTailwindConfig(templateLocations []string, sourceFS *appfs.WritableSourceFs, workFS *appfs.WorkFs, twVersion int) error {
	configPath := fmt.Sprintf("style/%s", TAILWIND_CONFIG_FILE)
	inputPath := fmt.Sprintf("style/%s", "input.css")

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

	var inputContents string
	if twVersion == types.TailwindVersionLegacy {
		daisyPlugin := ""
		daisyThemes := ""
		if s.library == DaisyUI {
			daisyPlugin = `require("daisyui")`
			daisyThemes = s.legacyDaisyThemes()
		}

		configContents := fmt.Sprintf(TAILWIND_CONFIG_CONTENTS, buf.String(), daisyPlugin, daisyThemes)
		if err := workFS.Write(configPath, []byte(configContents)); err != nil {
			return fmt.Errorf("error writing tailwind config file : %s", err)
		}
		inputContents = TAILWIND_INPUT_LEGACY_CONTENTS
	} else {
		inputContents = fmt.Sprintf(TAILWIND_INPUT_CONTENTS, sourceDirectives(buf.String()), s.daisyUIPlugin())
	}

	if err := workFS.Write(inputPath, []byte(inputContents)); err != nil {
		return fmt.Errorf("error writing tailwind input file : %s", err)
	}

	return nil
}

func (s *AppStyle) legacyDaisyThemes() string {
	if len(s.themes) == 0 {
		return ""
	}

	quotedThemes := strings.Builder{}
	for i, theme := range s.themes {
		if i > 0 {
			quotedThemes.WriteString(", ")
		}
		quotedThemes.WriteString(fmt.Sprintf("\"%s\"", theme))
	}

	return fmt.Sprintf("  daisyui: { themes: [%s], },", quotedThemes.String())
}

// resolvePluginFile returns the plugin reference to use in the generated
// input.css. When a tailwind CLI is configured, the prebundled plugin file is
// downloaded into the app work dir, next to input.css (cached across
// restarts), so that the standalone tailwindcss CLI works without requiring
// node_modules. Falls back to the node_modules based reference if the
// download fails.
func (s *AppStyle) resolvePluginFile(dev *AppDev, fileName, url, moduleRef string) string {
	if strings.TrimSpace(dev.systemConfig.TailwindCSSCommand) == "" || url == "" {
		// No watcher will run (or no download url is configured); keep the
		// node_modules based reference for externally run tailwind builds
		return moduleRef
	}

	localRef := "./" + fileName
	filePath := path.Join("style", fileName)
	if fi, err := dev.workFS.Stat(filePath); err == nil && fi.Size() > 0 {
		return localRef
	}

	if err := dev.downloadWorkFile(url, filePath); err != nil {
		dev.Warn().Err(err).Msgf("Error downloading daisyui plugin from %s, falling back to node_modules resolution", url)
		return moduleRef
	}
	return localRef
}

func (s *AppStyle) daisyUIPlugin() string {
	if s.library != DaisyUI {
		return ""
	}

	customNames := map[string]bool{}
	for _, theme := range s.customThemes {
		customNames[theme.Name] = true
	}

	// Custom themes are excluded from the bundled themes list, they are
	// defined through the theme plugin instead
	themes := make([]string, 0, len(s.themes))
	for _, theme := range s.themes {
		if customNames[theme] {
			continue
		}
		themeConfig := theme
		if theme == s.Light {
			themeConfig += " --default"
		}
		if theme == s.Dark {
			themeConfig += " --prefersdark"
		}
		themes = append(themes, themeConfig)
	}

	pluginRef := cmp.Or(s.daisyUIPluginRef, DAISYUI_MODULE_REF)
	var buf strings.Builder
	if len(themes) > 0 {
		fmt.Fprintf(&buf, `@plugin "%s" {
	  themes: %s;
	}`, pluginRef, strings.Join(themes, ", "))
	} else if len(s.customThemes) > 0 {
		// Only custom themes are used, disable the bundled themes
		fmt.Fprintf(&buf, `@plugin "%s" {
	  themes: false;
	}`, pluginRef)
	} else {
		fmt.Fprintf(&buf, `@plugin "%s";`, pluginRef)
	}

	themePluginRef := cmp.Or(s.daisyUIThemePluginRef, DAISYUI_THEME_MODULE_REF)
	for _, theme := range s.customThemes {
		fmt.Fprintf(&buf, "\n\t@plugin \"%s\" {\n", themePluginRef)
		fmt.Fprintf(&buf, "\t  name: \"%s\";\n", theme.Name)
		fmt.Fprintf(&buf, "\t  default: %t;\n", theme.Name == s.Light)
		fmt.Fprintf(&buf, "\t  prefersdark: %t;\n", theme.Name == s.Dark)
		for _, prop := range theme.Props {
			fmt.Fprintf(&buf, "\t  %s: %s;\n", prop[0], prop[1])
		}
		buf.WriteString("\t}")
	}

	return buf.String()
}

func sourceDirectives(contentList string) string {
	sources := strings.Split(contentList, ", ")
	var buf strings.Builder
	for _, source := range sources {
		source = strings.Trim(source, "'")
		buf.WriteString(fmt.Sprintf("@source \"%s\";\n", source))
	}
	return strings.TrimSpace(buf.String())
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
	targetFile, err := ensureSourceOutputDir(sourceFS.Root, STYLE_FILE_PATH, 0700)
	if err != nil {
		return err
	}
	args = append(args, "--watch")
	if tailwindVersion(systemConfig) == types.TailwindVersionLegacy {
		args = append(args, "-c", path.Join(workFS.Root, "style", TAILWIND_CONFIG_FILE))
	}
	args = append(args, "-i", path.Join(workFS.Root, "style", "input.css"))
	args = append(args, "-o", targetFile)
	fmt.Printf("Running command %s args %#v\n", split[0], args) // TODO: log

	// Setup stdin/stdout for watcher process
	if s.watcherStdout != nil {
		_ = s.watcherStdout.Close()
	}
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
