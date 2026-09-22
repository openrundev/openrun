// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"cmp"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/types"
)

// The actions of an app as MCP tools (apps with mcp source "actions"): one
// tool per action, served by OpenRun itself over Streamable HTTP in the MCP
// region of the app. The region is reachable only through the bearer path of
// the server (token audience, app:access, tool scopes, audit), which attaches
// the identity context the permit checks read. Stateless: no session state,
// safe across zero downtime restarts and multiple nodes

const (
	mcpDryRunArg        = "dry_run" // prefixed with _ until it is not a param of the action
	mcpSuggestSuffix    = "_suggest"
	mcpTableRowLimit    = 50        // rows rendered in the text block of a table result
	mcpCellLimit        = 100       // chars of a table cell in the text block
	mcpTextLimit        = 64 << 10  // bytes of values rendered in the text block, what a model reads
	mcpStructuredLimit  = 256 << 10 // bytes of values in the structured result
	mcpStreamTailLimit  = 64 << 10  // bytes of stream output kept for the result
	mcpImageLimit       = 2 << 20   // bytes of an image returned inline
	mcpFileLimit        = 1 << 20   // bytes of a download returned inline
	mcpTextFileLimit    = 256 << 10 // bytes of a text download returned inline as text
	mcpInlineFiles      = 4         // files returned inline per result, the rest are links
	mcpProgressInterval = 250 * time.Millisecond
	reportStream        = "STREAM" // report value of a stream result, beside the apptype report types
)

// MCPTool is an action exposed as an MCP tool
type MCPTool struct {
	Tool    *mcp.Tool
	Action  *Action
	Suggest bool // the tool runs the suggest handler
	dryRun  string
}

// MCPTools returns the MCP tools for the actions: a tool per action, named by
// ToolNames, plus a <tool>_suggest tool for the actions with a suggest
// handler. An action with a required file upload param cannot be called with
// a JSON args document and gets no tool
func MCPTools(actions []*Action) ([]*MCPTool, error) {
	names := ToolNames(actions)
	suggestNames := suggestToolNames(actions, names)
	tools := make([]*MCPTool, 0, len(actions))
	for _, act := range actions {
		if act.HasRequiredFileParam() {
			act.Warn().Msgf("action %s has a required file upload param, it is not exposed as an MCP tool", act.name)
			continue
		}
		schema, err := act.InputJSONSchema(true)
		if err != nil {
			return nil, err
		}
		schema["additionalProperties"] = false

		// The validate control must not shadow a param of the action
		dryRunArg := mcpDryRunArg
		for act.HasParam(dryRunArg) {
			dryRunArg = "_" + dryRunArg
		}
		runSchema := map[string]any{}
		for k, v := range schema {
			runSchema[k] = v
		}
		properties := map[string]any{}
		for k, v := range schema["properties"].(map[string]any) {
			properties[k] = v
		}
		properties[dryRunArg] = map[string]any{
			"type":        "boolean",
			"default":     false,
			"description": "Validate the arguments only: reports the param errors, runs nothing",
		}
		runSchema["properties"] = properties

		description := strings.TrimSpace(act.description)
		if description != "" {
			description += "\n"
		}
		description += fmt.Sprintf("Set %s=true to validate the arguments without running.", dryRunArg)
		if act.suggest != nil {
			description += fmt.Sprintf(" %s suggests argument values.", suggestNames[act])
		}
		tools = append(tools, &MCPTool{
			Action: act,
			dryRun: dryRunArg,
			Tool: &mcp.Tool{
				Name:         names[act],
				Title:        act.name,
				Description:  description,
				InputSchema:  runSchema,
				OutputSchema: mcpResultSchema,
			},
		})

		if act.suggest != nil {
			// Suggest takes a partial set of args, no param is required
			suggestSchema := map[string]any{}
			for k, v := range schema {
				if k != "required" {
					suggestSchema[k] = v
				}
			}
			tools = append(tools, &MCPTool{
				Action:  act,
				Suggest: true,
				Tool: &mcp.Tool{
					Name:        suggestNames[act],
					Title:       act.name + " (suggest)",
					Description: fmt.Sprintf("Suggest argument values for %s, given the arguments known so far. Runs nothing.", names[act]),
					InputSchema: suggestSchema,
					Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
				},
			})
		}
	}
	return tools, nil
}

// suggestToolNames returns the name of the suggest tool for each action with
// a suggest handler: <tool>_suggest, with a numeric suffix when that is the
// name of another tool (an action at /foo_suggest beside /foo). The tool
// names are unique across the run and the suggest tools: the MCP server
// replaces a tool added under an existing name
func suggestToolNames(actions []*Action, names map[*Action]string) map[*Action]string {
	used := map[string]bool{}
	for _, name := range names {
		used[name] = true
	}
	suggestNames := map[*Action]string{}
	for _, act := range actions {
		if act.suggest == nil {
			continue
		}
		name := names[act] + mcpSuggestSuffix
		for suffix := 2; used[name]; suffix++ {
			name = fmt.Sprintf("%s%s_%d", names[act], mcpSuggestSuffix, suffix)
		}
		used[name] = true
		suggestNames[act] = name
	}
	return suggestNames
}

var mcpResultSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"status":       map[string]any{"type": "string", "description": "Result message of the action"},
		"report":       map[string]any{"type": "string", "description": "Kind of values: TABLE, TEXT, JSON, DOWNLOAD, IMAGE, or STREAM for command output"},
		"values":       map[string]any{"type": "array", "description": "Result rows (objects) or lines (strings)"},
		"truncated":    map[string]any{"type": "boolean", "description": "The values or the output were cut to the size limit"},
		"param_errors": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
		"output":       map[string]any{"type": "string", "description": "Command output, for a stream result (the tail when large)"},
		"exit_status":  map[string]any{"type": "integer", "description": "Exit status of the command, for a stream result"},
	},
	"required": []string{"status"},
}

// BuildMCPHandler creates the Streamable HTTP handler serving the actions as
// MCP tools
func BuildMCPHandler(appName, version string, actions []*Action) (http.Handler, error) {
	tools, err := MCPTools(actions)
	if err != nil {
		return nil, err
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: appName, Version: version}, &mcp.ServerOptions{
		Instructions: fmt.Sprintf("Tools are the actions of the %s app, they run as the authenticated user. "+
			"Pass %s=true to a tool to validate its arguments without running it. "+
			"A tool named <tool>%s, where present, suggests argument values.", appName, mcpDryRunArg, mcpSuggestSuffix),
	})

	byName := make(map[string]*MCPTool, len(tools))
	for _, tool := range tools {
		byName[tool.Tool.Name] = tool
		srv.AddTool(tool.Tool, tool.handle)
	}

	// tools/list shows a caller only the tools of the actions their permit
	// allows: the param definitions and defaults of restricted actions are
	// not disclosed (the same rule as the OpenAPI spec). tools/call checks
	// the permit again in Invoke
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			listResult, ok := result.(*mcp.ListToolsResult)
			if err != nil || !ok {
				return result, err
			}
			visible := make([]*mcp.Tool, 0, len(listResult.Tools))
			for _, listed := range listResult.Tools {
				tool, known := byName[listed.Name]
				if !known {
					continue
				}
				authorized, authErr := tool.Action.Authorized(ctx)
				if authErr != nil {
					return nil, authErr
				}
				if authorized {
					visible = append(visible, listed)
				}
			}
			listResult.Tools = visible
			return listResult, nil
		}
	})

	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return srv
	}, &mcp.StreamableHTTPOptions{Stateless: true}), nil
}

// mcpToolError is a tool execution error: reported in the result (isError)
// so that the model can see the message and correct the call
func mcpToolError(format string, args ...any) *mcp.CallToolResult {
	result := &mcp.CallToolResult{IsError: true}
	result.Content = []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}}
	return result
}

func (t *MCPTool) handle(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args map[string]jsontext.Value
	if len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return mcpToolError("invalid arguments: %s", err), nil
		}
	}

	op := OpRun
	if t.Suggest {
		op = OpSuggest
	} else if raw, ok := args[t.dryRun]; ok {
		delete(args, t.dryRun)
		var dryRun bool
		if err := json.Unmarshal(raw, &dryRun); err != nil {
			return mcpToolError("param %s must be a boolean", t.dryRun), nil
		}
		if dryRun {
			op = OpValidate
		}
	}

	outcome, invErr := t.Action.Invoke(ctx, Invocation{Op: op, AuditOp: AuditOp(SourceMCP, op), JSONArgs: args})
	if invErr != nil {
		return mcpToolError("%s", invErr.Msg), nil
	}
	defer outcome.Close()

	var progress func(chunk string)
	if token := req.Params.GetProgressToken(); token != nil && req.Session != nil {
		progress = mcpProgressEmitter(ctx, req.Session, token)
	}
	return t.Action.MCPResult(ctx, outcome, op, progress), nil
}

// mcpProgressEmitter forwards stream output to the client as progress
// notifications, batched to at most one per mcpProgressInterval
func mcpProgressEmitter(ctx context.Context, session *mcp.ServerSession, token any) func(chunk string) {
	var pending strings.Builder
	var count float64
	lastSent := time.Now()
	return func(chunk string) {
		pending.WriteString(chunk)
		if chunk != "" && time.Since(lastSent) < mcpProgressInterval {
			return
		}
		if pending.Len() == 0 {
			return
		}
		count++
		_ = session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Progress:      count,
			Message:       strings.ToValidUTF8(pending.String(), "\uFFFD"),
		})
		pending.Reset()
		lastSent = time.Now()
	}
}

// MCPResult builds the tool result for an outcome: the structured content for
// programs and a text block written for a model. A stream result is consumed
// to completion, progress (optional) receives the output as it arrives and is
// called with an empty chunk at the end to flush
func (a *Action) MCPResult(ctx context.Context, o *Outcome, op Op, progress func(chunk string)) *mcp.CallToolResult {
	structured, text, isError := a.ResultDocument(ctx, o, op, progress)
	result := &mcp.CallToolResult{IsError: isError, StructuredContent: structured}
	result.Content = []mcp.Content{&mcp.TextContent{Text: text}}
	if !isError {
		if report, _ := structured["report"].(string); report == apptype.DOWNLOAD || report == apptype.IMAGE {
			result.Content = append(result.Content, a.fileContents(ctx, o, report == apptype.IMAGE)...)
		}
	}
	return result
}

// ResultDocument returns the result of an outcome as a document (status,
// report, values, param_errors; output and exit_status for a stream), its
// rendering as text for a model, and whether the result is an error the
// caller can act on (param errors, a failed command)
func (a *Action) ResultDocument(ctx context.Context, o *Outcome, op Op, progress func(chunk string)) (map[string]any, string, bool) {
	doc, text, isError := a.resultDocument(ctx, o, op, progress)
	// The values are limited as they are rendered; this bounds the rest (a
	// status, param errors, suggestions, a table of very wide rows) as well:
	// the text block goes into the context of a model in full
	return doc, capText(text, 2*mcpTextLimit), isError
}

func (a *Action) resultDocument(ctx context.Context, o *Outcome, op Op, progress func(chunk string)) (map[string]any, string, bool) {
	if op == OpSuggest {
		response, invErr := a.SuggestResult(o.Suggest)
		if invErr != nil {
			return map[string]any{"status": invErr.Msg}, invErr.Msg, true
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n", response["status"])
		if params, ok := response["params"].(map[string]any); ok {
			for _, name := range slices.Sorted(maps.Keys(params)) {
				fmt.Fprintf(&b, "%s = %s\n", name, compactJSON(params[name]))
			}
		}
		return response, b.String(), false
	}

	if o.IsStream() {
		return a.streamDocument(ctx, o, progress)
	}

	doc, code := a.APIResult(o, op == OpValidate)
	var b strings.Builder
	if code == http.StatusUnprocessableEntity {
		fmt.Fprintf(&b, "%s\n", cmp.Or(o.Status, "Invalid arguments"))
		errs := doc["param_errors"].(map[string]string)
		for _, name := range slices.Sorted(maps.Keys(errs)) {
			fmt.Fprintf(&b, "param %s: %s\n", name, errs[name])
		}
		return doc, b.String(), true
	}
	if op == OpValidate {
		return doc, cmp.Or(o.Status, "Arguments are valid") + "\n", false
	}

	if o.Status != "" {
		fmt.Fprintf(&b, "%s\n", o.Status)
	}
	report, _ := doc["report"].(string)
	// The text block is what a model reads, in full: every report type is
	// limited, a table by rows and the lines of the other reports by size
	switch {
	case len(o.ValuesStr) > 0:
		b.WriteString("\n")
		writeLimitedLines(&b, len(o.ValuesStr), func(i int) string { return o.ValuesStr[i] }, mcpTextLimit)
	case len(o.ValuesMap) == 0:
	case report == apptype.TABLE:
		b.WriteString("\n" + markdownTable(o.ValuesMap, mcpTableRowLimit))
	default:
		writeLimitedLines(&b, len(o.ValuesMap), func(i int) string { return compactJSON(o.ValuesMap[i]) }, mcpTextLimit)
	}

	// The structured values are capped too
	if encoded, err := json.Marshal(doc["values"]); err == nil && len(encoded) > mcpStructuredLimit {
		doc["values"] = truncateValues(o, mcpStructuredLimit)
		doc["truncated"] = true
		b.WriteString("(structured values truncated to the size limit)\n")
	}
	return doc, b.String(), false
}

// writeLimitedLines writes the lines which fit in limit bytes, and a note with
// the number of lines left out. Lines are produced one at a time: a large
// result is not rendered beyond the limit. A first line which does not fit by
// itself is cut, so that the block is never empty
func writeLimitedLines(b *strings.Builder, count int, line func(i int) string, limit int) {
	written := 0
	for i := 0; i < count; i++ {
		text := line(i)
		if written+len(text)+1 > limit {
			if i == 0 {
				b.WriteString(capText(text, limit) + "\n")
				i++
			}
			if left := count - i; left > 0 {
				fmt.Fprintf(b, "... %d more values, the text is limited to %d bytes\n", left, limit)
			}
			return
		}
		b.WriteString(text + "\n")
		written += len(text) + 1
	}
}

// capText cuts text to limit bytes, on a character boundary, noting the cut
func capText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + fmt.Sprintf("\n... (cut, %d of %d bytes shown)\n", cut, len(text))
}

// streamDocument consumes a stream result to completion
func (a *Action) streamDocument(ctx context.Context, o *Outcome, progress func(chunk string)) (map[string]any, string, bool) {
	var tail []byte
	truncated := false
	exitStatus, err := o.ConsumeStream(ctx, func(chunk string) error {
		tail = append(tail, chunk...)
		if len(tail) > 2*mcpStreamTailLimit {
			tail = append([]byte{}, tail[len(tail)-mcpStreamTailLimit:]...)
			truncated = true
		}
		if progress != nil {
			progress(chunk)
		}
		return nil
	})
	if progress != nil {
		progress("") // flush
	}
	if len(tail) > mcpStreamTailLimit {
		tail = tail[len(tail)-mcpStreamTailLimit:]
		truncated = true
	}
	output := strings.ToValidUTF8(string(tail), "�")

	doc := map[string]any{"status": o.Status, "report": reportStream, "output": output}
	var b strings.Builder
	if o.Status != "" {
		fmt.Fprintf(&b, "%s\n", o.Status)
	}
	if truncated {
		doc["truncated"] = true
		fmt.Fprintf(&b, "(output truncated, showing the last %d bytes)\n", mcpStreamTailLimit)
	}
	b.WriteString(output)
	if !strings.HasSuffix(output, "\n") && output != "" {
		b.WriteString("\n")
	}
	if err != nil {
		a.Error().Err(err).Msg("error producing action stream")
		fmt.Fprintf(&b, "stream failed: %s\n", err)
		return doc, b.String(), true
	}
	doc["exit_status"] = exitStatus
	fmt.Fprintf(&b, "exit status %d\n", exitStatus)
	return doc, b.String(), exitStatus != 0
}

// fileContents returns the content blocks for the files of a download or
// image result. An MCP client has no app session to fetch a result url with,
// so the files within the app are fetched here as the caller and returned
// inline: images as image content, other files as embedded resources (text
// when the file is text). Files over the size limits, files after the first
// mcpInlineFiles and urls outside the app are returned as resource links
func (a *Action) fileContents(ctx context.Context, o *Outcome, image bool) []mcp.Content {
	// Result urls are server absolute paths (they include the app path)
	origin := ""
	if appUrl, err := url.Parse(types.GetAppUrl(a.appPathDomain, a.serverConfig)); err == nil {
		origin = appUrl.Scheme + "://" + appUrl.Host
	}

	contents := []mcp.Content{}
	for i, file := range ResultFiles(o.ValuesMap) {
		local, external, err := a.ResolveResultURL(file.URL)
		if err != nil {
			contents = append(contents, &mcp.TextContent{Text: err.Error()})
			continue
		}
		uri := file.URL
		if !external {
			uri = origin + local
		}
		name := cmp.Or(file.Name, path.Base(strings.SplitN(local+file.URL, "?", 2)[0]))
		link := &mcp.ResourceLink{URI: uri, Name: name}
		if external || a.fetchFile == nil || i >= mcpInlineFiles {
			contents = append(contents, link)
			continue
		}

		limit := int64(mcpFileLimit)
		if image {
			limit = mcpImageLimit
		}
		fetched, err := a.fetchFile(ctx, local, limit)
		if err != nil {
			note := fmt.Sprintf("%s was not returned inline: %s", name, err)
			if errors.Is(err, ErrFileTooLarge) {
				note = fmt.Sprintf("%s is over the %d byte limit for inline content, it is available at the link for a signed in user", name, limit)
			}
			contents = append(contents, &mcp.TextContent{Text: note}, link)
			continue
		}
		switch {
		case strings.HasPrefix(fetched.MimeType, "image/"):
			contents = append(contents, &mcp.ImageContent{Data: fetched.Data, MIMEType: fetched.MimeType})
		case isTextFile(fetched) && len(fetched.Data) <= mcpTextFileLimit:
			contents = append(contents, &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI: uri, MIMEType: fetched.MimeType, Text: string(fetched.Data)}})
		default:
			contents = append(contents, &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI: uri, MIMEType: fetched.MimeType, Blob: fetched.Data}})
		}
	}
	return contents
}

func isTextFile(file *FetchedFile) bool {
	mimeType := strings.ToLower(file.MimeType)
	if strings.HasPrefix(mimeType, "text/") || strings.Contains(mimeType, "json") || strings.Contains(mimeType, "xml") ||
		strings.Contains(mimeType, "yaml") || strings.Contains(mimeType, "csv") {
		return utf8.Valid(file.Data)
	}
	return false
}

// markdownTable renders rows as a markdown table, with the columns of the
// first row sorted by name as the form UI does
func markdownTable(rows []map[string]any, limit int) string {
	keys := slices.Sorted(maps.Keys(rows[0]))
	var b strings.Builder
	b.WriteString("| " + strings.Join(keys, " | ") + " |\n")
	b.WriteString("|" + strings.Repeat(" --- |", len(keys)) + "\n")
	for i, row := range rows {
		if i >= limit {
			fmt.Fprintf(&b, "... %d more rows\n", len(rows)-limit)
			break
		}
		cells := make([]string, 0, len(keys))
		for _, key := range keys {
			cell := ""
			if v, ok := row[key]; ok && v != nil {
				cell = fmt.Sprintf("%v", v)
			}
			if len(cell) > mcpCellLimit {
				cell = cell[:mcpCellLimit] + "..."
			}
			cell = strings.NewReplacer("|", "\\|", "\n", " ", "\r", "").Replace(cell)
			cells = append(cells, cell)
		}
		b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}
	return b.String()
}

// truncateValues returns the leading values which fit in the size limit
func truncateValues(o *Outcome, limit int) []any {
	values := []any{}
	size := 0
	add := func(v any) bool {
		encoded, err := json.Marshal(v)
		if err != nil || size+len(encoded) > limit {
			return false
		}
		size += len(encoded) + 1
		values = append(values, v)
		return true
	}
	for _, v := range o.ValuesStr {
		if !add(v) {
			return values
		}
	}
	for _, v := range o.ValuesMap {
		if !add(v) {
			return values
		}
	}
	return values
}

func compactJSON(v any) string {
	encoded, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(encoded)
}
