// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Package builder implements the AI app builder: agent sandboxes (containers
// built from per-profile Dockerfiles) driven over the Agent Client Protocol,
// with sessions and full activity persisted in the metadata database
package builder

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	acp "github.com/coder/acp-go-sdk"
	"github.com/openrundev/openrun/internal/container"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
	"github.com/segmentio/ksuid"
)

const maxReadFileBytes = 1024 * 1024

// Manager owns builder sessions: sandbox lifecycle, the ACP driver and the
// activity log. Preview app creation and publishing live in the server
// package; the OnTurnDone hook lets the server react to completed turns
type Manager struct {
	*types.Logger
	config     func() *types.ServerConfig
	db         *metadata.Metadata
	evalSecret func(string) (string, error)

	// OnTurnDone is called (on its own goroutine) after each completed
	// prompt turn; the server uses it to create/refresh the preview app
	OnTurnDone func(sessionId string)

	mu     sync.Mutex
	live   map[string]*liveSession
	stopCh chan struct{}
}

func NewManager(logger *types.Logger, config func() *types.ServerConfig, db *metadata.Metadata,
	evalSecret func(string) (string, error)) *Manager {
	return &Manager{
		Logger:     logger,
		config:     config,
		db:         db,
		evalSecret: evalSecret,
		live:       map[string]*liveSession{},
		stopCh:     make(chan struct{}),
	}
}

// Enabled returns whether builder mode is on in the current config
func (m *Manager) Enabled() bool {
	return m.config().AppBuilder.Enabled
}

// hostMode reports whether security.unsafe_agent_without_sandbox is set:
// agents run as plain host processes instead of container sandboxes
func (m *Manager) hostMode() bool {
	return m.config().Security.UnsafeAgentWithoutSandbox
}

// containerCLI resolves the container runtime binary. The builder is not
// supported on Kubernetes: the sandbox needs a local runtime with host
// directory volume mounts
func (m *Manager) containerCLI() (string, error) {
	command := strings.TrimSpace(m.config().System.ContainerCommand)
	if command == "" || command == "auto" {
		command = container.LookupContainerCommand(true)
	}
	if command == types.CONTAINER_KUBERNETES {
		return "", fmt.Errorf("app_builder is not supported with the Kubernetes container backend")
	}
	if command == "" {
		return "", fmt.Errorf("app_builder requires a docker or podman runtime, none found")
	}
	return command, nil
}

// ValidateConfig checks the app_builder and builder_agent config. Called at
// startup when enabled; also the first part of the verify checklist
func (m *Manager) ValidateConfig() error {
	config := m.config()
	if !config.AppBuilder.Enabled {
		return nil
	}
	// Host mode (unsafe_agent_without_sandbox) needs no container runtime
	if !m.hostMode() {
		if _, err := m.containerCLI(); err != nil {
			return err
		}
	}
	if name := config.AppBuilder.DefaultBuilderProfile; name != "" {
		if _, ok := config.BuilderProfile[name]; !ok {
			return fmt.Errorf("app_builder.default_builder_profile %q has no [builder_profile.%s] entry", name, name)
		}
	}
	for name, agentConfig := range config.BuilderAgent {
		if _, err := resolveProfile(name, agentConfig, os.ReadFile); err != nil {
			return err
		}
	}
	for name, profile := range config.BuilderProfile {
		if profile.Agent == "" {
			return fmt.Errorf("builder_profile.%s: agent is required", name)
		}
		if _, ok := config.BuilderAgent[profile.Agent]; !ok {
			return fmt.Errorf("builder_profile.%s agent %q has no [builder_agent.%s] entry",
				name, profile.Agent, profile.Agent)
		}
		if profile.GitConfig != "" {
			if _, ok := config.BuilderGit[profile.GitConfig]; !ok {
				return fmt.Errorf("builder_profile.%s git_config %q has no [builder_git.%s] entry",
					name, profile.GitConfig, profile.GitConfig)
			}
		}
	}
	return nil
}

// agentConfig resolves an agent config name to its entry. Empty name (a
// session with no builder profile) falls back to opencode - which works
// without a [builder_agent.opencode] entry since the type is inferred from
// the name (the implicit default for fresh installs)
func (m *Manager) agentConfig(name string) (string, types.BuilderAgentConfig, error) {
	config := m.config()
	if name == "" {
		name = "opencode"
	}
	if cfg, ok := config.BuilderAgent[name]; ok {
		return name, cfg, nil
	}
	if name == "opencode" {
		return name, types.BuilderAgentConfig{}, nil
	}
	return "", types.BuilderAgentConfig{}, fmt.Errorf("no [builder_agent.%s] config entry", name)
}

// Start reconciles orphan sandboxes from a previous run, marks their
// sessions detached and starts the idle reaper
func (m *Manager) Start(ctx context.Context) error {
	if !m.Enabled() {
		return nil
	}
	if err := m.ValidateConfig(); err != nil {
		return err
	}
	// Clean up orphan sandbox containers whenever a runtime is available;
	// in host mode a missing runtime is fine (host agents die with the server)
	if cli, err := m.containerCLI(); err == nil {
		if err := StopOrphanSandboxes(ctx, cli); err != nil {
			m.Warn().Err(err).Msg("Error stopping orphan builder sandboxes")
		}
		// State volumes whose session was deleted while docker was down.
		// Only a definitive not-found permits removal: a transient lookup
		// failure (cancelled startup context, database hiccup) must not
		// destroy a live session's agent state, so those keep the volume
		sessionExists := func(id string) bool {
			_, err := m.db.GetBuilderSession(ctx, types.Transaction{}, id)
			if err == nil {
				return true
			}
			if !errors.Is(err, metadata.ErrBuilderSessionNotFound) {
				m.Warn().Err(err).Str("session", id).Msg("Error checking session for state volume sweep, keeping volume")
				return true
			}
			return false
		}
		if err := SweepOrphanStateVolumes(ctx, cli, sessionExists); err != nil {
			m.Warn().Err(err).Msg("Error sweeping orphan agent state volumes")
		}
	} else if !m.hostMode() {
		return err
	}

	// Sessions that were live when the server stopped are now detached
	sessions, err := m.db.ListBuilderSessions(ctx, "")
	if err != nil {
		return err
	}
	for _, session := range sessions {
		switch session.Status {
		case types.BuilderSessionStarting, types.BuilderSessionReady, types.BuilderSessionRunning:
			session.Status = types.BuilderSessionDetached
			if err := m.updateSession(ctx, session); err != nil {
				m.Warn().Err(err).Str("session", session.Id).Msg("Error marking session detached")
			}
		}
	}

	go m.idleReaper()
	return nil
}

// Stop stops all live sandboxes (server shutdown)
func (m *Manager) Stop() {
	close(m.stopCh)
	m.mu.Lock()
	sessions := make([]*liveSession, 0, len(m.live))
	for _, ls := range m.live {
		sessions = append(sessions, ls)
	}
	m.mu.Unlock()
	for _, ls := range sessions {
		m.stopLive(ls, types.BuilderSessionDetached)
	}
}

func (m *Manager) idleReaper() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			idleMins := m.config().AppBuilder.SessionIdleMins
			if idleMins <= 0 {
				continue
			}
			cutoff := time.Now().Add(-time.Duration(idleMins) * time.Minute)
			m.mu.Lock()
			var idle []*liveSession
			for _, ls := range m.live {
				ls.mu.Lock()
				if !ls.turnActive && ls.lastActive.Before(cutoff) {
					idle = append(idle, ls)
				}
				ls.mu.Unlock()
			}
			m.mu.Unlock()
			for _, ls := range idle {
				m.Info().Str("session", ls.id).Msg("Stopping idle builder sandbox")
				m.appendActivity(ls.id, ls.userID, "lifecycle", "sandbox stopped after idle timeout", nil)
				m.stopLive(ls, types.BuilderSessionDetached)
			}
		}
	}
}

// workspaceRoot returns the parent directory for session workspaces
func (m *Manager) workspaceRoot() string {
	config := m.config()
	if config.AppBuilder.WorkspaceDir != "" {
		return config.AppBuilder.WorkspaceDir
	}
	return filepath.Join(os.ExpandEnv("$OPENRUN_HOME"), "run", "builder")
}

// CreateSession creates the session row and workspace, then launches the
// sandbox and sends the composed first prompt asynchronously. The returned
// session is in starting state; progress streams over session events.
// profileChoice names a [builder_profile.*] entry chosen by the user; empty
// resolves the implicit default (no profiles) or the only configured one.
// The resolved profile decides the agent config, git target and publish
// restrictions and is stored on the session.
// editApp marks a session editing an existing published app: the caller
// (server) validates the app. seed populates the workspace (spec scaffold
// or the edited app's source) and may set session fields (EditVersion,
// PublishPath); it runs to completion BEFORE the agent launches, so the
// first prompt never races an empty or half-copied workspace. A seed
// failure aborts the create with nothing left behind
func (m *Manager) CreateSession(ctx context.Context, userID, name, prompt, spec, specKind, profileChoice, editApp string,
	services []string, seed func(*types.BuilderSession) error) (*types.BuilderSession, error) {
	config := m.config()
	if !config.AppBuilder.Enabled {
		return nil, fmt.Errorf("app_builder is not enabled")
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	if strings.TrimSpace(prompt) == "" {
		return nil, fmt.Errorf("prompt is required")
	}
	profileName, profile, err := config.ChooseBuilderProfile(profileChoice)
	if err != nil {
		return nil, err
	}
	agentChoice := ""
	if profile != nil {
		agentChoice = profile.Agent
	}
	agentName, agentEntry, err := m.agentConfig(agentChoice)
	if err != nil {
		return nil, err
	}
	if _, err := resolveProfile(agentName, agentEntry, os.ReadFile); err != nil {
		return nil, err
	}
	// Fail now, not at publish time, if the profile names a missing
	// [builder_git.*] entry. Edit sessions republish to the app's own
	// destination, so the profile git resolution does not apply
	if editApp == "" {
		if _, err := config.ResolveBuilderGit(profileName); err != nil {
			return nil, err
		}
	}

	m.mu.Lock()
	liveCount := len(m.live)
	m.mu.Unlock()
	if maxSessions := config.AppBuilder.MaxSessions; maxSessions > 0 && liveCount >= maxSessions {
		return nil, fmt.Errorf("max concurrent builder sessions (%d) reached, stop an idle session first", maxSessions)
	}

	genId, err := ksuid.NewRandom()
	if err != nil {
		return nil, err
	}
	id := types.ID_PREFIX_BUILDER_SES + strings.ToLower(genId.String())
	workspace := filepath.Join(m.workspaceRoot(), id)
	if err := os.MkdirAll(workspace, 0755); err != nil {
		return nil, fmt.Errorf("creating workspace: %w", err)
	}

	session := &types.BuilderSession{
		Id:           id,
		UserID:       userID,
		Name:         name,
		Spec:         spec,
		Agent:        agentName,
		Profile:      profileName,
		EditApp:      editApp,
		Services:     services,
		Status:       types.BuilderSessionStarting,
		WorkspaceDir: workspace,
	}

	if seed != nil {
		if err := seed(session); err != nil {
			os.RemoveAll(workspace) //nolint:errcheck
			return nil, err
		}
	}

	// Edit workspaces are seeded from the app's own source, and the spec
	// (and so the spec kind) only reflects the app's metadata: a custom
	// containerized app without a spec would read as the starlark shape.
	// The seeded files are the truth - a container file means the agent
	// must get the container guidance, not the starlark template shape
	if editApp != "" && specKind != SpecKindContainer {
		for _, name := range []string{"Containerfile", "Dockerfile"} {
			if _, err := os.Stat(filepath.Join(workspace, name)); err == nil {
				specKind = SpecKindContainer
				break
			}
		}
	}

	tx, err := m.db.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := m.db.CreateBuilderSession(ctx, tx, session); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	m.appendActivity(id, userID, "lifecycle", "session created", map[string]any{"agent": agentName, "spec": spec, "name": name})
	m.appendActivity(id, userID, "prompt", prompt, nil)

	ls := newLiveSession(id, userID)
	// The first turn is claimed up front so SendMessage rejects with "still
	// working" during launch instead of racing (and dropping) the first prompt
	ls.turnActive = true
	m.mu.Lock()
	m.live[id] = ls
	m.mu.Unlock()

	// App containers (previews included) need a container runtime; when
	// disabled the no-spec guidance must not offer container shapes
	containersAvailable := strings.TrimSpace(config.System.ContainerCommand) != ""
	firstPrompt := composePrompt(config.AppBuilder.SystemPrompt, spec, specKind, prompt, profile, editApp,
		services, containersAvailable)
	go func() {
		if err := m.launch(ls); err != nil {
			m.failSession(ls, fmt.Errorf("starting sandbox: %w", err))
			return
		}
		m.runTurn(ls, firstPrompt, true)
	}()

	return session, nil
}

// launch builds the profile image if needed, starts the sandbox container
// and performs the ACP handshake
func (m *Manager) launch(ls *liveSession) error {
	session, err := m.db.GetBuilderSession(context.Background(), types.Transaction{}, ls.id)
	if err != nil {
		return err
	}
	_, agentConfig, err := m.agentConfig(session.Agent)
	if err != nil {
		return err
	}
	p, err := resolveProfile(session.Agent, agentConfig, os.ReadFile)
	if err != nil {
		return err
	}

	env := map[string]string{}
	for key, value := range p.env {
		resolved, err := m.evalSecret(value)
		if err != nil {
			return fmt.Errorf("resolving env %s: %w", key, err)
		}
		env[key] = resolved
	}
	// Model/effort ride into the sandbox as env for agents that honor it
	// (custom agents, claude's ANTHROPIC_MODEL); agents advertising ACP
	// config options get them set explicitly after session/new below
	if agentConfig.Model != "" {
		if _, ok := env["OPENRUN_AGENT_MODEL"]; !ok {
			env["OPENRUN_AGENT_MODEL"] = agentConfig.Model
		}
		if _, ok := env["ANTHROPIC_MODEL"]; !ok && p.agentType == "claude" {
			env["ANTHROPIC_MODEL"] = agentConfig.Model
		}
	}
	if agentConfig.Effort != "" {
		if _, ok := env["OPENRUN_AGENT_EFFORT"]; !ok {
			env["OPENRUN_AGENT_EFFORT"] = agentConfig.Effort
		}
	}

	// The agent's working directory: the workspace mount point inside the
	// sandbox, or the real workspace path for host-mode (no sandbox) agents
	acpCwd := "/workspace"
	var sb *sandbox
	if m.hostMode() {
		ls.emit(Event{Kind: "status", Status: "starting agent process (unsafe, no sandbox)"})
		sb, err = startHostAgent(session.WorkspaceDir, p, env)
		if err != nil {
			return err
		}
		acpCwd = session.WorkspaceDir
	} else {
		cli, err := m.containerCLI()
		if err != nil {
			return err
		}
		ls.emit(Event{Kind: "status", Status: "building image"})
		image, err := buildImage(context.Background(), cli, p)
		if err != nil {
			return err
		}
		ls.emit(Event{Kind: "status", Status: "starting sandbox"})
		sb, err = startSandbox(cli, image, ls.id, session.WorkspaceDir, p, env)
		if err != nil {
			return err
		}
	}

	conn := acp.NewClientSideConnection(&driverClient{manager: m, session: ls}, sb.stdin, sb.stdout)

	handshakeCtx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	initResp, err := conn.Initialize(handshakeCtx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientInfo:      &acp.Implementation{Name: "openrun", Title: acp.Ptr("OpenRun App Builder"), Version: "1.0"},
		// auth: terminal login methods are not supported (defaults sent
		// explicitly so agents may rely on the declaration)
		ClientCapabilities: acp.ClientCapabilities{Auth: acp.AuthCapabilities{Terminal: false}},
	})
	if err != nil {
		sb.stop()
		return fmt.Errorf("ACP initialize failed: %w (agent stderr: %s)", err, sb.stderr())
	}
	// Version negotiation: the agent echoes our version if it supports it,
	// otherwise it answers with its own latest. The client must disconnect
	// when it does not support the returned version
	if initResp.ProtocolVersion != acp.ProtocolVersionNumber {
		sb.stop()
		return fmt.Errorf("agent %s uses unsupported ACP protocol version %v (supported: %v)",
			session.Agent, initResp.ProtocolVersion, acp.ProtocolVersionNumber)
	}
	// Restore the previous conversation when the agent supports it and this
	// session ran before: session/resume (rehydrates without replaying the
	// history) is preferred over session/load (streams the whole history
	// back as updates, suppressed by the restoring flag). The agent's own
	// state lives in its home - persisted across sandbox restarts by the
	// state volume (host mode uses the real home). A failed restore falls
	// back to a fresh session: the chat transcript in the console is
	// unaffected either way, only the agent's memory of it
	acpSessionId := acp.SessionId(session.AcpSessionId)
	restored := false
	if session.AcpSessionId != "" {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), handshakeTimeout)
		caps := initResp.AgentCapabilities
		if caps.SessionCapabilities.Resume != nil {
			_, err := conn.ResumeSession(restoreCtx, acp.ResumeSessionRequest{
				Cwd: acpCwd, SessionId: acpSessionId})
			restored = err == nil
			if err != nil {
				m.Warn().Err(err).Str("session", ls.id).Msg("ACP session/resume failed, starting fresh")
			}
		} else if caps.LoadSession {
			ls.mu.Lock()
			ls.restoring = true
			ls.mu.Unlock()
			_, err := conn.LoadSession(restoreCtx, acp.LoadSessionRequest{
				Cwd: acpCwd, SessionId: acpSessionId, McpServers: []acp.McpServer{}})
			ls.mu.Lock()
			ls.restoring = false
			ls.mu.Unlock()
			restored = err == nil
			if err != nil {
				m.Warn().Err(err).Str("session", ls.id).Msg("ACP session/load failed, starting fresh")
			}
		}
		restoreCancel()
		if restored {
			m.appendActivity(ls.id, ls.userID, "lifecycle", "conversation restored", nil)
		} else {
			m.appendActivity(ls.id, ls.userID, "lifecycle",
				"previous conversation could not be restored; the agent starts fresh (the transcript above is unaffected)", nil)
		}
	}

	if !restored {
		newSession, err := m.newSessionWithAuth(context.Background(), conn, sb, acpCwd, session.Agent,
			initResp.AuthMethods, func(msg string) {
				m.appendActivity(ls.id, ls.userID, "lifecycle", msg, nil)
				ls.emit(Event{Kind: "status", Status: msg})
			})
		if err != nil {
			sb.stop()
			return err
		}
		// Fresh timeout: handshakeCtx may be near expiry when an interactive
		// authentication flow ran before the session was created
		configCtx, configCancel := context.WithTimeout(context.Background(), handshakeTimeout)
		defer configCancel()
		for _, warning := range applySessionConfig(configCtx, conn, newSession.SessionId,
			newSession.ConfigOptions, agentConfig.Model, agentConfig.Effort) {
			m.Warn().Str("session", ls.id).Msg(warning)
			m.appendActivity(ls.id, ls.userID, "lifecycle", warning, nil)
		}
		acpSessionId = newSession.SessionId
		// Persist the agent-side session id so the conversation can be
		// restored on the next resume
		if string(acpSessionId) != session.AcpSessionId {
			session.AcpSessionId = string(acpSessionId)
			if err := m.updateSession(context.Background(), session); err != nil {
				m.Warn().Err(err).Str("session", ls.id).Msg("Error persisting ACP session id")
			}
		}
	}

	ls.mu.Lock()
	ls.sandbox = sb
	ls.conn = conn
	ls.acpSessionId = acpSessionId
	ls.lastActive = time.Now()
	ls.mu.Unlock()

	// If the sandbox dies unexpectedly, detach the session
	go func() {
		<-sb.exited
		ls.mu.Lock()
		current := ls.sandbox
		ls.mu.Unlock()
		if current == sb {
			m.Warn().Str("session", ls.id).Msg("Builder sandbox exited unexpectedly")
			m.appendActivity(ls.id, ls.userID, "error", "sandbox exited: "+tailBytes([]byte(sb.stderr()), 1000), nil)
			m.stopLive(ls, types.BuilderSessionDetached)
		}
	}()

	m.setStatus(ls, types.BuilderSessionReady)
	return nil
}

// SendMessage starts a prompt turn with the user's message
func (m *Manager) SendMessage(ctx context.Context, id, userID, text string) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("message is empty")
	}
	ls, err := m.requireLive(id)
	if err != nil {
		return err
	}
	ls.mu.Lock()
	if ls.conn == nil {
		ls.mu.Unlock()
		return fmt.Errorf("session %s is still starting", id)
	}
	if ls.turnActive {
		ls.mu.Unlock()
		return fmt.Errorf("the agent is still working, wait for the turn to finish")
	}
	// Claim the turn before releasing the lock: two concurrent sends would
	// otherwise both pass the check and one message would be persisted to
	// the transcript but silently never sent to the agent
	ls.turnActive = true
	ls.mu.Unlock()

	m.appendActivity(id, userID, "prompt", text, nil)
	go m.runTurn(ls, text, true)
	return nil
}

// runTurn sends one prompt and blocks until the turn completes, persisting
// the accumulated agent message. claimed means the caller already set
// turnActive under the lock (SendMessage), so the guard here must not
// treat that claim as a concurrent turn
func (m *Manager) runTurn(ls *liveSession, text string, claimed bool) {
	ls.mu.Lock()
	if !claimed && ls.turnActive {
		ls.mu.Unlock()
		return
	}
	if ls.conn == nil {
		ls.turnActive = false
		ls.mu.Unlock()
		return
	}
	turnCtx, cancel := context.WithTimeout(context.Background(), turnTimeout)
	ls.turnActive = true
	ls.turnCancel = cancel
	ls.turnCancelled = false
	ls.approvals = 0
	ls.msgBuf.Reset()
	ls.chunkBreak = false
	ls.lastActive = time.Now()
	conn := ls.conn
	acpSessionId := ls.acpSessionId
	ls.mu.Unlock()
	defer cancel()

	m.setStatus(ls, types.BuilderSessionRunning)
	ls.emit(Event{Kind: "turn_started"})

	response, err := conn.Prompt(turnCtx, acp.PromptRequest{
		SessionId: acpSessionId,
		Prompt:    []acp.ContentBlock{acp.TextBlock(text)},
	})

	timedOut := err != nil && errors.Is(turnCtx.Err(), context.DeadlineExceeded)
	if timedOut {
		// The client stopped waiting but the agent does not know: per the
		// protocol the turn is ended with session/cancel, so a still-running
		// agent does not keep working (and burning tokens) unattended. A
		// stopped session (context cancelled) needs no cancel: the sandbox
		// is being torn down. The cancel is sent BEFORE the turn claim is
		// released below - session/cancel is session-scoped, so a new turn
		// claimed in between would be the one cancelled
		ls.mu.Lock()
		ls.turnCancelled = true
		ls.mu.Unlock()
		if cancelErr := conn.Cancel(context.Background(), acp.CancelNotification{SessionId: acpSessionId}); cancelErr != nil {
			m.Warn().Err(cancelErr).Str("session", ls.id).Msg("Error cancelling timed-out builder turn")
		}
	}

	ls.mu.Lock()
	ls.turnActive = false
	ls.turnCancel = nil
	ls.lastActive = time.Now()
	message := ls.msgBuf.String()
	ls.msgBuf.Reset()
	ls.mu.Unlock()

	if err != nil {
		errText := err.Error()
		if timedOut {
			errText = fmt.Sprintf("turn timed out after %v, the agent was cancelled", turnTimeout)
		}
		m.Warn().Err(err).Str("session", ls.id).Msg("Builder prompt turn failed")
		m.appendActivity(ls.id, ls.userID, "error", "turn failed: "+errText, nil)
		ls.emit(Event{Kind: "error", Text: "The agent turn failed: " + errText})
		m.setStatus(ls, types.BuilderSessionReady)
		return
	}

	metadata := map[string]any{"stop_reason": string(response.StopReason)}
	if response.Usage != nil {
		metadata["input_tokens"] = response.Usage.InputTokens
		metadata["output_tokens"] = response.Usage.OutputTokens
	}
	if message = strings.TrimSpace(message); message != "" {
		m.appendActivity(ls.id, ls.userID, "agent_message", message, metadata)
	}
	m.setStatus(ls, types.BuilderSessionReady)
	ls.emit(Event{Kind: "turn_done", StopReason: string(response.StopReason)})

	if m.OnTurnDone != nil {
		go m.OnTurnDone(ls.id)
	}
}

// CancelTurn sends the ACP cancel notification for the in-flight turn
func (m *Manager) CancelTurn(id string) error {
	ls, err := m.requireLive(id)
	if err != nil {
		return err
	}
	return m.cancelTurn(ls)
}

func (m *Manager) cancelTurn(ls *liveSession) error {
	ls.mu.Lock()
	conn := ls.conn
	acpSessionId := ls.acpSessionId
	active := ls.turnActive
	if conn != nil && active {
		// From here on, pending and new permission requests for this turn
		// must resolve with the cancelled outcome, not auto-approval
		ls.turnCancelled = true
	}
	ls.mu.Unlock()
	if conn == nil {
		if active {
			// the first turn is claimed while the sandbox launches; there
			// is no agent to cancel yet
			return fmt.Errorf("the session is still starting, stop the session to abort")
		}
		return fmt.Errorf("no agent turn is running")
	}
	if !active {
		return fmt.Errorf("no agent turn is running")
	}
	return conn.Cancel(context.Background(), acp.CancelNotification{SessionId: acpSessionId})
}

// StopSession stops the sandbox; the workspace and preview app remain
func (m *Manager) StopSession(id, userID string) error {
	ls, err := m.requireLive(id)
	if err != nil {
		return err
	}
	m.appendActivity(id, userID, "lifecycle", "sandbox stopped", nil)
	m.stopLive(ls, types.BuilderSessionDetached)
	return nil
}

// ResumeSession relaunches the sandbox for a detached session. The agent
// conversation starts fresh over the same sources; the transcript history
// stays in the activity log
func (m *Manager) ResumeSession(ctx context.Context, id, userID string) error {
	config := m.config()
	if !config.AppBuilder.Enabled {
		return fmt.Errorf("app_builder is not enabled")
	}
	session, err := m.db.GetBuilderSession(ctx, types.Transaction{}, id)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if _, exists := m.live[id]; exists {
		m.mu.Unlock()
		return fmt.Errorf("session %s is already live", id)
	}
	if maxSessions := config.AppBuilder.MaxSessions; maxSessions > 0 && len(m.live) >= maxSessions {
		m.mu.Unlock()
		return fmt.Errorf("max concurrent builder sessions (%d) reached, stop an idle session first", maxSessions)
	}
	ls := newLiveSession(id, session.UserID)
	m.live[id] = ls
	m.mu.Unlock()

	m.appendActivity(id, userID, "lifecycle", "session resumed", nil)
	go func() {
		if err := m.launch(ls); err != nil {
			m.failSession(ls, fmt.Errorf("resuming sandbox: %w", err))
		}
	}()
	return nil
}

// DeleteSession stops the sandbox and removes the workspace and session row.
// Activity rows are retained; the caller (server) removes the preview app
func (m *Manager) DeleteSession(ctx context.Context, id, userID string) error {
	m.mu.Lock()
	ls := m.live[id]
	m.mu.Unlock()
	if ls != nil {
		m.stopLive(ls, types.BuilderSessionDetached)
	}

	session, err := m.db.GetBuilderSession(ctx, types.Transaction{}, id)
	if err != nil {
		return err
	}
	// Only remove directories we created (guards against a manually edited row)
	if session.WorkspaceDir != "" && strings.HasPrefix(session.WorkspaceDir, m.workspaceRoot()) {
		if err := os.RemoveAll(session.WorkspaceDir); err != nil {
			m.Warn().Err(err).Str("session", id).Msg("Error removing builder workspace")
		}
	}
	// The agent state volume (conversation state) dies with the session
	if !m.hostMode() {
		if cli, err := m.containerCLI(); err == nil {
			if err := RemoveStateVolume(ctx, cli, id); err != nil {
				m.Warn().Err(err).Str("session", id).Msg("Error removing agent state volume")
			}
		}
	}

	tx, err := m.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := m.db.DeleteBuilderSession(ctx, tx, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.appendActivity(id, userID, "lifecycle", "session deleted", nil)
	return nil
}

// Subscribe returns the event stream for a session (live sessions only)
func (m *Manager) Subscribe(id string) (<-chan Event, func(), error) {
	ls, err := m.requireLive(id)
	if err != nil {
		return nil, nil, err
	}
	ch, cancel := ls.subscribe()
	return ch, cancel, nil
}

// LiveState returns the in-flight turn state for a session: whether a turn
// is running and the partial agent message accumulated so far
func (m *Manager) LiveState(id string) (isLive, turnActive bool, partial string) {
	m.mu.Lock()
	ls := m.live[id]
	m.mu.Unlock()
	if ls == nil {
		return false, false, ""
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return true, ls.turnActive, ls.msgBuf.String()
}

// ListFiles returns the workspace file tree (relative paths), skipping VCS
// and dependency directories
func (m *Manager) ListFiles(ctx context.Context, id string) ([]string, error) {
	session, err := m.db.GetBuilderSession(ctx, types.Transaction{}, id)
	if err != nil {
		return nil, err
	}
	var files []string
	err = filepath.WalkDir(session.WorkspaceDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if name == ".git" || name == "node_modules" || name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			// symlinks etc are not listed (and ReadFile rejects them): the
			// agent controls the workspace, a link may point at host files
			return nil
		}
		rel, err := filepath.Rel(session.WorkspaceDir, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// ReadFile returns one workspace file, path-jailed to the workspace
func (m *Manager) ReadFile(ctx context.Context, id, relPath string) (string, error) {
	session, err := m.db.GetBuilderSession(ctx, types.Transaction{}, id)
	if err != nil {
		return "", err
	}
	return readWorkspaceFile(session.WorkspaceDir, relPath)
}

// readWorkspaceFile reads relPath under workspaceDir. The agent controls the
// workspace content, so this is the console's sandbox boundary: the path is
// jailed to the workspace, symlinks are resolved and must not escape it (a
// link to /proc/self/environ or a host config file must not be readable),
// and only regular files are served
func readWorkspaceFile(workspaceDir, relPath string) (string, error) {
	full := filepath.Join(workspaceDir, filepath.Clean("/"+relPath))
	if !strings.HasPrefix(full, workspaceDir+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid file path %q", relPath)
	}
	// The workspace root itself may sit behind a symlink (macOS /tmp), so
	// compare fully resolved paths on both sides
	resolvedRoot, err := filepath.EvalSymlinks(workspaceDir)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(resolved, resolvedRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("file %s resolves outside the workspace", relPath)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("file %s is not a regular file", relPath)
	}
	if info.Size() > maxReadFileBytes {
		return "", fmt.Errorf("file %s is too large to view (%d bytes)", relPath, info.Size())
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetSession returns one session row
func (m *Manager) GetSession(ctx context.Context, id string) (*types.BuilderSession, error) {
	return m.db.GetBuilderSession(ctx, types.Transaction{}, id)
}

// ListSessions returns session rows, optionally filtered by user
func (m *Manager) ListSessions(ctx context.Context, userID string) ([]*types.BuilderSession, error) {
	return m.db.ListBuilderSessions(ctx, userID)
}

// ListActivity returns activity rows for a session
func (m *Manager) ListActivity(ctx context.Context, sessionId, afterId string, limit int) ([]*types.BuilderActivity, error) {
	return m.db.ListBuilderActivity(ctx, sessionId, afterId, limit)
}

func (m *Manager) requireLive(id string) (*liveSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ls, ok := m.live[id]
	if !ok {
		return nil, fmt.Errorf("session %s has no running sandbox (resume it first)", id)
	}
	return ls, nil
}

// stopLive stops the sandbox, removes the session from the live map and
// persists the final status
func (m *Manager) stopLive(ls *liveSession, status types.BuilderSessionStatus) {
	ls.mu.Lock()
	sb := ls.sandbox
	ls.sandbox = nil
	ls.conn = nil
	if ls.turnCancel != nil {
		ls.turnCancel()
		ls.turnCancel = nil
	}
	ls.turnActive = false
	ls.mu.Unlock()

	if sb != nil {
		sb.stop()
	}

	m.mu.Lock()
	delete(m.live, ls.id)
	m.mu.Unlock()

	m.setStatus(ls, status)
	ls.emit(Event{Kind: "status", Status: string(status)})
	ls.closeSubscribers()
}

func (m *Manager) failSession(ls *liveSession, failure error) {
	m.Error().Err(failure).Str("session", ls.id).Msg("Builder session failed")
	m.appendActivity(ls.id, ls.userID, "error", failure.Error(), nil)
	ls.emit(Event{Kind: "error", Text: failure.Error()})
	m.stopLive(ls, types.BuilderSessionError)
}

// setStatus persists the session status, preserving published: once a
// session is published, ready/detached transitions keep that state visible
func (m *Manager) setStatus(ls *liveSession, status types.BuilderSessionStatus) {
	ctx := context.Background()
	session, err := m.db.GetBuilderSession(ctx, types.Transaction{}, ls.id)
	if err != nil {
		return // session deleted
	}
	if session.Status == types.BuilderSessionPublished &&
		(status == types.BuilderSessionReady || status == types.BuilderSessionDetached) {
		return
	}
	session.Status = status
	if err := m.updateSession(ctx, session); err != nil {
		m.Warn().Err(err).Str("session", ls.id).Msg("Error updating session status")
		return
	}
	ls.emit(Event{Kind: "status", Status: string(status)})
}

func (m *Manager) updateSession(ctx context.Context, session *types.BuilderSession) error {
	tx, err := m.db.BeginTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := m.db.UpdateBuilderSession(ctx, tx, session); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateSessionInfo persists caller changes (preview/publish path, status)
func (m *Manager) UpdateSessionInfo(ctx context.Context, session *types.BuilderSession) error {
	return m.updateSession(ctx, session)
}

// LogActivity writes one activity row on behalf of the server (preview and
// publish events)
func (m *Manager) LogActivity(sessionId, userID, kind, content string, metadata map[string]any) {
	m.appendActivity(sessionId, userID, kind, content, metadata)
}

// VerifyProfile runs the sandbox checks for one agent profile: profile and
// config_files validation, secret resolution, image build and the ACP
// handshake in a throwaway container. With testPrompt, one real prompt
// round-trips through the model ("reply with OK") to prove credentials work
func (m *Manager) VerifyProfile(ctx context.Context, name string, testPrompt bool) error {
	agentConfig, ok := m.config().BuilderAgent[name]
	if !ok {
		return fmt.Errorf("no [builder_agent.%s] config entry", name)
	}
	p, err := resolveProfile(name, agentConfig, os.ReadFile)
	if err != nil {
		return err
	}
	if !m.hostMode() { // host-mode agents read their host config, mounts are ignored
		for _, mount := range p.configs {
			if _, err := os.Stat(mount.host); err != nil {
				return fmt.Errorf("config file %s: %w", mount.host, err)
			}
		}
	}
	env := map[string]string{}
	for key, value := range p.env {
		resolved, err := m.evalSecret(value)
		if err != nil {
			return fmt.Errorf("resolving env %s: %w", key, err)
		}
		env[key] = resolved
	}

	workspace, err := os.MkdirTemp("", "openrun-builder-verify")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workspace) //nolint:errcheck

	acpCwd := "/workspace"
	var sb *sandbox
	if m.hostMode() {
		sb, err = startHostAgent(workspace, p, env)
		if err != nil {
			return err
		}
		acpCwd = workspace
	} else {
		cli, err := m.containerCLI()
		if err != nil {
			return err
		}
		image, err := buildImage(ctx, cli, p)
		if err != nil {
			return err
		}
		sb, err = startSandbox(cli, image, "bld_ses_verify_"+p.name, workspace, p, env)
		if err != nil {
			return err
		}
	}
	defer sb.stop()

	ls := newLiveSession("verify", "verify")
	conn := acp.NewClientSideConnection(&driverClient{manager: m, session: ls}, sb.stdin, sb.stdout)
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	initResp, err := conn.Initialize(handshakeCtx, acp.InitializeRequest{
		ProtocolVersion:    acp.ProtocolVersionNumber,
		ClientInfo:         &acp.Implementation{Name: "openrun", Title: acp.Ptr("OpenRun App Builder"), Version: "1.0"},
		ClientCapabilities: acp.ClientCapabilities{Auth: acp.AuthCapabilities{Terminal: false}},
	})
	if err != nil {
		return fmt.Errorf("ACP initialize failed: %w (agent stderr: %s)", err, sb.stderr())
	}
	if initResp.ProtocolVersion != acp.ProtocolVersionNumber {
		return fmt.Errorf("agent %s uses unsupported ACP protocol version %v (supported: %v)",
			name, initResp.ProtocolVersion, acp.ProtocolVersionNumber)
	}
	newSession, err := m.newSessionWithAuth(ctx, conn, sb, acpCwd, name, initResp.AuthMethods,
		func(msg string) { m.Info().Str("agent", name).Msg(msg) })
	if err != nil {
		return err
	}

	if testPrompt {
		promptCtx, promptCancel := context.WithTimeout(ctx, 5*time.Minute)
		defer promptCancel()
		if _, err := conn.Prompt(promptCtx, acp.PromptRequest{
			SessionId: newSession.SessionId,
			Prompt:    []acp.ContentBlock{acp.TextBlock("Reply with exactly: OK. Do not use any tools.")},
		}); err != nil {
			return fmt.Errorf("test prompt failed: %w (agent stderr: %s)", err, sb.stderr())
		}
	}
	return nil
}

// appendActivity writes one activity row; failures are logged, not fatal
// (activity is the durable transcript, but must not break the session)
func (m *Manager) appendActivity(sessionId, userID, kind, content string, metadata map[string]any) {
	ctx := context.Background()
	genId, err := ksuid.NewRandom()
	if err != nil {
		m.Warn().Err(err).Msg("Error generating activity id")
		return
	}
	activity := &types.BuilderActivity{
		Id:        types.ID_PREFIX_BUILDER_ACT + strings.ToLower(genId.String()),
		SessionId: sessionId,
		UserID:    userID,
		Kind:      kind,
		Content:   content,
		Metadata:  metadata,
	}
	tx, err := m.db.BeginTransaction(ctx)
	if err != nil {
		m.Warn().Err(err).Msg("Error starting activity transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck
	if err := m.db.CreateBuilderActivity(ctx, tx, activity); err != nil {
		m.Warn().Err(err).Msg("Error writing builder activity")
		return
	}
	if err := tx.Commit(); err != nil {
		m.Warn().Err(err).Msg("Error committing builder activity")
	}
}
