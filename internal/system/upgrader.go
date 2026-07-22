// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/tableflip"
	"github.com/openrundev/openrun/internal/types"
)

// ErrInPlaceRestartUnavailable is returned by Upgrader.Upgrade when a zero
// downtime in-place restart cannot be performed in this environment. The
// wrapped message says why and what to do instead.
var ErrInPlaceRestartUnavailable = errors.New("in-place restart unavailable")

// Upgrader wraps tableflip to provide zero downtime in-place restarts: the
// running process re-execs its binary, passes the listener fds to the child
// and drains once the child reports ready. tableflip allows a single Upgrader
// per process, so an Upgrader is only created for the `server start` command
// path (config.EnableInPlaceRestart); embedded and test servers fall back to
// plain listeners. The fallback is also used where a handoff cannot work:
// Windows (fds cannot be turned back into listeners) and containers (the
// parent exiting after handoff terminates the container, killing the child)
type Upgrader struct {
	logger *types.Logger
	tf     *tableflip.Upgrader
	reason string // why in-place restart is unavailable, when tf is nil
	// parentExited is closed once the previous process of an in-place
	// restart handoff has exited (immediately when there is no parent),
	// giving ParentExited a deterministic non-blocking probe
	parentExited chan struct{}
}

// NewUpgrader creates the process Upgrader. It never fails: when in-place
// restarts are not possible the Upgrader runs in fallback mode where Listen
// binds plain listeners and Upgrade returns ErrInPlaceRestartUnavailable
func NewUpgrader(logger *types.Logger, config *types.ServerConfig) *Upgrader {
	u := &Upgrader{logger: logger}

	if !config.EnableInPlaceRestart {
		u.reason = "in-place restart is not enabled for this server instance"
		return u
	}
	if reason := containerRestartAdvice(); reason != "" {
		u.reason = reason
		return u
	}

	// tableflip re-execs os.Args[0], resolved with exec.LookPath in the
	// parent's working directory. The server chdirs to OPENRUN_HOME after
	// this point, so a relative invocation path (./openrun) would resolve
	// wrongly at upgrade time. Pin argv[0] to an absolute path now
	if exe, err := invocationPath(); err == nil {
		os.Args[0] = exe
	}

	pidDir := path.Join(os.ExpandEnv("$OPENRUN_HOME"), "run")
	if err := os.MkdirAll(pidDir, 0700); err != nil {
		u.reason = fmt.Sprintf("error creating pid file directory %s: %s", pidDir, err)
		logger.Warn().Str("reason", u.reason).Msg("In-place restart disabled")
		return u
	}

	upgradeTimeout := time.Duration(config.Restart.UpgradeTimeoutSecs) * time.Second
	tf, err := tableflip.New(tableflip.Options{
		PIDFile:        path.Join(pidDir, "openrun.pid"),
		UpgradeTimeout: upgradeTimeout,
	})
	if err != nil {
		// tableflip returns ErrNotSupported on Windows
		u.reason = fmt.Sprintf("in-place restart is not supported on this platform: %s", err)
		logger.Info().Str("reason", u.reason).Msg("In-place restart disabled")
		return u
	}
	u.tf = tf
	u.parentExited = make(chan struct{})
	if tf.HasParent() {
		logger.Info().Msg("Started as in-place restart child, waiting to inherit listeners")
		go func() {
			_ = tf.WaitForParent(context.Background())
			close(u.parentExited)
		}()
	} else {
		close(u.parentExited)
	}
	return u
}

// invocationPath returns the absolute path this process was invoked as,
// deliberately NOT resolving the final symlink (unlike os.Executable, which
// reads /proc/self/exe): when openrun is installed behind a stable symlink
// that a package update repoints to a new versioned binary, an in-place
// restart must re-exec through the symlink to pick up the update, not the
// target captured at startup (which the update may have removed). Must be
// called before the server chdirs away from the invocation directory
func invocationPath() (string, error) {
	exe := os.Args[0]
	if !strings.ContainsRune(exe, os.PathSeparator) {
		// Bare command name: resolve through PATH, the way the shell did.
		// LookPath returns the symlink itself, not its target
		looked, err := exec.LookPath(exe)
		if err != nil {
			return os.Executable()
		}
		exe = looked
	}
	if !filepath.IsAbs(exe) {
		abs, err := filepath.Abs(exe)
		if err != nil {
			return os.Executable()
		}
		exe = abs
	}
	return exe, nil
}

// containerRestartAdvice returns a non-empty reason when the process is
// running inside a container, where an in-place handoff would terminate the
// container (the parent is pid 1) and kill the upgraded child with it.
// OPENRUN_IN_CONTAINER overrides auto-detection in both directions
func containerRestartAdvice() string {
	advice := "running inside a container; restart the container instead (kubectl rollout restart / docker restart)"
	if env := os.Getenv("OPENRUN_IN_CONTAINER"); env != "" {
		if inContainer, err := strconv.ParseBool(env); err == nil {
			if inContainer {
				return advice
			}
			return ""
		}
		return advice // set to a non-boolean value, treat as in-container
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return advice
	}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return advice
		}
	}
	return ""
}

// Listen returns a listener for the address, inheriting it from the previous
// process during an in-place restart when possible. bind is used to create a
// fresh listener when there is nothing to inherit; it also runs in fallback
// mode, so address-specific recovery logic (like the UDS stale socket probe)
// applies on every path
func (u *Upgrader) Listen(network, addr string, bind func(network, addr string) (net.Listener, error)) (net.Listener, error) {
	if u.tf == nil {
		return bind(network, addr)
	}
	return u.tf.ListenWithCallback(network, addr, bind)
}

// Ready signals the previous process (if any) that this process has bound its
// listeners and can serve traffic, allowing the old process to drain. It also
// writes the pid file. Must be called once startup is complete
func (u *Upgrader) Ready() error {
	if u.tf == nil {
		return nil
	}
	return u.tf.Ready()
}

// Upgrade starts an in-place restart: it re-execs the current binary and
// blocks until the child process reports ready (at which point Exit() fires)
// or the child fails, in which case the current process continues serving
func (u *Upgrader) Upgrade() error {
	if u.tf == nil {
		return fmt.Errorf("%w: %s", ErrInPlaceRestartUnavailable, u.reason)
	}
	return u.tf.Upgrade()
}

// Exit returns a channel that is closed when an upgrade has succeeded and
// the process must drain and exit. Returns nil in fallback mode (a nil
// channel never fires in a select)
func (u *Upgrader) Exit() <-chan struct{} {
	if u.tf == nil {
		return nil
	}
	return u.tf.Exit()
}

// Stop releases upgrade resources on shutdown. In-flight upgrades are
// aborted
func (u *Upgrader) Stop() {
	if u.tf != nil {
		u.tf.Stop()
	}
}

// Supported reports whether an in-place restart can be attempted
func (u *Upgrader) Supported() bool {
	return u.tf != nil
}

// HasParent reports whether this process was started as the child of an
// in-place restart handoff, meaning the previous process is still running
// (draining) until it exits
func (u *Upgrader) HasParent() bool {
	return u.tf != nil && u.tf.HasParent()
}

// WaitForParent blocks until the previous process of an in-place restart
// handoff has exited, or the context expires. Returns immediately when there
// is no parent
func (u *Upgrader) WaitForParent(ctx context.Context) error {
	if u.tf == nil {
		return nil
	}
	select {
	case <-u.parentExited:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ParentExited reports whether the previous process of an in-place restart
// handoff has exited. True when there was no handoff. Once true, stays true
func (u *Upgrader) ParentExited() bool {
	if u.tf == nil {
		return true
	}
	select {
	case <-u.parentExited:
		return true
	default:
		return false
	}
}
