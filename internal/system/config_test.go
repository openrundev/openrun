// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func TestServerConfig(t *testing.T) {
	c, err := NewServerConfigEmbedded()
	if err != nil {
		t.Fatalf("failed to load embedded config: %v", err)
	}

	// The default value are read from the embedded openrun.default.toml file,
	// verify if the expected values are read correctly

	// HTTP listen related settings
	testutil.AssertEqualsString(t, "http host", "127.0.0.1", c.Http.Host)
	testutil.AssertEqualsInt(t, "http port", 25222, c.Http.Port)

	// Logging related settings
	testutil.AssertEqualsString(t, "log level", "INFO", c.Log.Level)
	testutil.AssertEqualsBool(t, "console logging", false, c.Log.Console)
	testutil.AssertEqualsBool(t, "file logging", true, c.Log.File)
	testutil.AssertEqualsInt(t, "max backups", 10, c.Log.MaxBackups)
	testutil.AssertEqualsInt(t, "max size MB", 50, c.Log.MaxSizeMB)

	// Metadata related settings
	testutil.AssertEqualsString(t, "db connection", "sqlite:$OPENRUN_HOME/metadata/clace_metadata.db", c.Metadata.DBConnection)
	testutil.AssertEqualsBool(t, "auto upgrade", true, c.Metadata.AutoUpgrade)

	// HTTPS listen related settings
	testutil.AssertEqualsString(t, "https host", "0.0.0.0", c.Https.Host)
	testutil.AssertEqualsInt(t, "https port", 25223, c.Https.Port)
	testutil.AssertEqualsBool(t, "https cert lookup", true, c.Https.EnableCertLookup)
	testutil.AssertEqualsString(t, "email", "", c.Https.ServiceEmail)
	testutil.AssertEqualsBool(t, "https staging", true, c.Https.UseStaging)
	testutil.AssertEqualsString(t, "storage", "$OPENRUN_HOME/run/certmagic", c.Https.StorageLocation)
	testutil.AssertEqualsString(t, "cache", "$OPENRUN_HOME/config/certificates", c.Https.CertLocation)

	// System settings
	testutil.AssertEqualsString(t, "tailwind command", "tailwindcss", c.System.TailwindCSSCommand)
	testutil.AssertEqualsInt(t, "file debounce", 300, c.System.FileWatcherDebounceMillis)
	testutil.AssertEqualsString(t, "node path", "", c.System.NodePath)
	testutil.AssertEqualsString(t, "default domain", "localhost", c.System.DefaultDomain)
	testutil.AssertEqualsInt(t, "max concurrent builds", 1, c.System.MaxConcurrentBuilds)
	testutil.AssertEqualsInt(t, "max build wait secs", 120, c.System.MaxBuildWaitSecs)

	// Global Settings
	testutil.AssertEqualsString(t, "server uri", "$OPENRUN_HOME/run/openrun.sock", c.ServerUri)
	testutil.AssertEqualsString(t, "admin user", "admin", c.AdminUser)

	// Security Settings
	testutil.AssertEqualsBool(t, "admin tcp", false, c.Security.AdminOverTCP)
	testutil.AssertEqualsString(t, "admin password bcrypt", "", c.Security.AdminPasswordBcrypt)

	// Container Settings
	testutil.AssertEqualsString(t, "command", "auto", c.System.ContainerCommand)

	// App CORS default Settings
	testutil.AssertEqualsString(t, "cors origin", "*", c.AppConfig.CORS.AllowOrigin)
	testutil.AssertEqualsString(t, "cors headers", "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization,X-Requested-With", c.AppConfig.CORS.AllowHeaders)
	testutil.AssertEqualsString(t, "cors methods", "*", c.AppConfig.CORS.AllowMethods)
	testutil.AssertEqualsString(t, "cors methods", "true", c.AppConfig.CORS.AllowCredentials)
	testutil.AssertEqualsString(t, "cors methods", "2678400", c.AppConfig.CORS.MaxAge)

	// Container Settings
	testutil.AssertEqualsString(t, "health", "/", c.AppConfig.Container.HealthUrl)
	testutil.AssertEqualsInt(t, "attempts", 10, c.AppConfig.Container.HealthAttemptsAfterStartup)
	testutil.AssertEqualsInt(t, "timeout", 5, c.AppConfig.Container.HealthTimeoutSecs)
	testutil.AssertEqualsInt(t, "idle", 180, c.AppConfig.Container.IdleShutdownSecs)
	testutil.AssertEqualsInt(t, "idle bytes high watermark", 1500, c.AppConfig.Container.IdleBytesHighWatermark)
	testutil.AssertEqualsInt(t, "status interval", 20, c.AppConfig.Container.StatusCheckIntervalSecs)
	testutil.AssertEqualsInt(t, "status attempts", 10, c.AppConfig.Container.StatusHealthAttempts)

	testutil.AssertEqualsInt(t, "proxy max idle", 250, c.AppConfig.Proxy.MaxIdleConns)
	testutil.AssertEqualsInt(t, "proxy idle timeout", 15, c.AppConfig.Proxy.IdleConnTimeoutSecs)
	testutil.AssertEqualsBool(t, "proxy disable compression", true, c.AppConfig.Proxy.DisableCompression)
	testutil.AssertEqualsString(t, "secrets provider", "env", c.AppConfig.Security.DefaultSecretsProvider)

	testutil.AssertEqualsString(t, "kubernetes namespace", "openrun", c.Kubernetes.Namespace)
	testutil.AssertEqualsString(t, "builder mode", "auto", c.Builder.Mode)
	testutil.AssertEqualsString(t, "kaniko image", "ghcr.io/kaniko-build/dist/chainguard-dev-kaniko/executor:v1.25.3-slim", c.Builder.KanikoImage)
}

func TestClientConfig(t *testing.T) {
	c, err := NewClientConfigEmbedded()
	if err != nil {
		t.Fatalf("failed to load embedded config: %v", err)
	}
	testutil.AssertEqualsBool(t, "cert check", false, c.Client.SkipCertCheck)
	testutil.AssertEqualsString(t, "admin password", "", c.Client.AdminPassword)
	testutil.AssertEqualsString(t, "server uri", "$OPENRUN_HOME/run/openrun.sock", c.ServerUri)
	testutil.AssertEqualsString(t, "admin user", "admin", c.AdminUser)
	testutil.AssertEqualsString(t, "default format", "basic", c.Client.DefaultFormat)
}
