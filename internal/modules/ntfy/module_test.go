// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Abysslink Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ntfy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/platform"
	"github.com/abysslink/abysslink/internal/secrets"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubKeychain is a minimal in-memory secrets.KeychainStore for unit tests.
// applyDocker → ensureAdminUserDocker requires a non-nil keychain; this stub
// lets the apply path run to completion without touching a real keychain.
type stubKeychain struct{ pw string }

func (s *stubKeychain) Set(_ context.Context, _, _, secret string) error {
	s.pw = secret
	return nil
}
func (s *stubKeychain) Get(_ context.Context, _, _ string) (string, error) {
	return s.pw, nil
}
func (s *stubKeychain) Delete(_ context.Context, _, _ string) error { return nil }

// testPlatform is a minimal platform.Platform for unit tests.
type testPlatform struct{}

func (p *testPlatform) OS() string                              { return "linux" }
func (p *testPlatform) Distro() platform.Distro                 { return platform.DistroUnknown }
func (p *testPlatform) PackageManager() platform.PackageManager { return platform.PkgApt }
func (p *testPlatform) InstallPackage(_ context.Context, _ string) error {
	return nil
}
func (p *testPlatform) RemovePackage(_ context.Context, _ string) error { return nil }
func (p *testPlatform) ServiceInstall(_ context.Context, _ platform.ServiceSpec) error {
	return nil
}
func (p *testPlatform) ServiceUninstall(_ context.Context, _ string) error { return nil }
func (p *testPlatform) ServiceStart(_ context.Context, _ string) error     { return nil }
func (p *testPlatform) ServiceStop(_ context.Context, _ string) error      { return nil }
func (p *testPlatform) ServiceStatus(_ context.Context, _ string) (platform.ServiceStatus, error) {
	return platform.ServiceUnknown, nil
}
func (p *testPlatform) DiskEncryptionStatus(_ context.Context) (platform.DiskState, error) {
	return platform.DiskUnknown, nil
}
func (p *testPlatform) Firewall() platform.FirewallController                       { return nil }
func (p *testPlatform) KeepAwake(_ context.Context, _ platform.KeepAwakeMode) error { return nil }

func TestGenerateServerConfig_BindsTailnetIPNotWildcard(t *testing.T) {
	m := New(modules.Deps{Cfg: config.Defaults()})
	out := string(m.generateServerConfig("100.64.1.2", "/home/testuser"))

	assert.Contains(t, out, "listen-http: \"100.64.1.2:2586\"", "must bind to the tailnet IP")
	assert.NotContains(t, out, "0.0.0.0", "must never bind to all interfaces")
	assert.Contains(t, out, "auth-default-access: \"deny-all\"")
}

func TestHasWildcardListen(t *testing.T) {
	assert.True(t, hasWildcardListen(`listen-http: ":2586"`), "bare :port binds to all interfaces")
	assert.False(t, hasWildcardListen(`listen-http: "100.64.1.2:2586"`))
	assert.False(t, hasWildcardListen("no listen line here"))
}

func TestGenerateServerConfig_IsYAMLish(t *testing.T) {
	m := New(modules.Deps{Cfg: config.Defaults()})
	out := string(m.generateServerConfig("100.64.1.2", "/home/testuser"))
	assert.True(t, strings.HasPrefix(out, "# ntfy server config"))
}

func TestListenAddressOK(t *testing.T) {
	// Clean path: config file exists and binds to tailnet IP (not 0.0.0.0) →
	// expect SeverityOK finding with Check=="listen_address".
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Write a valid ntfy server.yml that binds to a tailnet IP, not 0.0.0.0.
	cfgDir := filepath.Join(dir, ".config", "ntfy")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgContent := `listen-http: "100.64.1.2:2586"` + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "server.yml"), []byte(cfgContent), 0o600))

	// Mock runner: ntfyBinaryPresent returns true (binary present, has "serve" command).
	// ntfyDockerRunning → false (docker inspect fails).
	r := shell.NewMockRunner(
		// ntfyBinaryPresent: ntfy --help → includes "serve"
		shell.Call{Result: shell.Result{Stdout: "serve  Start ntfy server\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}})

	findings, err := m.Detect(context.Background())
	require.NoError(t, err)

	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "listen_address" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a finding with Check==\"listen_address\" on clean path, got none")
	}
	assert.Equal(t, modules.SeverityOK, found.Severity, "tailnet-bound listen_address must emit SeverityOK")
}

func TestHasWildcardListenIPv6(t *testing.T) {
	// IPv6 wildcard forms must return true.
	assert.True(t, hasWildcardListen(`listen-http: "[::]:2586"`), "[::]:PORT binds to all IPv6 interfaces")
	assert.True(t, hasWildcardListen(`listen-http: "[::]:80"`), "[::]:80 binds to all IPv6 interfaces")
	assert.True(t, hasWildcardListen(`listen-http: "::"`), "bare :: binds to all IPv6 interfaces")

	// Existing IPv4 cases must still return true (regression).
	assert.True(t, hasWildcardListen(`listen-http: ":2586"`), "bare :port binds to all interfaces")

	// Valid tailnet IP must return false (regression).
	assert.False(t, hasWildcardListen(`listen-http: "100.64.0.1:2586"`), "tailnet IP must not be flagged as wildcard")
}

func TestListenAddressIPv6Wildcard(t *testing.T) {
	// Config with IPv6 wildcard bind ([::]:2586) must produce SeverityFatal,
	// not SeverityOK (WR-04 fix validation).
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfgDir := filepath.Join(dir, ".config", "ntfy")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	cfgContent := `listen-http: "[::]:2586"` + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "server.yml"), []byte(cfgContent), 0o600))

	// Mock runner: ntfyBinaryPresent returns true; docker inspect returns non-zero
	// (not running in Docker mode), so Docker-mode guard does not apply.
	r := shell.NewMockRunner(
		// ntfyBinaryPresent: ntfy --help → includes "serve"
		shell.Call{Result: shell.Result{Stdout: "serve  Start ntfy server\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}})

	findings, err := m.Detect(context.Background())
	require.NoError(t, err)

	var listenFinding *modules.Finding
	for i := range findings {
		if findings[i].Check == "listen_address" {
			listenFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, listenFinding, "expected a finding with Check==\"listen_address\" for IPv6 wildcard config")
	assert.Equal(t, modules.SeverityFatal, listenFinding.Severity,
		"IPv6 wildcard bind [::]:2586 must emit SeverityFatal, not SeverityOK")

	// Also assert no SeverityOK on listen_address: a false-OK would mask the misconfiguration.
	for _, f := range findings {
		if f.Check == "listen_address" {
			assert.NotEqual(t, modules.SeverityOK, f.Severity,
				"no listen_address finding should be SeverityOK when config has IPv6 wildcard")
		}
	}
}

// TestApplyDockerBindsTailnetIPOnly is the NET-01a tailnet-only bind floor for
// the Docker container port publish. The `docker run` argv's `-p` mapping must be
// exactly <tailnetIP>:<port>:80 — never a loopback (127.0.0.1), all-interfaces
// (0.0.0.0 / [::] / ::), or bare-wildcard publish. No prior test inspected the
// `docker run` runner argv; ntfy tests only covered the server-config listen-http
// bind. This closes that gap by asserting on the actual recorded argv.
func TestApplyDockerBindsTailnetIPOnly(t *testing.T) {
	tmpHome := t.TempDir()
	auditLog := filepath.Join(t.TempDir(), "audit.log")

	// Script every runner call applyDocker makes, in order, all exit-0:
	//   1. getTailnetHostname → tailscale status --json (valid JSON with
	//      Self.DNSName — NET-19: the hostname is now parsed structurally,
	//      not by string-matching the first "DNSName" line)
	//   2. docker pull
	//   3. docker rm -f
	//   4. docker run -d ... (the call under test)
	//   5. ensureAdminUserDocker → docker exec -i ... (RunWithStdin)
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: `{"Self":{"DNSName":"rig.example.ts.net."}}`, ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)

	cfg := config.Defaults()
	m := New(modules.Deps{
		Cfg:      cfg,
		Runner:   r,
		Audit:    audit.New(auditLog),
		Platform: &testPlatform{},
		Keychain: &stubKeychain{},
	})

	const tailnetIP = "100.64.1.2"
	err := m.applyDocker(context.Background(), tailnetIP, tmpHome)
	require.NoError(t, err, "applyDocker should run cleanly through the scripted runner")

	// Locate the `docker run` call among the recorded argv.
	var runArgs []string
	for _, c := range r.RecordedCalls() {
		if c.Name == "docker" && len(c.Args) > 0 && c.Args[0] == "run" {
			runArgs = c.Args
			break
		}
	}
	require.NotNil(t, runArgs, "expected a `docker run` call to be recorded")

	// Extract the value following the (single) -p flag.
	var portMapping string
	pFound := false
	for i := 0; i < len(runArgs); i++ {
		if runArgs[i] == "-p" {
			require.Less(t, i+1, len(runArgs), "-p flag must be followed by a value")
			require.False(t, pFound, "docker run must publish exactly one -p mapping")
			portMapping = runArgs[i+1]
			pFound = true
		}
	}
	require.True(t, pFound, "docker run must contain a -p port-publish mapping")

	expectedPort := cfg.Modules.Ntfy.ListenPort()
	expected := fmt.Sprintf("%s:%d:80", tailnetIP, expectedPort)
	assert.Equal(t, expected, portMapping,
		"NET-01a: -p must publish only the tailnet IP, container port 80")

	// Load-bearing negative assertions: no loopback or wildcard host bind.
	for _, forbidden := range []string{"127.0.0.1", "0.0.0.0", "[::]", "::", "localhost"} {
		assert.NotContains(t, portMapping, forbidden,
			"NET-01a: -p mapping must never expose %q", forbidden)
	}
}

func TestVerifyReturnsNil(t *testing.T) {
	// ntfy Verify must return nil (no findings, no error) — Pitfall-4 fix.
	// runner.Doctor calls both Detect and Verify; Verify delegating to Detect
	// would double every listen_address finding. Verify must return nil, nil.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Use a minimal runner with no calls expected — Verify should return
	// immediately without touching the runner.
	r := shell.NewMockRunner()
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}})

	findings, err := m.Verify(context.Background())
	assert.NoError(t, err, "Verify must return nil error")
	assert.Empty(t, findings, "Verify must return nil/empty findings (Pitfall-4: no double-emit)")
}

// errKeychain is a KeychainStore whose Get fails with a non-ErrNotFound error
// (e.g. keychain locked / backend unreachable). Used by the NET-12 tests.
type errKeychain struct{}

func (errKeychain) Set(_ context.Context, _, _, _ string) error { return nil }
func (errKeychain) Get(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("keychain locked")
}
func (errKeychain) Delete(_ context.Context, _, _ string) error { return nil }

// TestEnsureAdminUser_KeychainUnavailableAborts is the NET-12 regression test:
// a keychain Get failure that is NOT secrets.ErrNotFound must abort — never
// generate a fresh password. Generating while user.db still holds the old
// password would desync keychain and server permanently (`ntfy user add` on
// an existing admin is tolerated as "already exists" and changes nothing).
func TestEnsureAdminUser_KeychainUnavailableAborts(t *testing.T) {
	r := shell.NewMockRunner() // NO runner calls may happen
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}, Keychain: errKeychain{}})

	err := m.ensureAdminUser(context.Background(), "/home/u/.config/ntfy/server.yml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keychain unavailable",
		"a non-NotFound keychain error must abort with a clear message")
	assert.True(t, r.Done(), "no ntfy commands may run when the keychain state is unknown")

	// Same gate on the Docker path.
	err = m.ensureAdminUserDocker(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keychain unavailable")
	assert.True(t, r.Done())
}

// TestEnsureAdminUser_NotFoundGenerates asserts the legitimate first-run path:
// a definitive secrets.ErrNotFound miss generates a password, stores it in the
// keychain, and provisions the admin user.
func TestEnsureAdminUser_NotFoundGenerates(t *testing.T) {
	kc := secrets.NewMockStore() // empty store: Get wraps secrets.ErrNotFound
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 0}}, // ntfy user add succeeds
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}, Keychain: kc})

	const cfgPath = "/home/u/.config/ntfy/server.yml"
	require.NoError(t, m.ensureAdminUser(context.Background(), cfgPath))
	require.True(t, r.Done())

	pw, err := kc.Get(context.Background(), keychainService, keychainAccount)
	require.NoError(t, err, "generated password must be stored in the keychain")
	assert.NotEmpty(t, pw)
}

// TestEnsureAdminUser_PassesConfigFlag is the C5 regression test: the native
// `ntfy user add` / `ntfy user change-pass` invocations must carry
// `--config <abysslink server.yml>`. Without it the ntfy CLI reads the default
// /etc/ntfy/server.yml and the admin user lands in the WRONG auth DB — the
// abysslink server (deny-all) would reject every authenticated send.
func TestEnsureAdminUser_PassesConfigFlag(t *testing.T) {
	kc := secrets.NewMockStore()
	require.NoError(t, kc.Set(context.Background(), keychainService, keychainAccount, "pw"))

	r := shell.NewMockRunner(
		// user add → "already exists" so the change-pass path runs too.
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "user admin already exists"}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}, Keychain: kc})

	const cfgPath = "/home/u/.config/ntfy/server.yml"
	require.NoError(t, m.ensureAdminUser(context.Background(), cfgPath))
	require.True(t, r.Done())

	for _, c := range r.RecordedCalls() {
		argv := strings.Join(c.Args, " ")
		assert.Contains(t, argv, "--config "+cfgPath,
			"every native ntfy user command must target the abysslink server.yml, got %q", argv)
	}
}

// TestEnsureAdminUser_AlreadyExistsForcesChangePass asserts the NET-12 repair
// path: when the admin user already exists, the server-side password is forced
// to match the keychain via `ntfy user change-pass` instead of silently
// tolerating a potential divergence.
func TestEnsureAdminUser_AlreadyExistsForcesChangePass(t *testing.T) {
	kc := secrets.NewMockStore()
	require.NoError(t, kc.Set(context.Background(), keychainService, keychainAccount, "existing-pw"))

	r := shell.NewMockRunner(
		// ntfy user add → exit 1, "already exists" (tolerated)
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "user admin already exists"}},
		// ntfy user change-pass admin → exit 0
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}, Keychain: kc})

	require.NoError(t, m.ensureAdminUser(context.Background(), "/home/u/.config/ntfy/server.yml"))
	require.True(t, r.Done(), "change-pass must run when the admin already exists")

	calls := r.RecordedCalls()
	require.Len(t, calls, 2)
	assert.Contains(t, calls[1].Args, "change-pass",
		"second call must be ntfy user change-pass to converge user.db to the keychain")
	assert.Equal(t, "existing-pw\nexisting-pw\n", calls[1].Stdin,
		"change-pass must receive the KEYCHAIN password via stdin (never argv)")
}

// TestEnsureAdminUserDocker_AlreadyExistsForcesChangePass covers the same
// NET-12 convergence on the Docker code path.
func TestEnsureAdminUserDocker_AlreadyExistsForcesChangePass(t *testing.T) {
	kc := secrets.NewMockStore()
	require.NoError(t, kc.Set(context.Background(), keychainService, keychainAccount, "existing-pw"))

	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{ExitCode: 1, Stderr: "user admin already exists"}},
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}, Keychain: kc})

	require.NoError(t, m.ensureAdminUserDocker(context.Background()))
	require.True(t, r.Done())

	calls := r.RecordedCalls()
	require.Len(t, calls, 2)
	assert.Equal(t, "docker", calls[1].Name)
	assert.Contains(t, calls[1].Args, "change-pass")
	assert.Equal(t, "existing-pw\nexisting-pw\n", calls[1].Stdin)
}

// TestGetTailnetHostname_SelfNotPeer is the NET-19 regression test: when a
// Peer's DNSName appears before Self in the `tailscale status --json` output,
// the hostname must still come from Self.DNSName.
func TestGetTailnetHostname_SelfNotPeer(t *testing.T) {
	statusJSON := `{
		"Peer": {
			"nodekey:abc": {"DNSName": "phone.example.ts.net."}
		},
		"Self": {"DNSName": "rig.example.ts.net."}
	}`
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: statusJSON, ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}})

	got := m.getTailnetHostname(context.Background())
	assert.Equal(t, "rig.example.ts.net", got,
		"hostname must be Self.DNSName (trailing dot trimmed), never a Peer's DNSName")
}

// TestPlan_HealthyConfigConverges is the W1 regression test: a correctly
// configured ntfy (Detect emits listen_address SeverityOK) must NOT plan a
// "write ntfy server.yml" action — SeverityOK findings are confirmation, not
// remediation targets, and the plan must converge.
func TestPlan_HealthyConfigConverges(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	cfgDir := filepath.Join(dir, ".config", "ntfy")
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "server.yml"),
		[]byte(`listen-http: "100.64.1.2:2586"`+"\n"), 0o600))

	r := shell.NewMockRunner(
		// Detect → ntfyBinaryPresent: ntfy --help (has "serve")
		shell.Call{Result: shell.Result{Stdout: "serve  Start ntfy server\n", ExitCode: 0}},
	)
	cfg := config.Defaults()
	cfg.Modules.Ntfy.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: r, Platform: &testPlatform{}})

	actions, err := m.Plan(context.Background(), true)
	require.NoError(t, err)
	for _, a := range actions {
		assert.NotContains(t, a.Description, "write ntfy server.yml",
			"a healthy SeverityOK listen_address must not schedule a config rewrite")
	}
}

// TestGetTailnetIP_TakesFirstLine: `tailscale ip --4` may print multiple
// addresses one per line; an embedded newline must never reach the generated
// server.yml.
func TestGetTailnetIP_TakesFirstLine(t *testing.T) {
	r := shell.NewMockRunner(
		shell.Call{Result: shell.Result{Stdout: "100.64.1.2\n100.64.9.9\n", ExitCode: 0}},
	)
	m := New(modules.Deps{Cfg: config.Defaults(), Runner: r, Platform: &testPlatform{}})

	ip, err := m.getTailnetIP(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "100.64.1.2", ip)
	assert.NotContains(t, ip, "\n")
}

// TestDockerImagePinnedByDigest: the Docker image must be pinned by digest so
// a floating tag cannot silently swap the image (supply chain).
func TestDockerImagePinnedByDigest(t *testing.T) {
	assert.Contains(t, dockerImage, "@sha256:", "ntfy Docker image must be digest-pinned")
	assert.True(t, strings.HasPrefix(dockerImage, "binwiederhier/ntfy:"),
		"image must keep a human-readable tag alongside the digest")
}

// TestConfigureNative_CreatesStateDirAndTargetsConfig covers the rest of C5:
// configureNative must create the auth-file parent dir (the native server.yml
// points auth-file into it) and provision the admin user against the SAME
// config file the service is launched with.
func TestConfigureNative_CreatesStateDirAndTargetsConfig(t *testing.T) {
	home := t.TempDir()
	auditLog := filepath.Join(t.TempDir(), "audit.log")

	r := shell.NewMockRunner(
		// ensureAdminUser → ntfy user add (exit 0)
		shell.Call{Result: shell.Result{ExitCode: 0}},
	)
	m := New(modules.Deps{
		Cfg:      config.Defaults(),
		Runner:   r,
		Audit:    audit.New(auditLog),
		Platform: &testPlatform{},
		Keychain: &stubKeychain{pw: "pw"},
	})

	require.NoError(t, m.configureNative(context.Background(), "100.64.1.2", home))
	require.True(t, r.Done())

	// Auth-file parent dir must exist before ntfy serve starts.
	st, err := os.Stat(filepath.Join(home, ".local", "state", "abysslink", "ntfy"))
	require.NoError(t, err, "configureNative must create the auth-file parent dir")
	assert.True(t, st.IsDir())

	// The user command must target the abysslink server.yml via --config.
	cfgPath := filepath.Join(home, ".config", "ntfy", "server.yml")
	calls := r.RecordedCalls()
	require.Len(t, calls, 1)
	assert.Contains(t, strings.Join(calls[0].Args, " "), "--config "+cfgPath,
		"ntfy user add must run against the abysslink config, not /etc/ntfy")

	// And the server config itself must exist, bound to the tailnet IP.
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), `listen-http: "100.64.1.2:`)
}

// TestProbeNtfyReachable covers the doctor reachability probe (the universal
// macOS Docker-Desktop fix): a live ntfy answers -> true; nothing listening
// (the silent-drop case this check exists to catch) -> false.
func TestProbeNtfyReachable(t *testing.T) {
	m := New(modules.Deps{Cfg: config.Defaults()})

	// Reachable: a server that answers /v1/health with 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	host, portStr, err := splitHostPortTest(u.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	assert.True(t, m.probeNtfyReachable(context.Background(), host, port),
		"a live ntfy on host:port must probe as reachable")

	// Unreachable: nothing listening (server closed) -> false.
	srv.Close()
	assert.False(t, m.probeNtfyReachable(context.Background(), host, port),
		"a dead/unpublished ntfy must probe as unreachable (the silent-drop case)")
}

func splitHostPortTest(hostport string) (string, string, error) {
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 {
		return hostport, "", fmt.Errorf("no port in %q", hostport)
	}
	return hostport[:i], hostport[i+1:], nil
}
