//go:build darwin

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

package darwin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/platform"
)

// ServiceInstall writes a launchd plist and bootstraps the service for the current GUI session.
func (p *Platform) ServiceInstall(ctx context.Context, spec platform.ServiceSpec) error {
	plistPath, err := launchAgentPath(spec.Label)
	if err != nil {
		return err
	}
	data, err := renderPlist(spec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o750); err != nil {
		return fmt.Errorf("mkdir LaunchAgents: %w", err)
	}
	logPath, err := audit.DefaultLogPath()
	if err != nil {
		return fmt.Errorf("audit log path: %w", err)
	}
	if err := audit.New(logPath).WriteFile(plistPath, data, 0o600, false); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	uid := fmt.Sprintf("%d", os.Getuid())
	domain := "gui/" + uid
	target := domain + "/" + spec.Label

	// Boot out any previously-loaded instance first so the rewritten plist is
	// re-read; bootout fails when nothing is loaded, which is fine (best-effort).
	_, _ = p.runner.Run(ctx, "launchctl", "bootout", target)

	// bootout is ASYNCHRONOUS: bootstrapping immediately can race the teardown and
	// fail with "Bootstrap failed: 5: Input/output error". The old code tolerated
	// that exit-5 as "already loaded" and then ran `kickstart -k` against the
	// (now unloaded) service, surfacing the opaque "Could not find service … 113".
	// Wait for the prior instance to actually unload first (no-op when nothing was
	// loaded, so the common fresh-install path pays no latency).
	p.waitServiceUnloaded(ctx, target)

	// Bootstrap the (re)written plist. shell.Runner reports a non-zero exit in
	// Result.ExitCode with err == nil — both must be checked (C3/C4 bug class).
	res, err := p.runner.Run(ctx, "launchctl", "bootstrap", domain, plistPath)
	if err != nil {
		return fmt.Errorf("launchctl bootstrap %s: %w", spec.Label, err)
	}
	// Trust the LOADED state, not the exit code. macOS returns a non-zero
	// bootstrap both for real failures and for the benign "already loaded" case
	// (exit 5), so the old string-match heuristic masked real failures. If the
	// service did not load, surface the real bootstrap output + remediation rather
	// than letting the kickstart below fail with the opaque 113.
	if !res.Ok() && !p.serviceLoaded(ctx, target) {
		return fmt.Errorf(
			"launchctl bootstrap %s did not load the service (exited %d: %s)\n"+
				"  clear any stale registration and retry:\n"+
				"    launchctl bootout %s\n"+
				"    abysslink daemon enable --apply",
			spec.Label, res.ExitCode, strings.TrimSpace(res.Stderr+res.Stdout), target)
	}

	// Kickstart -k kills any running instance and restarts it so a changed
	// service spec takes effect immediately instead of after logout/login
	// (parity with the systemd daemon-reload + enable --now path).
	if spec.RunAtLoad {
		kres, kerr := p.runner.Run(ctx, "launchctl", "kickstart", "-k", target)
		if kerr != nil {
			return fmt.Errorf("launchctl kickstart %s: %w", spec.Label, kerr)
		}
		if !kres.Ok() {
			return fmt.Errorf("launchctl kickstart %s exited %d: %s",
				spec.Label, kres.ExitCode, strings.TrimSpace(kres.Stderr+kres.Stdout))
		}
	}
	return nil
}

// serviceLoaded reports whether the launchd label is bootstrapped in the domain
// (`launchctl print <target>` exits 0). It is the reliable signal used to decide
// success over the ambiguous bootstrap exit code.
func (p *Platform) serviceLoaded(ctx context.Context, target string) bool {
	res, err := p.runner.Run(ctx, "launchctl", "print", target)
	return err == nil && res.Ok()
}

// waitServiceUnloaded polls until the launchd label is no longer loaded (or a
// short timeout elapses), so a bootstrap after bootout does not race the
// asynchronous teardown. It returns immediately when nothing is loaded.
func (p *Platform) waitServiceUnloaded(ctx context.Context, target string) {
	for range 20 {
		if !p.serviceLoaded(ctx, target) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// ServiceUninstall bootouts and removes the launchd plist for the given label.
func (p *Platform) ServiceUninstall(ctx context.Context, label string) error {
	plistPath, err := launchAgentPath(label)
	if err != nil {
		return err
	}
	uid := fmt.Sprintf("%d", os.Getuid())
	// bootout may fail if not loaded; ignore
	_, _ = p.runner.Run(ctx, "launchctl", "bootout", "gui/"+uid+"/"+label)
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	return nil
}

// ServiceStart kickstarts an already-bootstrapped launchd service.
func (p *Platform) ServiceStart(ctx context.Context, label string) error {
	uid := fmt.Sprintf("%d", os.Getuid())
	_, err := p.runner.Run(ctx, "launchctl", "kickstart", "gui/"+uid+"/"+label)
	return err
}

// ServiceStop sends SIGTERM to a running launchd service.
func (p *Platform) ServiceStop(ctx context.Context, label string) error {
	uid := fmt.Sprintf("%d", os.Getuid())
	_, err := p.runner.Run(ctx, "launchctl", "kill", "TERM", "gui/"+uid+"/"+label)
	return err
}

// ServiceStatus reports Running only when the launchd service is BOTH loaded
// AND actually running (a live pid). `launchctl print` exits non-zero when the
// label is not bootstrapped in the domain (→ Stopped) and zero when it is
// loaded — but a loaded service whose program cannot start (missing binary,
// crash-loop) is loaded yet NOT running, so we additionally require a live pid
// in the print output.
//
// shell.Runner reports a non-zero exit via Result.ExitCode with err == nil; the
// exit code is the signal, NOT the error (mirrors the linux fix, C3). The old
// `if err != nil` check only ever saw an error on exec failure, so it reported
// Running for every stopped OR missing service (e.g. exit 113 "could not find
// service") — a false-OK that made `daemon status` claim "running" when no
// process existed.
func (p *Platform) ServiceStatus(ctx context.Context, label string) (platform.ServiceStatus, error) {
	uid := fmt.Sprintf("%d", os.Getuid())
	res, err := p.runner.Run(ctx, "launchctl", "print", "gui/"+uid+"/"+label)
	if err != nil {
		// launchctl itself could not be executed — the status is unknown.
		return platform.ServiceUnknown, fmt.Errorf("launchctl print %s: %w", label, err)
	}
	if !res.Ok() {
		// Not bootstrapped in this domain (e.g. exit 113 "could not find service").
		return platform.ServiceStopped, nil
	}
	// Loaded — but it is actually RUNNING only if launchd reports a live pid; a
	// loaded job with no pid (waiting / crash-looping / missing program) is
	// stopped.
	if launchdHasLivePID(res.Stdout) {
		return platform.ServiceRunning, nil
	}
	return platform.ServiceStopped, nil
}

// launchdHasLivePID reports whether `launchctl print` output shows a live pid —
// i.e. the service process is actually running, not merely loaded. launchd
// emits a `pid = N` line in the print block only while the job is running.
func launchdHasLivePID(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "pid = ") {
			return true
		}
	}
	return false
}

func launchAgentPath(label string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), nil
}

func renderPlist(spec platform.ServiceSpec) ([]byte, error) {
	plist := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	plist += "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
	plist += "<plist version=\"1.0\">\n<dict>\n"
	plist += "\t<key>Label</key>\n\t<string>" + xmlEscape(spec.Label) + "</string>\n"
	plist += "\t<key>ProgramArguments</key>\n\t<array>\n"
	for _, a := range spec.Args {
		plist += "\t\t<string>" + xmlEscape(a) + "</string>\n"
	}
	plist += "\t</array>\n"
	if spec.KeepAlive {
		plist += "\t<key>KeepAlive</key>\n\t<true/>\n"
	}
	if spec.RunAtLoad {
		plist += "\t<key>RunAtLoad</key>\n\t<true/>\n"
	}
	if spec.StdoutPath != "" {
		plist += "\t<key>StandardOutPath</key>\n\t<string>" + xmlEscape(spec.StdoutPath) + "</string>\n"
	}
	if spec.StderrPath != "" {
		plist += "\t<key>StandardErrorPath</key>\n\t<string>" + xmlEscape(spec.StderrPath) + "</string>\n"
	}
	if len(spec.Env) > 0 {
		plist += "\t<key>EnvironmentVariables</key>\n\t<dict>\n"
		envKeys := make([]string, 0, len(spec.Env))
		for k := range spec.Env {
			envKeys = append(envKeys, k)
		}
		sort.Strings(envKeys)
		for _, k := range envKeys {
			plist += "\t\t<key>" + xmlEscape(k) + "</key>\n\t\t<string>" + xmlEscape(spec.Env[k]) + "</string>\n"
		}
		plist += "\t</dict>\n"
	}
	plist += "</dict>\n</plist>\n"
	return []byte(plist), nil
}

func xmlEscape(s string) string {
	var result string
	for _, c := range s {
		switch c {
		case '&':
			result += "&amp;"
		case '<':
			result += "&lt;"
		case '>':
			result += "&gt;"
		case '"':
			result += "&quot;"
		default:
			result += string(c)
		}
	}
	return result
}
