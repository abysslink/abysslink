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

package cli

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
)

// ntfyDockerContainerName is the name of the ntfy Docker container to inspect.
// It mirrors ntfy/module.go:dockerContainerName (cannot import without a cycle).
const ntfyDockerContainerName = "abysslink-ntfy"

// ntfyOKFinding builds a SeverityOK ntfy finding. It MUST set Module:"ntfy" —
// NOT "webui". These helpers are intentionally separate from the webui-scoped
// okFinding/fatalFinding in cmd_doctor_webui.go, which hardcode Module:"webui".
// (D-03 / RESEARCH.md WARNING 4 — Phase 23 doctor-honesty grouping boundary.)
func ntfyOKFinding(check, msg string) modules.Finding {
	return modules.Finding{Module: "ntfy", Check: check, Severity: modules.SeverityOK, Message: msg}
}

// ntfyFatalFinding builds a SeverityFatal ntfy finding. Module is "ntfy".
func ntfyFatalFinding(check, msg string) modules.Finding {
	return modules.Finding{Module: "ntfy", Check: check, Severity: modules.SeverityFatal, Message: msg}
}

// isOffTailnetHost returns true when the host string is a loopback address,
// the unspecified wildcard address (0.0.0.0 / ::), or the string "localhost".
// These bindings expose ntfy to traffic outside the tailnet (T-22-09).
func isOffTailnetHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

// ntfyBindCheck is the PRIMARY (FATAL, deterministic) D-02 check.
// It runs `docker inspect` via shell.Runner and returns a FATAL finding if any
// published port binding has HostIp ∈ {127.0.0.1, 0.0.0.0, ::, localhost}.
// On any runner error or non-zero exit code it also returns FATAL — fail-closed
// posture so an uninspectable container is never silently treated as safe
// (T-22-10, D-02 PRIMARY).
func ntfyBindCheck(ctx context.Context, runner shell.Runner, containerName string) modules.Finding {
	const check = "ntfy-bind"
	res, err := runner.Run(ctx, "docker", "inspect",
		"--format={{range $k,$v := .NetworkSettings.Ports}}{{range $v}}{{.HostIp}} {{end}}{{end}}",
		containerName)
	if err != nil || res.ExitCode != 0 {
		return ntfyFatalFinding(check,
			"ntfy-bind: docker inspect failed — cannot verify port binding posture; "+
				"container may be misconfigured (T-22-10, D-02)")
	}
	for _, hostIP := range strings.Fields(res.Stdout) {
		if isOffTailnetHost(hostIP) {
			return ntfyFatalFinding(check, fmt.Sprintf(
				"ntfy-bind: ntfy container publishes on %q — must bind to tailnet IP only, "+
					"never loopback or wildcard (T-22-09, D-01); "+
					"run: abysslink up --apply  to reprovision with the correct binding", hostIP))
		}
	}
	return ntfyOKFinding(check, "ntfy container port binding is tailnet-scoped (no loopback/wildcard HostIp)")
}

// ntfyLoopbackReachCheck is the SECONDARY (corroborating) D-02 check.
// It TCP-dials 127.0.0.1:<port> with the same context-timeout pattern as
// webuiCSRFCheck. A successful dial means ntfy answers off-tailnet — FATAL.
// A dial failure means ntfy is not reachable on loopback — correct (OK).
// This check is gated on cfg.Modules.Ntfy.Enabled.
func ntfyLoopbackReachCheck(ctx context.Context, cfg *config.Config) modules.Finding {
	const check = "ntfy-loopback"
	if !cfg.Modules.Ntfy.Enabled {
		return ntfyOKFinding(check, "ntfy disabled — loopback reachability probe not applicable")
	}
	port := fmt.Sprintf("%d", cfg.Modules.Ntfy.ListenPort())
	addr := net.JoinHostPort("127.0.0.1", port)
	dialCtx, cancel := context.WithTimeout(ctx, webuiProbeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return ntfyOKFinding(check, "ntfy-loopback: ntfy not reachable on 127.0.0.1 (correct — tailnet-only binding)")
	}
	_ = conn.Close()
	return ntfyFatalFinding(check, fmt.Sprintf(
		"ntfy-loopback: ntfy answered on %s — ntfy must not be reachable on loopback; "+
			"run: abysslink up --apply  to reprovision with tailnet-IP-only binding (T-22-11, D-01)", addr))
}

// ntfyBindFindings aggregates both D-02 ntfy posture checks and returns the
// combined findings slice. The entire function is gated on
// cfg.Modules.Ntfy.Enabled — when ntfy is disabled no findings are emitted
// (Pitfall 6 prevention: no spurious failures against an unused module).
func ntfyBindFindings(ctx context.Context, runner shell.Runner, cfg *config.Config) []modules.Finding {
	if !cfg.Modules.Ntfy.Enabled {
		return nil
	}
	return []modules.Finding{
		ntfyBindCheck(ctx, runner, ntfyDockerContainerName),
		ntfyLoopbackReachCheck(ctx, cfg),
	}
}
