//go:build linux

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

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abysslink/abysslink/internal/platform"
)

// ServiceInstall writes a systemd --user unit file and enables/starts the service.
func (p *Platform) ServiceInstall(ctx context.Context, spec platform.ServiceSpec) error {
	unitPath, err := systemdUnitPath(spec.Label)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(unitPath), 0o750); err != nil {
		return fmt.Errorf("mkdir systemd user dir: %w", err)
	}

	data := renderUnit(spec)
	if err := os.WriteFile(unitPath, []byte(data), 0o600); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	if _, err := p.runner.Run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}

	if spec.RunAtLoad {
		if _, err := p.runner.Run(ctx, "systemctl", "--user", "enable", "--now", spec.Label); err != nil {
			return fmt.Errorf("systemctl enable --now %s: %w", spec.Label, err)
		}
	}

	return nil
}

// ServiceUninstall disables and removes the systemd --user unit for the given label.
func (p *Platform) ServiceUninstall(ctx context.Context, label string) error {
	// Disable and stop — ignore errors (service may not be running/enabled).
	_, _ = p.runner.Run(ctx, "systemctl", "--user", "disable", "--now", label)

	unitPath, err := systemdUnitPath(label)
	if err != nil {
		return err
	}
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}
	return nil
}

// ServiceStart starts the systemd --user service.
func (p *Platform) ServiceStart(ctx context.Context, label string) error {
	_, err := p.runner.Run(ctx, "systemctl", "--user", "start", label)
	return err
}

// ServiceStop stops the systemd --user service.
func (p *Platform) ServiceStop(ctx context.Context, label string) error {
	_, err := p.runner.Run(ctx, "systemctl", "--user", "stop", label)
	return err
}

// ServiceStatus returns Running if the service is active, Stopped otherwise.
func (p *Platform) ServiceStatus(ctx context.Context, label string) (platform.ServiceStatus, error) {
	_, err := p.runner.Run(ctx, "systemctl", "--user", "is-active", label)
	if err != nil {
		return platform.ServiceStopped, nil
	}
	return platform.ServiceRunning, nil
}

// systemdUnitPath returns the path for the --user unit file for the given label.
func systemdUnitPath(label string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user", label+".service"), nil
}

// renderUnit generates a systemd unit file for the given ServiceSpec.
func renderUnit(spec platform.ServiceSpec) string {
	var b strings.Builder

	b.WriteString("[Unit]\n")
	b.WriteString("Description=" + spec.Label + "\n")
	b.WriteString("\n")

	b.WriteString("[Service]\n")
	b.WriteString("ExecStart=" + strings.Join(spec.Args, " ") + "\n")

	if spec.KeepAlive {
		b.WriteString("Restart=always\n")
	}
	if spec.StdoutPath != "" {
		b.WriteString("StandardOutput=file:" + spec.StdoutPath + "\n")
	}
	if spec.StderrPath != "" {
		b.WriteString("StandardError=file:" + spec.StderrPath + "\n")
	}

	// Inject environment variables.
	for k, v := range spec.Env {
		b.WriteString("Environment=" + k + "=" + v + "\n")
	}

	b.WriteString("\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=default.target\n")

	return b.String()
}
