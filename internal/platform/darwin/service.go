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
	if err := os.WriteFile(plistPath, data, 0o600); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	uid := fmt.Sprintf("%d", os.Getuid())
	// bootstrap returns error if already loaded; ignore
	_, _ = p.runner.Run(ctx, "launchctl", "bootstrap", "gui/"+uid, plistPath)
	return nil
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

// ServiceStatus returns Running if the service is loaded and active, Stopped otherwise.
func (p *Platform) ServiceStatus(ctx context.Context, label string) (platform.ServiceStatus, error) {
	uid := fmt.Sprintf("%d", os.Getuid())
	_, err := p.runner.Run(ctx, "launchctl", "print", "gui/"+uid+"/"+label)
	if err != nil {
		return platform.ServiceStopped, nil
	}
	return platform.ServiceRunning, nil
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
		for k, v := range spec.Env {
			plist += "\t\t<key>" + xmlEscape(k) + "</key>\n\t\t<string>" + xmlEscape(v) + "</string>\n"
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
