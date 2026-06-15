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
	"encoding/json"
	"errors"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withStubDaemonStatus swaps the fetchDaemonStatus package seam for the test
// duration and restores it afterwards.
func withStubDaemonStatus(t *testing.T, fn func(context.Context) (*statusDaemonExtras, error)) {
	t.Helper()
	orig := fetchDaemonStatus
	fetchDaemonStatus = fn
	t.Cleanup(func() { fetchDaemonStatus = orig })
}

// csExtras builds a statusDaemonExtras whose content_store field is the given
// JSON string value (matching the daemon's GET /status encoding).
func csExtras(t *testing.T, status string) *statusDaemonExtras {
	t.Helper()
	raw, err := json.Marshal(status)
	require.NoError(t, err)
	return &statusDaemonExtras{ContentStore: json.RawMessage(raw)}
}

func contentStoreEnabledCfg() *config.Config {
	cfg := config.Defaults()
	cfg.ContentStore.Enabled = true
	return cfg
}

func findOnly(t *testing.T, findings []modules.Finding) modules.Finding {
	t.Helper()
	require.Len(t, findings, 1)
	return findings[0]
}

func TestContentStoreDoctorFindings_DaemonDownWarns(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return nil, errors.New("daemon unreachable")
	})
	f := findOnly(t, contentStoreDoctorFindings(context.Background(), contentStoreEnabledCfg()))
	assert.Equal(t, "content-store-daemon-down", f.Check)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	assert.Contains(t, f.Message, "not reachable")
	assert.NotEmpty(t, findingFix(f.Check), "daemon-down must carry a fix hint")
}

func TestContentStoreDoctorFindings_DisabledEchoesReason(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return csExtras(t, "disabled: tailnet HTTPS certs unavailable — enable HTTPS Certificates"), nil
	})
	f := findOnly(t, contentStoreDoctorFindings(context.Background(), contentStoreEnabledCfg()))
	assert.Equal(t, "content-store-disabled", f.Check)
	assert.Equal(t, modules.SeverityWarning, f.Severity)
	assert.Contains(t, f.Message, "HTTPS certs unavailable", "the daemon reason must flow through")
	assert.NotEmpty(t, findingFix(f.Check), "disabled must carry a fix hint")
}

func TestContentStoreDoctorFindings_ListeningIsOK(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return csExtras(t, "listening on 100.64.0.5:2587"), nil
	})
	f := findOnly(t, contentStoreDoctorFindings(context.Background(), contentStoreEnabledCfg()))
	assert.Equal(t, "content-store", f.Check)
	assert.Equal(t, modules.SeverityOK, f.Severity)
	assert.Contains(t, f.Message, "100.64.0.5:2587")
}

func TestContentStoreDoctorFindings_OptOutIsOK(t *testing.T) {
	// enabled=false must NOT warn — it is a deliberate opt-out. The daemon seam
	// must not even be consulted.
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		t.Fatal("daemon must not be pinged when content store is disabled in config")
		return nil, nil
	})
	cfg := config.Defaults()
	cfg.ContentStore.Enabled = false
	f := findOnly(t, contentStoreDoctorFindings(context.Background(), cfg))
	assert.Equal(t, modules.SeverityOK, f.Severity)
	assert.Equal(t, "content-store", f.Check)
}

func TestContentStoreDoctorFindings_OlderDaemonUnknownIsOK(t *testing.T) {
	// A daemon that does not emit content_store must not WARN (no false alarm
	// against an older daemon generation) and must not falsely claim listening.
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return &statusDaemonExtras{}, nil
	})
	f := findOnly(t, contentStoreDoctorFindings(context.Background(), contentStoreEnabledCfg()))
	assert.Equal(t, "content-store-unknown", f.Check)
	assert.Equal(t, modules.SeverityOK, f.Severity)
}
