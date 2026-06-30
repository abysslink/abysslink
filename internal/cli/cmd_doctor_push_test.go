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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

// pushCfg returns a *config.Config with gateway defaults applied.
func pushCfg() *config.Config {
	return config.Defaults()
}

// extrasWithCredsStatus builds a statusDaemonExtras whose gateway_creds_status
// field is set to the given value.
func extrasWithCredsStatus(status string) *statusDaemonExtras {
	return &statusDaemonExtras{GatewayCredsStatus: status}
}

// extrasWithContentStore builds a statusDaemonExtras whose ContentStore JSON
// string is set to the given value (mirrors csExtras but with a raw string).
func extrasWithBothFields(credsStatus, contentStore string) *statusDaemonExtras {
	e := extrasWithCredsStatus(credsStatus)
	if contentStore != "" {
		raw := []byte(`"` + contentStore + `"`)
		e.ContentStore = raw
	}
	return e
}

// makeFileWithMode creates a temp file with the given content and permission mode.
func makeFileWithMode(t *testing.T, mode os.FileMode) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "creds-*.json")
	require.NoError(t, err)
	_, _ = f.WriteString(`{"key":"value"}`)
	require.NoError(t, f.Close())
	require.NoError(t, os.Chmod(f.Name(), mode))
	return f.Name()
}

// overrideDeviceListForPush overrides the readDeviceRecords seam for push doctor
// tests and restores it after.
func overrideDeviceListForPush(t *testing.T, recs []pushDeviceRecord) {
	t.Helper()
	orig := readPushDeviceRecords
	readPushDeviceRecords = func() []pushDeviceRecord { return recs }
	t.Cleanup(func() { readPushDeviceRecords = orig })
}

// --- push-creds-keychain ---

// TestDoctorPushCredsOK verifies that when the daemon reports creds status "ok",
// the push-creds-keychain check emits an OK finding.
func TestDoctorPushCredsOK(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	findings := pushGatewayDoctorFindings(context.Background(), pushCfg())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-creds-keychain" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-creds-keychain finding must be present")
	assert.Equal(t, modules.SeverityOK, found.Severity)
	assert.Contains(t, found.Message, "loaded")
}

// TestDoctorPushCredsDaemonDown verifies that when the daemon is unreachable,
// the push-creds-keychain check emits a WARN finding.
func TestDoctorPushCredsDaemonDown(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return nil, errors.New("connection refused")
	})
	findings := pushGatewayDoctorFindings(context.Background(), pushCfg())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-creds-keychain" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-creds-keychain finding must be present even when daemon down")
	assert.Equal(t, modules.SeverityWarning, found.Severity)
	assert.Contains(t, found.Message, "cannot verify")
}

// --- push-creds-file-perms ---

// TestDoctorPushCredsFilePerms644 verifies that a creds file with mode 0644
// emits a FATAL finding for push-creds-file-perms.
func TestDoctorPushCredsFilePerms644(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	path := makeFileWithMode(t, 0o644)
	cfg := config.Defaults()
	cfg.Gateway.APNs.Enabled = true
	cfg.Gateway.APNs.BundleID = "com.example.app"
	cfg.Gateway.APNs.KeySource = "file"
	cfg.Gateway.APNs.CredFilePath = path

	findings := pushGatewayDoctorFindings(context.Background(), cfg)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-creds-file-perms" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-creds-file-perms finding must be present")
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "0644")
}

// TestDoctorPushCredsFilePerms600 verifies that a creds file with mode 0600
// emits an OK finding for push-creds-file-perms.
func TestDoctorPushCredsFilePerms600(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	path := makeFileWithMode(t, 0o600)
	cfg := config.Defaults()
	cfg.Gateway.APNs.Enabled = true
	cfg.Gateway.APNs.BundleID = "com.example.app"
	cfg.Gateway.APNs.KeySource = "file"
	cfg.Gateway.APNs.CredFilePath = path

	findings := pushGatewayDoctorFindings(context.Background(), cfg)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-creds-file-perms" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-creds-file-perms finding must be present")
	assert.Equal(t, modules.SeverityOK, found.Severity)
}

// --- push-creds-file-location ---

// TestDoctorPushCredsFileLocation verifies that a creds file under the iCloud Drive
// directory emits a FATAL finding for push-creds-file-location.
// The test creates a real file inside a temp directory structured to match the
// iCloud Drive prefix pattern, then overrides the cloudSyncedPrefixesFunc seam
// so the check sees the temp dir as "cloud-synced" without needing to write to
// the real ~/Library/Mobile Documents path (which is protected by macOS sandbox).
func TestDoctorPushCredsFileLocation(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})

	// Create a temp dir that mimics the iCloud Drive prefix.
	fakeICloudBase := t.TempDir()
	fakeICloudDir := filepath.Join(fakeICloudBase, "Library", "Mobile Documents", "test-app")
	require.NoError(t, os.MkdirAll(fakeICloudDir, 0o700))
	cloudFile := filepath.Join(fakeICloudDir, "gateway-creds.json")
	require.NoError(t, os.WriteFile(cloudFile, []byte(`{}`), 0o600))

	// Override the home-dir lookup to return our temp dir so checkCredsFileLocation
	// sees fakeICloudBase as HOME and thus detects the iCloud prefix correctly.
	origFn := userHomeDirFn
	userHomeDirFn = func() (string, error) { return fakeICloudBase, nil }
	t.Cleanup(func() { userHomeDirFn = origFn })

	cfg := config.Defaults()
	cfg.Gateway.FCM.Enabled = true
	cfg.Gateway.FCM.CredsSource = "file"
	cfg.Gateway.FCM.CredFilePath = cloudFile

	findings := pushGatewayDoctorFindings(context.Background(), cfg)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-creds-file-location" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-creds-file-location finding must be present")
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "cloud-synced")
}

// --- push-apns-experimental ---

// TestDoctorPushAPNsExperimental verifies that enabling the APNs leg emits a WARN.
func TestDoctorPushAPNsExperimental(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	cfg := config.Defaults()
	cfg.Gateway.APNs.Enabled = true
	cfg.Gateway.APNs.BundleID = "com.example.app" // avoid bundle-missing FATAL

	findings := pushGatewayDoctorFindings(context.Background(), cfg)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-apns-experimental" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-apns-experimental finding must be present")
	assert.Equal(t, modules.SeverityWarning, found.Severity)
	assert.Contains(t, found.Message, "experimental")
}

// --- push-fcm-experimental ---

// TestDoctorPushFCMExperimental verifies that enabling the FCM leg emits a WARN.
func TestDoctorPushFCMExperimental(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	cfg := config.Defaults()
	cfg.Gateway.FCM.Enabled = true

	findings := pushGatewayDoctorFindings(context.Background(), cfg)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-fcm-experimental" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-fcm-experimental finding must be present")
	assert.Equal(t, modules.SeverityWarning, found.Severity)
	assert.Contains(t, found.Message, "experimental")
}

// --- push-apns-bundle-missing ---

// TestDoctorPushAPNsBundleMissing verifies that APNs enabled without a bundle_id
// emits a FATAL finding for push-apns-bundle-missing.
func TestDoctorPushAPNsBundleMissing(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	cfg := config.Defaults()
	cfg.Gateway.APNs.Enabled = true
	cfg.Gateway.APNs.BundleID = "" // missing bundle ID

	findings := pushGatewayDoctorFindings(context.Background(), cfg)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-apns-bundle-missing" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-apns-bundle-missing finding must be present")
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "bundle_id")
}

// --- push-stale-tokens ---

// TestDoctorPushStaleToken verifies that a device last seen 45 days ago
// emits a WARN finding for push-stale-tokens.
func TestDoctorPushStaleToken(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	staleTime := time.Now().Add(-45 * 24 * time.Hour)
	overrideDeviceListForPush(t, []pushDeviceRecord{
		{ID: "01J1Y8X3Q0B1ABCD", Name: "old-phone", LastSeen: staleTime, Revoked: false},
	})

	findings := pushGatewayDoctorFindings(context.Background(), pushCfg())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-stale-tokens" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-stale-tokens finding must be present")
	assert.Equal(t, modules.SeverityWarning, found.Severity)
	assert.Contains(t, found.Message, "old-phone")
}

// --- push-unifiedpush-ntfysh ---

// TestDoctorPushNtfySh verifies that a device with a ntfy.sh UnifiedPush endpoint
// emits a WARN finding for push-unifiedpush-ntfysh.
func TestDoctorPushNtfySh(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	overrideDeviceListForPush(t, []pushDeviceRecord{
		{ID: "01J2A8X3Q0B1EFGH", Name: "my-phone", Platform: "unifiedpush",
			ProviderToken: "https://ntfy.sh/mytopic", LastSeen: time.Now(), Revoked: false},
	})

	findings := pushGatewayDoctorFindings(context.Background(), pushCfg())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-unifiedpush-ntfysh" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-unifiedpush-ntfysh finding must be present")
	assert.Equal(t, modules.SeverityWarning, found.Severity)
	assert.Contains(t, found.Message, "ntfy.sh")
}

// --- push-ios-unifiedpush-gap ---

// TestDoctorPushIOSGap verifies the iOS UnifiedPush gap warning is emitted when
// UnifiedPush is enabled and APNs is not.
func TestDoctorPushIOSGap(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithCredsStatus("ok"), nil
	})
	cfg := config.Defaults()
	cfg.Gateway.UnifiedPush.Enabled = true
	cfg.Gateway.APNs.Enabled = false

	findings := pushGatewayDoctorFindings(context.Background(), cfg)
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-ios-unifiedpush-gap" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-ios-unifiedpush-gap finding must be present when UP enabled, APNs disabled")
	assert.Equal(t, modules.SeverityWarning, found.Severity)
	assert.Contains(t, found.Message, "iOS")

	// When APNs IS enabled, there must be no iOS gap warning.
	cfg2 := config.Defaults()
	cfg2.Gateway.UnifiedPush.Enabled = true
	cfg2.Gateway.APNs.Enabled = true
	cfg2.Gateway.APNs.BundleID = "com.example.app"
	findings2 := pushGatewayDoctorFindings(context.Background(), cfg2)
	for _, f := range findings2 {
		assert.NotEqual(t, "push-ios-unifiedpush-gap", f.Check,
			"push-ios-unifiedpush-gap must NOT fire when APNs is enabled")
	}
}

// --- push-contentstore-bind ---

// TestDoctorPushContentStorePublicBind verifies that when the daemon reports the
// content store is bound to 0.0.0.0, the push-contentstore-bind check emits FATAL.
func TestDoctorPushContentStorePublicBind(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithBothFields("ok", "listening on 0.0.0.0:2587"), nil
	})
	findings := pushGatewayDoctorFindings(context.Background(), pushCfg())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-contentstore-bind" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-contentstore-bind finding must be present")
	assert.Equal(t, modules.SeverityFatal, found.Severity)
	assert.Contains(t, found.Message, "0.0.0.0")
}

// TestDoctorPushContentStoreDisabled verifies that when the content store
// fail-closed and disabled itself (BACK-06), the push-contentstore-bind check is
// OK — a disabled store binds to nothing, so it must NOT be a false "bound to a
// public address" FATAL (the "disabled: <reason>" status string is not an
// address).
func TestDoctorPushContentStoreDisabled(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithBothFields("ok", "disabled: bind address could not be confirmed as the tailnet IP (BACK-06)"), nil
	})
	findings := pushGatewayDoctorFindings(context.Background(), pushCfg())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-contentstore-bind" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-contentstore-bind finding must be present")
	assert.Equal(t, modules.SeverityOK, found.Severity, "a disabled content store must not be a public-bind FATAL")
	assert.Contains(t, found.Message, "disabled")
}

// TestDoctorPushContentStoreTailnetBind verifies that when the content store is
// bound to a tailnet IP, the push-contentstore-bind check emits OK.
func TestDoctorPushContentStoreTailnetBind(t *testing.T) {
	withStubDaemonStatus(t, func(context.Context) (*statusDaemonExtras, error) {
		return extrasWithBothFields("ok", "listening on 100.64.1.5:2587"), nil
	})
	findings := pushGatewayDoctorFindings(context.Background(), pushCfg())
	var found *modules.Finding
	for i := range findings {
		if findings[i].Check == "push-contentstore-bind" {
			found = &findings[i]
			break
		}
	}
	require.NotNil(t, found, "push-contentstore-bind finding must be present")
	assert.Equal(t, modules.SeverityOK, found.Severity)
}
