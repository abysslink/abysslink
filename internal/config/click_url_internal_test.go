// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Abysslink Contributors

package config

import "testing"

func TestValidateNotifyClickURL(t *testing.T) {
	mk := func(u string) *Config {
		c := &Config{}
		c.Modules.Notify.ClickURL = u
		return c
	}
	for _, u := range []string{"", "ssh://me@rig.tailnet-name.ts.net", "https://example.com/x"} {
		if err := validateNotifyClickURL(mk(u)); err != nil {
			t.Errorf("click_url %q should be valid, got: %v", u, err)
		}
	}
	if err := validateNotifyClickURL(mk("rig.ts.net")); err == nil {
		t.Error("a bare host with no scheme must be rejected")
	}
	if err := validateNotifyClickURL(mk("ssh://rig\ninjected")); err == nil {
		t.Error("control chars must be rejected")
	}
}
