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

package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abysslink/abysslink/internal/config"
	"github.com/abysslink/abysslink/internal/modules"
	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendDirect_PostsToNtfy(t *testing.T) {
	var receivedTitle, receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTitle = r.Header.Get("X-Title")
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	cfg.Modules.Notify.DefaultTopic = "alerts"
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirect(context.Background(), "hello title", "hello body")
	require.NoError(t, err)
	assert.Equal(t, "hello title", receivedTitle)
	assert.Equal(t, "hello body", receivedBody)
}

func TestSendDirect_NonOKStatus_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad credentials"))
	}))
	defer srv.Close()

	old := ntfyBaseURL
	ntfyBaseURL = srv.URL
	defer func() { ntfyBaseURL = old }()

	cfg := config.Defaults()
	cfg.Modules.Notify.Enabled = true
	m := New(modules.Deps{Cfg: cfg, Runner: shell.NewMockRunner()})

	err := m.SendDirect(context.Background(), "t", "b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}
