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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abysslink/abysslink/internal/shell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetBirdEventsCmd_Once(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"id": "e1", "activity": "peer.login"},
		})
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner()}
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	err := netbirdEventsRunE(context.Background(), cc, p, false)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "e1")
}

func TestNetBirdEventsCmd_Follow(t *testing.T) {
	var polls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&polls, 1)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"id": "e1", "activity": "peer.login"},
		})
	}))
	defer srv.Close()

	cc := &cmdContext{cfg: netbirdCfg(t, srv.URL), runner: shell.NewMockRunner()}
	out := &bytes.Buffer{}
	p := NewHumanPrinterTo(out, &bytes.Buffer{})

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	err := netbirdEventsRunE(ctx, cc, p, true)
	require.NoError(t, err, "follow loop must exit cleanly on context cancellation")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&polls), int32(1))
}
