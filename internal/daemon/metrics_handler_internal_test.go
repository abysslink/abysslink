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

package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMetricsHandlerNilRegistry is the WR-04 regression: a nil Registry must not
// panic the handler (CLAUDE.md: no panics in normal control flow). It returns a
// 200 with the strict content type and an empty body.
func TestMetricsHandlerNilRegistry(t *testing.T) {
	h := metricsHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	assert.NotPanics(t, func() { h(rec, req) })

	res := rec.Result()
	defer res.Body.Close() //nolint:errcheck
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, metricsContentType, res.Header.Get("Content-Type"))
	assert.Empty(t, rec.Body.String(), "nil registry yields an empty exposition")
}
