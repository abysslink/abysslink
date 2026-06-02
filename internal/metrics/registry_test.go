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

package metrics_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/metrics"
)

func TestNoopRegistryNilSafe(t *testing.T) {
	var reg metrics.Registry = metrics.NoopRegistry{}
	c := reg.Counter("c", "help", nil)
	require.NotNil(t, c)
	assert.NotPanics(t, func() {
		c.Inc()
		c.Add(5)
		_ = c.Value()
	})
	assert.Equal(t, 0.0, c.Value())
}

func TestNoopRegistryGauge(t *testing.T) {
	var reg metrics.Registry = metrics.NoopRegistry{}
	g := reg.Gauge("g", "help", nil)
	require.NotNil(t, g)
	assert.NotPanics(t, func() {
		g.Set(3.14)
	})
	assert.Equal(t, 0.0, g.Value())
}

func TestNoopRegistrySnapshot(t *testing.T) {
	var reg metrics.Registry = metrics.NoopRegistry{}
	var snap []metrics.MetricFamily
	assert.NotPanics(t, func() {
		snap = reg.Snapshot()
	})
	assert.Len(t, snap, 0)
}

func TestMemRegistryCounter(t *testing.T) {
	reg := metrics.NewMemRegistry()
	c := reg.Counter("req", "help", map[string]string{"result": "ok"})
	c.Inc()
	c.Inc()
	c.Inc()

	snap := reg.Snapshot()
	require.Len(t, snap, 1)
	fam := snap[0]
	assert.Equal(t, "req", fam.Name)
	assert.Equal(t, "counter", fam.Type)
	require.Len(t, fam.Samples, 1)
	assert.Equal(t, 3.0, fam.Samples[0].Value)
	assert.Equal(t, "ok", fam.Samples[0].Labels["result"])
}

func TestMemRegistryGauge(t *testing.T) {
	reg := metrics.NewMemRegistry()
	g := reg.Gauge("up", "help", nil)
	g.Set(1.0)

	snap := reg.Snapshot()
	require.Len(t, snap, 1)
	fam := snap[0]
	assert.Equal(t, "up", fam.Name)
	assert.Equal(t, "gauge", fam.Type)
	require.Len(t, fam.Samples, 1)
	assert.Equal(t, 1.0, fam.Samples[0].Value)
}

func TestMemRegistryConcurrent(t *testing.T) {
	reg := metrics.NewMemRegistry()
	c := reg.Counter("hits", "help", nil)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c.Inc()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1000.0, c.Value())
}

func TestMemRegistrySameKeyReturnsIdentical(t *testing.T) {
	reg := metrics.NewMemRegistry()
	labels := map[string]string{"result": "ok"}
	c1 := reg.Counter("req", "help", labels)
	c1.Inc()
	c2 := reg.Counter("req", "help", labels)
	assert.Equal(t, 1.0, c2.Value(), "second lookup must observe the first increment")
	c2.Inc()
	assert.Equal(t, 2.0, c1.Value(), "both handles refer to the same logical counter")
}

// TestMemRegistryTypeCollisionValueIsTypeAware is the WR-06 regression: when a
// name is first registered as a gauge and then fetched via Counter(),
// getOrCreate returns the existing gauge entry. The counter handle's Value()
// must reinterpret the stored bits per the entry's real (gauge) type — matching
// Snapshot — rather than reading the Float64bits storage as a raw integer.
func TestMemRegistryTypeCollisionValueIsTypeAware(t *testing.T) {
	reg := metrics.NewMemRegistry()
	g := reg.Gauge("collide", "help", nil)
	g.Set(3.5)

	// Fetch the same name as a counter — getOrCreate returns the gauge entry.
	c := reg.Counter("collide", "help", nil)

	// Both accessors must agree with the type-aware Snapshot value (3.5), not a
	// garbage integer reinterpretation of the float bit pattern.
	assert.Equal(t, 3.5, c.Value(), "counter handle to a gauge entry must read the gauge value (WR-06)")
	assert.Equal(t, 3.5, g.Value())

	snap := reg.Snapshot()
	require.Len(t, snap, 1)
	require.Len(t, snap[0].Samples, 1)
	assert.Equal(t, 3.5, snap[0].Samples[0].Value)
}
