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

package metrics

import (
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry is the metrics interface every module uses. The concrete in-memory
// implementation is created via NewMemRegistry; NoopRegistry is the nil-safe
// default wired into modules.Deps when metrics are disabled or unavailable.
type Registry interface {
	// Counter returns (or creates) a monotonically increasing counter for the
	// given name and label set.
	Counter(name, help string, labels map[string]string) Counter
	// Gauge returns (or creates) an arbitrary-value gauge for the given name and
	// label set.
	Gauge(name, help string, labels map[string]string) Gauge
	// Snapshot returns all metric families for exposition, sorted by name.
	Snapshot() []MetricFamily
}

// Counter is a monotonically increasing metric.
type Counter interface {
	Inc()
	Add(delta int64)
	Value() float64
}

// Gauge is an arbitrary-value metric.
type Gauge interface {
	Set(v float64)
	Value() float64
}

// MetricFamily groups all samples for one metric name.
type MetricFamily struct {
	Name    string
	Help    string
	Type    string // "counter" or "gauge"
	Samples []Sample
}

// Sample is a single time-series data point.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// NoopRegistry is a zero-value Registry whose methods are no-ops. It is the
// nil-safe default in modules.Deps: modules call Registry methods
// unconditionally (never nil-check before calling) and the Noop implementation
// guarantees no panics when metrics are disabled.
type NoopRegistry struct{}

// Counter returns a no-op counter.
func (NoopRegistry) Counter(_, _ string, _ map[string]string) Counter { return noopCounter{} }

// Gauge returns a no-op gauge.
func (NoopRegistry) Gauge(_, _ string, _ map[string]string) Gauge { return noopGauge{} }

// Snapshot returns nil; a NoopRegistry holds no state.
func (NoopRegistry) Snapshot() []MetricFamily { return nil }

type noopCounter struct{}

func (noopCounter) Inc()           {}
func (noopCounter) Add(_ int64)    {}
func (noopCounter) Value() float64 { return 0 }

type noopGauge struct{}

func (noopGauge) Set(_ float64)  {}
func (noopGauge) Value() float64 { return 0 }

// metricEntry holds the state for a single (name, label-set) series. The value
// is stored as an int64 bit-pattern: counters use it as a plain integer count,
// gauges store math.Float64bits of the current value. Access is atomic so the
// hot path (Inc/Add/Set) takes no lock.
type metricEntry struct {
	name       string
	help       string
	metricType string // "counter" or "gauge"
	labels     map[string]string
	value      atomic.Int64
}

// memRegistry is the in-memory Registry implementation. The map is guarded by a
// RWMutex for create/snapshot; per-entry value mutation is lock-free (atomic).
type memRegistry struct {
	mu      sync.RWMutex
	entries map[string]*metricEntry
}

// NewMemRegistry returns a new in-memory Registry.
func NewMemRegistry() Registry {
	return &memRegistry{entries: make(map[string]*metricEntry)}
}

// canonicalKey builds a deterministic map key from a metric name and its label
// set: "name|k1=v1|k2=v2" with keys sorted for stability.
func canonicalKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	for _, k := range keys {
		b.WriteString("|")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(labels[k])
	}
	return b.String()
}

// copyLabels returns a defensive copy of labels so later caller mutations cannot
// alter the registered series.
func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}

// getOrCreate returns the existing entry for (name, labels) or creates one with
// the given type. If an entry already exists, its stored type and help win.
func (r *memRegistry) getOrCreate(name, help, metricType string, labels map[string]string) *metricEntry {
	key := canonicalKey(name, labels)

	r.mu.RLock()
	e, ok := r.entries[key]
	r.mu.RUnlock()
	if ok {
		return e
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok = r.entries[key]; ok {
		return e
	}
	e = &metricEntry{
		name:       name,
		help:       help,
		metricType: metricType,
		labels:     copyLabels(labels),
	}
	r.entries[key] = e
	return e
}

// Counter returns (or creates) a counter for (name, labels).
func (r *memRegistry) Counter(name, help string, labels map[string]string) Counter {
	return &memCounter{entry: r.getOrCreate(name, help, "counter", labels)}
}

// Gauge returns (or creates) a gauge for (name, labels).
func (r *memRegistry) Gauge(name, help string, labels map[string]string) Gauge {
	return &memGauge{entry: r.getOrCreate(name, help, "gauge", labels)}
}

// Snapshot returns all metric families, grouped by name and sorted by name for
// deterministic exposition ordering.
func (r *memRegistry) Snapshot() []MetricFamily {
	r.mu.RLock()
	defer r.mu.RUnlock()

	byName := make(map[string]*MetricFamily)
	for _, e := range r.entries {
		fam, ok := byName[e.name]
		if !ok {
			fam = &MetricFamily{Name: e.name, Help: e.help, Type: e.metricType}
			byName[e.name] = fam
		}
		fam.Samples = append(fam.Samples, Sample{
			Labels: copyLabels(e.labels),
			Value:  e.read(),
		})
	}

	out := make([]MetricFamily, 0, len(byName))
	for _, fam := range byName {
		out = append(out, *fam)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// read returns the entry's current value as a float64, interpreting the stored
// int64 according to the metric type.
func (e *metricEntry) read() float64 {
	raw := e.value.Load()
	if e.metricType == "gauge" {
		return math.Float64frombits(uint64(raw))
	}
	return float64(raw)
}

type memCounter struct{ entry *metricEntry }

func (c *memCounter) Inc()              { c.entry.value.Add(1) }
func (c *memCounter) Add(delta int64)   { c.entry.value.Add(delta) }
func (c *memCounter) Value() float64    { return float64(c.entry.value.Load()) }

type memGauge struct{ entry *metricEntry }

func (g *memGauge) Set(v float64)  { g.entry.value.Store(int64(math.Float64bits(v))) }
func (g *memGauge) Value() float64 { return math.Float64frombits(uint64(g.entry.value.Load())) }
