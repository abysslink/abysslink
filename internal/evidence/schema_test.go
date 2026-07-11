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

package evidence_test

// This test asserts that docs/schemas/alevidence-v1.schema.json is a FAITHFUL,
// non-drifting contract for internal/evidence.Manifest — the object emitted by
// `abysslink audit evidence --json` and shipped as manifest.json inside every
// .alevidence bundle.
//
// VALIDATION APPROACH — dependency-free structural validation.
// No JSON-Schema validation library is present in go.mod (direct or transitive),
// and the DESIGN/CLAUDE.md dependency discipline forbids pulling a heavyweight
// validator in just for a test. So this file implements a small, purpose-built
// walker over the schema + the marshaled manifest that checks the parts of the
// contract that actually matter for ingest:
//
//	(a) every schema "required" key is present in the marshaled JSON (per object);
//	(b) every marshaled key exists in the schema "properties" — because the schema
//	    declares additionalProperties:false at every object level, so a field the
//	    struct emits but the schema forgot is caught here (byte-faithfulness);
//	(c) the const / enum / pattern / min / max constraints hold for the marshaled
//	    values (alevidence_v==1, sha256 fields match ^[0-9a-f]{64}$, algo=="ed25519",
//	    counter_status in its enum, key_fingerprint/public_key patterns, etc.);
//	(d) each value's JSON kind matches the schema "type" (object/array/string/
//	    number/integer/boolean), so a same-name field whose Go type changed is
//	    caught even without a const/enum/pattern constraint.
//
// LIMITATION (stated honestly): this is NOT a full JSON-Schema validator. It does
// not implement $ref/$defs, allOf/anyOf/oneOf, conditional (if/then), format
// assertion (date-time is validated as a plain string, not parsed), or numeric
// multipleOf. The schema deliberately uses only the keywords exercised above, so
// the walker covers 100% of what this schema declares — but a future schema that
// reaches for an unsupported keyword would be silently under-checked. Keep the
// schema within the supported keyword set, or upgrade to a real validator.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/abysslink/abysslink/internal/evidence"
)

// schemaPath is the versioned ingest contract, relative to this package dir.
const schemaPath = "../../docs/schemas/alevidence-v1.schema.json"

// loadSchema parses the schema file and asserts it is valid JSON (deliverable 2).
func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(schemaPath))
	require.NoError(t, err, "schema file must exist at %s", schemaPath)
	var schema map[string]any
	require.NoError(t, json.Unmarshal(raw, &schema), "schema file must be valid JSON")
	return schema
}

// marshalToAny round-trips v through JSON so the checked value is exactly the
// bytes a consumer sees (omitempty fields absent, numbers as float64).
func marshalToAny(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var out any
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

// TestSchema_MatchesRealManifest validates a manifest produced by the real
// Create path (optional fields absent) against the schema.
func TestSchema_MatchesRealManifest(t *testing.T) {
	logPath, kc := seededLog(t, 5)
	var buf bytes.Buffer
	m, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &buf)
	require.NoError(t, err)

	schema := loadSchema(t)
	data := marshalToAny(t, m)

	// The clean, full-history bundle must OMIT the omitempty fields — this proves
	// they are genuinely optional (not in the schema's "required" set).
	top, ok := data.(map[string]any)
	require.True(t, ok)
	rng, ok := top["range"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, rng, "since", "empty Since must be omitted (omitempty)")
	assert.NotContains(t, rng, "until", "empty Until must be omitted (omitempty)")
	chain, ok := top["chain"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, chain, "reason", "empty Reason must be omitted (omitempty)")

	validateNode(t, schema, data, "$")
}

// TestSchema_MatchesFullManifest validates a manifest with EVERY optional field
// populated (range.since, range.until, chain.reason) so the schema's optional
// properties are exercised too. It starts from a REAL Create'd manifest so the
// pattern-constrained fields (hashes, public_key, fingerprint) stay genuine, then
// fills the omitempty fields by hand.
func TestSchema_MatchesFullManifest(t *testing.T) {
	logPath, kc := seededLog(t, 3)
	var buf bytes.Buffer
	m, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &buf)
	require.NoError(t, err)

	m.Range.Since = "2026-07-01T00:00:00Z"
	m.Range.Until = "2026-07-09T00:00:00Z"
	m.Chain.CounterStatus = "mismatch" // exercise a non-"verified" enum member
	m.Chain.Reason = "counter exceeds entry count"

	schema := loadSchema(t)
	data := marshalToAny(t, m)

	// All optional fields must now be PRESENT (proves they round-trip into schema).
	top := data.(map[string]any)
	rng := top["range"].(map[string]any)
	assert.Contains(t, rng, "since")
	assert.Contains(t, rng, "until")
	assert.Contains(t, top["chain"].(map[string]any), "reason")

	validateNode(t, schema, data, "$")
}

// TestSchema_PublicKeyPatternMatchesRealKey guards the signing.public_key pattern
// against a REAL ed25519 public key (base64), not a hand-crafted literal.
func TestSchema_PublicKeyPatternMatchesRealKey(t *testing.T) {
	logPath, kc := seededLog(t, 1)
	var buf bytes.Buffer
	m, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &buf)
	require.NoError(t, err)

	schema := loadSchema(t)
	pat := stringLeaf(t, schema, "properties", "signing", "properties", "public_key")["pattern"].(string)
	assert.Regexp(t, regexp.MustCompile(pat), m.Signing.PublicKey,
		"schema public_key pattern must match a real ed25519 public key")
	fpPat := stringLeaf(t, schema, "properties", "signing", "properties", "key_fingerprint")["pattern"].(string)
	assert.Regexp(t, regexp.MustCompile(fpPat), m.Signing.Fingerprint,
		"schema key_fingerprint pattern must match a real fingerprint")
}

// TestSchema_VersionDriftGuard is the tripwire: if the struct's format version
// bumps (or Create stops emitting 1), the schema's alevidence_v const no longer
// matches the value a real manifest carries, and this fails. Bump the schema (or
// ship a new versioned schema) deliberately when that happens.
func TestSchema_VersionDriftGuard(t *testing.T) {
	logPath, kc := seededLog(t, 1)
	var buf bytes.Buffer
	m, err := evidence.Create(context.Background(), kc, makeOpts(logPath), &buf)
	require.NoError(t, err)

	schema := loadSchema(t)
	verSchema := stringLeaf(t, schema, "properties", "alevidence_v")
	constVal, ok := verSchema["const"].(float64)
	require.True(t, ok, "alevidence_v must declare a numeric const")
	assert.Equal(t, float64(m.FormatVersion), constVal,
		"schema alevidence_v const (%v) must equal the real Manifest.FormatVersion (%d) — bump the schema on a version change",
		constVal, m.FormatVersion)
}

// stringLeaf walks nested map keys and returns the leaf object (a schema node).
func stringLeaf(t *testing.T, node map[string]any, keys ...string) map[string]any {
	t.Helper()
	cur := node
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		require.True(t, ok, "schema path missing key %q", k)
		cur = next
	}
	return cur
}

// --- dependency-free structural validator (see file header for scope/limits) ---

// validateNode dispatches on the schema node's declared "type", applying the
// generic const/enum/pattern checks at every node first.
func validateNode(t *testing.T, schema map[string]any, data any, path string) {
	t.Helper()
	checkConst(t, schema, data, path)
	checkEnum(t, schema, data, path)
	checkPattern(t, schema, data, path)
	// Assert the marshaled value's JSON kind matches the schema's declared
	// "type" BEFORE dispatching, so a same-name field whose Go type changed
	// (e.g. int->string or bool->string) is caught even when it carries no
	// const/enum/pattern constraint — closing the last realistic drift gap for
	// the constraint-free counters/flags.
	if st, ok := schema["type"].(string); ok {
		assertJSONKind(t, st, data, path)
	}
	switch schema["type"] {
	case "object":
		validateObject(t, schema, data, path)
	case "integer", "number":
		checkNumberBounds(t, schema, data, path)
	}
}

// assertJSONKind fails if data's decoded JSON kind does not match the schema
// "type" string. encoding/json decodes every JSON number to float64, so
// "integer" additionally requires a whole value.
func assertJSONKind(t *testing.T, schemaType string, data any, path string) {
	t.Helper()
	switch schemaType {
	case "object":
		_, ok := data.(map[string]any)
		assert.True(t, ok, "%s: schema type object but marshaled value is %T", path, data)
	case "array":
		_, ok := data.([]any)
		assert.True(t, ok, "%s: schema type array but marshaled value is %T", path, data)
	case "string":
		_, ok := data.(string)
		assert.True(t, ok, "%s: schema type string but marshaled value is %T", path, data)
	case "boolean":
		_, ok := data.(bool)
		assert.True(t, ok, "%s: schema type boolean but marshaled value is %T", path, data)
	case "number":
		_, ok := data.(float64)
		assert.True(t, ok, "%s: schema type number but marshaled value is %T", path, data)
	case "integer":
		f, ok := data.(float64)
		assert.True(t, ok, "%s: schema type integer but marshaled value is %T", path, data)
		if ok {
			assert.True(t, float64(int64(f)) == f, "%s: schema type integer but marshaled value %v is not whole", path, f)
		}
	}
}

// validateObject enforces required keys, additionalProperties:false, and recurses
// into declared properties.
func validateObject(t *testing.T, schema map[string]any, data any, path string) {
	t.Helper()
	m, ok := data.(map[string]any)
	require.True(t, ok, "%s: expected object, got %T", path, data)
	props := mapOf(schema["properties"])

	for _, req := range sliceOf(schema["required"]) {
		key, _ := req.(string)
		_, present := m[key]
		assert.True(t, present, "%s: schema-required key %q is absent from the marshaled manifest", path, key)
	}

	if extra, ok := schema["additionalProperties"].(bool); ok && !extra {
		for k := range m {
			_, declared := props[k]
			assert.True(t, declared,
				"%s: marshaled key %q is not declared in schema properties (additionalProperties:false) — schema drift", path, k)
		}
	}

	for k, v := range m {
		if ps, ok := props[k].(map[string]any); ok {
			validateNode(t, ps, v, path+"."+k)
		}
	}
}

// checkConst asserts data equals the schema "const", when present.
func checkConst(t *testing.T, schema map[string]any, data any, path string) {
	t.Helper()
	want, ok := schema["const"]
	if !ok {
		return
	}
	assert.EqualValues(t, want, data, "%s: value %v must equal const %v", path, data, want)
}

// checkEnum asserts data is one of the schema "enum" members, when present.
func checkEnum(t *testing.T, schema map[string]any, data any, path string) {
	t.Helper()
	members := sliceOf(schema["enum"])
	if members == nil {
		return
	}
	for _, e := range members {
		if e == data {
			return
		}
	}
	assert.Failf(t, "enum violation", "%s: value %v is not in enum %v", path, data, members)
}

// checkPattern asserts a string data value matches the schema "pattern", when present.
func checkPattern(t *testing.T, schema map[string]any, data any, path string) {
	t.Helper()
	pat, ok := schema["pattern"].(string)
	if !ok {
		return
	}
	s, ok := data.(string)
	require.True(t, ok, "%s: pattern applies to a non-string value %T", path, data)
	assert.Regexp(t, regexp.MustCompile(pat), s, "%s: value %q must match /%s/", path, s, pat)
}

// checkNumberBounds asserts minimum/maximum, when present.
func checkNumberBounds(t *testing.T, schema map[string]any, data any, path string) {
	t.Helper()
	n, ok := data.(float64)
	if !ok {
		return
	}
	if min, ok := schema["minimum"].(float64); ok {
		assert.GreaterOrEqual(t, n, min, "%s: value %v below minimum %v", path, n, min)
	}
	if max, ok := schema["maximum"].(float64); ok {
		assert.LessOrEqual(t, n, max, "%s: value %v above maximum %v", path, n, max)
	}
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func sliceOf(v any) []any {
	s, _ := v.([]any)
	return s
}
