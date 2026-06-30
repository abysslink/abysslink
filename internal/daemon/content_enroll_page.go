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
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

// The credential-pull HTML page (DEVC-07 UX). When the QR is opened in a phone
// BROWSER (Accept: text/html), the bootstrap endpoint serves this formatted page
// — per-field Copy buttons and a Download button for the SSH key + cert —
// instead of dumping minified JSON that is impossible to use on a phone. curl /
// Shortcuts (Accept: application/json or */*) still get the raw JSON.
//
// Single-use safe: everything is embedded in this one response. Copy and
// Download run entirely client-side from the page's own DOM text — no second
// fetch (the token is already consumed), and crucially no secret value is ever
// interpolated into a JS string: the buttons read element.textContent, so the
// values live ONLY in html/template-escaped element text (no XSS/JS-injection
// surface). The page is fully self-contained: inline CSS/JS, zero external
// resources (no CDN — matches the project's no-third-party rule).

// enrollFieldLabel maps known bundle keys to human labels; unknown keys fall
// back to the raw key, so the page stays decoupled from the exact bundle shape.
var enrollFieldLabel = map[string]string{ //nolint:gochecknoglobals // static label lookup
	"device":              "Device",
	"rotated":             "Rotated",
	"ssh_command":         "Connect — SSH",
	"mosh_command":        "Connect — mosh + tmux",
	"ssh_host":            "Host",
	"ssh_user":            "User",
	"ssh_port":            "SSH port",
	"bearer":              "Bearer token",
	"push_token":          "Push token",
	"ssh_private_key_pem": "SSH private key",
	"ssh_public_key":      "Public Key",
	"ssh_certificate":     "SSH certificate",
	"ca_public_key":       "CA public key",
	"cert_not_after":      "Cert expires",
	"warning":             "Note",
}

// enrollFieldFile maps the file-importable secrets to the filename an SSH client
// expects (OpenSSH auto-loads "<key>-cert.pub" next to the key). Only these get
// a Download button.
var enrollFieldFile = map[string]string{ //nolint:gochecknoglobals // static filename lookup
	"ssh_private_key_pem": "abysslink_phone",
	"ssh_certificate":     "abysslink_phone-cert.pub",
}

// enrollFieldNote maps bundle keys to a short hint telling the user EXACTLY where
// each value goes in a phone SSH client (Termius "Paste Key" / Blink), so the
// page reads as a fill-in guide rather than an undifferentiated value dump.
var enrollFieldNote = map[string]string{ //nolint:gochecknoglobals // static hint lookup
	"ssh_private_key_pem": `Paste into the "Private Key" field (required). Or tap Download and import the file.`,
	"ssh_public_key":      `Leave the "Public Key" field empty — the certificate already carries this. Shown here only for reference.`,
	"ssh_certificate":     `Paste into the "Certificate" field. Required — it authorises the key for login.`,
	"ssh_host":            `Host / Address of the rig.`,
	"ssh_user":            `Username to log in as.`,
	"ssh_port":            `Port (default 22).`,
	"ssh_command":         `Ready-to-run: paste into any terminal SSH app to connect.`,
	"mosh_command":        `Roaming connection (survives Wi-Fi/cellular changes) that reattaches your tmux session.`,
	"bearer":              `For the abysslink notify app only — NOT your SSH client.`,
	"push_token":          `For the abysslink notify app only — NOT your SSH client.`,
	"ca_public_key":       `Server-side only: goes in sshd TrustedUserCAKeys on the rig. You don't need this on the phone.`,
	"cert_not_after":      `Your access stops working on this date — re-enroll before then.`,
	"device":              `The device name these credentials were minted for.`,
}

// enrollPageField is one rendered credential row. Guide rows (Guide=true) carry
// only a Label + Note (e.g. "leave empty") with no value/buttons.
type enrollPageField struct {
	Key   string // bundle key — used for ordering/notes; never rendered
	ID    string // DOM id (f0, f1, …) — server-controlled, never user data
	Label string
	Value string
	File   string // download filename; empty = no Download button
	Note   string // hint shown under the value (what it is / where it goes)
	Guide  bool   // true = label + note only (no value, no Copy/Download)
	NoCopy bool   // true = show the value (read-only) but no Copy/Download buttons
}

// enrollSection groups rows under a titled heading so the SSH-key import fields
// (Termius "Paste Key" order) are visually separated from connection details,
// the notify-app tokens, and advanced server-side material.
type enrollSection struct {
	Title  string
	Lead   string // optional one-line description under the title
	Fields []enrollPageField
}

// enrollPageData is the template payload.
type enrollPageData struct {
	Sections []enrollSection
}

var enrollPageTmpl = template.Must(template.New("enroll").Parse(enrollPageHTML)) //nolint:gochecknoglobals // compiled-once template

// wantsJSON reports whether the caller EXPLICITLY wants raw JSON instead of the
// formatted HTML page. HTML is the default because the link is delivered as a QR
// for a human to scan, and QR scanners / in-app webviews / some mobile browsers
// do NOT send "Accept: text/html" (often "*/*") — defaulting to HTML there was
// the bug that kept serving the raw JSON dump. A machine consumer opts into JSON
// via "?format=json" or an "Accept: application/json" that does not also ask for
// HTML (so a real browser, which sends both, still gets the page).
func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

// previewBotUAs is a focused denylist of well-known link-preview/crawler
// User-Agent tokens. When a user pastes a credential link into a chat app
// (iMessage/Slack/WhatsApp/…), that service FETCHES the URL to build a preview
// — which would otherwise burn the single-use token (and worse, deliver the
// secret bundle to the crawler's servers) before the real user opens it. We
// match these case-insensitively as substrings and serve a non-secret
// placeholder WITHOUT consuming the token.
//
// A bot that SPOOFS a real-browser UA falls through to the normal consume path
// — that is the same risk as any first-fetcher today (whoever fetches first
// wins the token), and is acceptable: this denylist handles the well-behaved
// previewers, which is the actual leak vector in practice.
var previewBotUAs = []string{ //nolint:gochecknoglobals // static denylist
	"slackbot", "facebookexternalhit", "whatsapp", "twitterbot",
	"telegrambot", "discordbot", "discord", "linkedinbot", "redditbot",
	"pinterest", "applebot", "skypeuripreview", "bingbot", "googlebot",
	"embedly", "vkshare", "preview", "crawler", "spider", "bot",
}

// isPreviewBot reports whether ua looks like a link-preview/crawler client.
// The match is a case-insensitive substring scan over previewBotUAs. An empty
// or browser UA is not a bot (returns false → the normal consume path runs).
func isPreviewBot(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)
	for _, tok := range previewBotUAs {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// writeEnrollPreviewPlaceholder serves a small, self-contained, NON-SECRET page
// to a link-preview crawler. It carries NO credential fields and NO token, is
// identical regardless of whether the requested token exists/valid/expired (so
// it is no token-existence oracle), and — crucially — is served WITHOUT the
// caller ever reaching the single-use consume, so a preview never burns the
// link nor leaks the bundle. Same dark style as the other enroll pages.
func writeEnrollPreviewPlaceholder(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(enrollPreviewHTML))
}

// writeEnrollNotFoundHTML serves a small, GENERIC "link expired or already
// used" page for a browser that opened a dead bootstrap link (expired, already
// consumed, or simply wrong) — instead of the blank white page an empty 404
// renders on a phone. It is STATIC and identical for every not-found cause, so
// it leaks no oracle (bad vs expired vs wrong-class are indistinguishable); the
// constant-work lookup already ran in the handler. Non-browser callers
// (curl/Shortcuts) keep the empty-body 404 (the BACK-09 contract is unchanged).
func writeEnrollNotFoundHTML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(enrollNotFoundHTML))
}

// writeEnrollHTML renders the bundle JSON as the formatted credential page. The
// bundle is parsed GENERICALLY in document order (a token stream, not a fixed
// struct) so the daemon never couples to the exact bundle shape. On any parse
// failure it returns an error and the caller falls back to serving JSON.
func writeEnrollHTML(w http.ResponseWriter, bundleJSON string) error {
	fields, err := parseOrderedEnrollFields(bundleJSON)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return enrollPageTmpl.Execute(w, enrollPageData{Sections: buildEnrollSections(fields)})
}

// buildEnrollSections arranges the parsed bundle rows into the SSH-client import
// flow: the key-import fields first in the exact Termius "Paste Key" order
// (Label → Private Key → Public Key → Passphrase → Certificate), then the
// connection details, then the notify-app tokens, then advanced server-side
// material. It attaches per-field notes and synthesises the guidance rows for
// the fields the user must leave empty. Any bundle key not placed by the spec is
// appended under "Advanced" so the page stays decoupled from the bundle shape
// (a newly-added bundle field still renders).
func buildEnrollSections(fields []enrollPageField) []enrollSection {
	byKey := make(map[string]enrollPageField, len(fields))
	for _, f := range fields {
		byKey[f.Key] = f
	}
	used := make(map[string]bool)
	take := func(keys ...string) []enrollPageField {
		var out []enrollPageField
		for _, k := range keys {
			if f, ok := byKey[k]; ok {
				f.Note = enrollFieldNote[k]
				out = append(out, f)
				used[k] = true
			}
		}
		return out
	}

	var sections []enrollSection

	// 1 — SSH key import, in the phone client's own field order so the user can
	// go straight down the screen. Real values (private key, certificate) are
	// Copy/Download rows; the Label is a copyable suggestion; Public Key and
	// Passphrase are guidance rows that say to leave them empty.
	keyFields := []enrollPageField{{
		ID:    "lbl",
		Label: `"Label" — any name`,
		Value: enrollSuggestedLabel(byKey),
		Note:  "A name for this key in your SSH app. Copy this suggestion or type your own.",
	}}
	keyFields = append(keyFields, take("ssh_private_key_pem")...)
	// Public Key: show the value (read-only, no Copy) so it's visible for
	// reference, with the note that Termius's field stays empty. Falls back to a
	// guidance row when an older daemon's bundle carries no public key.
	if pk, ok := byKey["ssh_public_key"]; ok {
		pk.Note = enrollFieldNote["ssh_public_key"]
		pk.NoCopy = true
		keyFields = append(keyFields, pk)
		used["ssh_public_key"] = true
	} else {
		keyFields = append(keyFields, enrollPageField{
			Guide: true, Label: `"Public Key"`,
			Note: "Leave empty — the certificate already carries the public key.",
		})
	}
	keyFields = append(keyFields, enrollPageField{
		Guide: true, Label: `"Passphrase"`,
		Note: "Leave empty — this key has no passphrase.",
	})
	keyFields = append(keyFields, take("ssh_certificate")...)
	sections = append(sections, enrollSection{
		Title:  "1 · Import the key into your SSH app",
		Lead:   `Termius / Blink → add a key ("Paste Key"), then fill its fields top to bottom:`,
		Fields: keyFields,
	})

	// 2 — Connection details / ready-to-run commands.
	if conn := take("ssh_host", "ssh_user", "ssh_port", "ssh_command", "mosh_command"); len(conn) > 0 {
		sections = append(sections, enrollSection{
			Title:  "2 · Connect to the rig",
			Lead:   "Add a host with these fields, or just run one of the commands.",
			Fields: conn,
		})
	}

	// 3 — Notify-app tokens (explicitly NOT the SSH client).
	if notify := take("bearer", "push_token"); len(notify) > 0 {
		sections = append(sections, enrollSection{
			Title:  "3 · Notify app (optional)",
			Lead:   "Only for the abysslink phone-notification app — your SSH client does not need these.",
			Fields: notify,
		})
	}

	// 4 — Advanced + any unrecognised bundle keys (decoupling).
	adv := take("ca_public_key", "cert_not_after", "device", "rotated", "warning")
	for _, f := range fields {
		if !used[f.Key] {
			f.Note = enrollFieldNote[f.Key]
			adv = append(adv, f)
			used[f.Key] = true
		}
	}
	if len(adv) > 0 {
		sections = append(sections, enrollSection{Title: "Advanced", Fields: adv})
	}

	return sections
}

// enrollSuggestedLabel builds a friendly default name for the imported key from
// the device name and rig host, e.g. "abysslink phone (rig.tailnet.ts.net)".
func enrollSuggestedLabel(byKey map[string]enrollPageField) string {
	dev := byKey["device"].Value
	if dev == "" {
		dev = "phone"
	}
	if host := byKey["ssh_host"].Value; host != "" {
		return "abysslink " + dev + " (" + host + ")"
	}
	return "abysslink " + dev
}

// parseOrderedEnrollFields decodes a flat JSON object into label/value rows in
// document order via a json.Decoder token stream (Go maps lose order, and order
// matters on a credential page — key/cert first). Non-string values are
// stringified. Nested objects/arrays are skipped (the bundle is flat).
func parseOrderedEnrollFields(raw string) ([]enrollPageField, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("daemon: enroll page: bundle is not a JSON object")
	}
	var fields []enrollPageField
	for i := 0; dec.More(); i++ {
		keyTok, kerr := dec.Token()
		if kerr != nil {
			return nil, kerr
		}
		key, _ := keyTok.(string)
		var val any
		if derr := dec.Decode(&val); derr != nil {
			return nil, derr
		}
		label := enrollFieldLabel[key]
		if label == "" {
			label = key
		}
		fields = append(fields, enrollPageField{
			Key:   key,
			ID:    "f" + strconv.Itoa(i),
			Label: label,
			Value: stringifyEnrollValue(val),
			File:  enrollFieldFile[key],
		})
	}
	return fields, nil
}

// stringifyEnrollValue renders a decoded JSON scalar for display. Strings pass
// through verbatim (the PEM's real newlines survive — JSON decode already turned
// \n into newlines); other scalars are formatted; objects/arrays (not expected
// in a flat bundle) render empty.
func stringifyEnrollValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return ""
	}
}

// enrollPageHTML is the self-contained page. html/template applies
// context-aware escaping: {{.Value}} is HTML-text-escaped inside <pre>, and the
// {{.ID}}/{{.File}} interpolations sit in onclick JS-string context (both are
// server-controlled safe tokens). The copy/download handlers read
// element.textContent — secret values never enter a JS string literal.
// enrollNotFoundHTML is the static dead-link page (see writeEnrollNotFoundHTML).
const enrollNotFoundHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Link expired</title>
<style>:root{color-scheme:dark}
body{margin:0;padding:24px;background:#0b0e14;color:#d7dbe0;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
h1{font-size:20px;margin:0 0 12px}
code{background:#11161f;border:1px solid #222b38;border-radius:6px;padding:2px 6px;font:14px ui-monospace,Menlo,monospace}
p{margin:0 0 12px}</style></head>
<body>
<h1>Link expired or already used</h1>
<p>Credential links are single-use and short-lived — this one has already been opened or has expired.</p>
<p>On your rig, run <code>abysslink enroll phone --apply</code> and scan the new QR (each QR is a fresh, one-time link — don't reuse a screenshot).</p>
</body></html>`

// enrollPreviewHTML is the static, NON-SECRET placeholder served to link-preview
// crawlers (see writeEnrollPreviewPlaceholder). It carries no credentials and no
// token, so a chat-app preview can never burn the single-use link nor receive
// the bundle.
const enrollPreviewHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Abysslink credential link</title>
<style>:root{color-scheme:dark}
body{margin:0;padding:24px;background:#0b0e14;color:#d7dbe0;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
h1{font-size:20px;margin:0 0 12px}
p{margin:0 0 12px}</style></head>
<body>
<h1>Abysslink credential link</h1>
<p>Open this on the device you're enrolling. It's a one-time, single-use credential link — this preview did not consume it.</p>
</body></html>`

const enrollPageHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Abysslink device credentials</title>
<style>
:root{color-scheme:dark}
body{margin:0;padding:16px;background:#0b0e14;color:#d7dbe0;font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
h1{font-size:19px;margin:0 0 4px}
.warn{background:#3a2a00;color:#ffd27a;border:1px solid #6b4f10;border-radius:8px;padding:10px 12px;margin:10px 0 18px;font-size:13px}
section{margin:0 0 16px}
.row{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px}
h2{font-size:13px;font-weight:600;color:#9aa4b2;margin:0;text-transform:uppercase;letter-spacing:.04em}
.btns{display:flex;gap:6px;flex-shrink:0}
button{background:#1f6feb;color:#fff;border:0;border-radius:7px;padding:7px 12px;font-size:13px;font-weight:600}
button.sec{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
button:active{opacity:.7}
pre.val{margin:0;background:#11161f;border:1px solid #222b38;border-radius:8px;padding:10px 12px;font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-all;-webkit-user-select:all;user-select:all}
.sectitle{font-size:12px;font-weight:700;color:#cfd6df;margin:22px 0 2px;letter-spacing:.03em}
.lead{font-size:12px;color:#7d8794;margin:0 0 12px}
.note{font-size:12px;color:#8b95a3;margin:5px 0 0}
section.guide{background:#0e1320;border:1px dashed #2a3342;border-radius:8px;padding:8px 12px}
section.guide h2{color:#7d8794}
</style></head><body>
<h1>Device credentials</h1>
<div class="warn">Shown once — copy what you need now. This page cannot be reloaded (the link is single-use and already consumed).</div>
{{range .Sections}}
<div class="sectitle">{{.Title}}</div>{{if .Lead}}
<div class="lead">{{.Lead}}</div>{{end}}
{{range .Fields}}<section{{if .Guide}} class="guide"{{end}}>
<div class="row"><h2>{{.Label}}</h2>{{if and (not .Guide) (not .NoCopy)}}<span class="btns">
<button onclick="cp('{{.ID}}',this)">Copy</button>{{if .File}}
<button class="sec" onclick="dl('{{.ID}}','{{.File}}')">Download</button>{{end}}
</span>{{end}}</div>{{if not .Guide}}
<pre class="val" id="{{.ID}}">{{.Value}}</pre>{{end}}{{if .Note}}
<div class="note">{{.Note}}</div>{{end}}
</section>
{{end}}{{end}}
<script>
function cp(id,b){var t=document.getElementById(id).textContent;
function ok(){var o=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=o},1200)}
if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(ok,function(){})}
else{var r=document.createRange();r.selectNodeContents(document.getElementById(id));var s=getSelection();s.removeAllRanges();s.addRange(r);try{document.execCommand('copy');ok()}catch(e){}}}
function dl(id,name){var t=document.getElementById(id).textContent;
var u=URL.createObjectURL(new Blob([t],{type:'application/octet-stream'}));
var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u)}
</script>
</body></html>`
