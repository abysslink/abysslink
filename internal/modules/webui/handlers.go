//go:build webui

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

package webui

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/abysslink/abysslink/internal/audit"
	"github.com/abysslink/abysslink/internal/modules"
)

// auditPageSize is the number of audit entries shown per page (UI-SPEC View 3).
const auditPageSize = 200

// statusProvider yields the fleet-status snapshot the dashboard renders. It is
// an interface seam so the daemon injects the real status source and tests
// inject a stub without a live daemon socket.
type statusProvider interface {
	FleetStatus(ctx context.Context) (online, total int, rigs []rigRow)
}

// doctorProvider yields the current doctor findings. The daemon injects the
// real check runner; tests inject a fixed slice.
type doctorProvider interface {
	DoctorFindings(ctx context.Context) []modules.Finding
}

// RigStatusRow is the EXPORTED, presentation-free fleet-status row a status
// provider returns. The daemon entrypoint (package main, //go:build webui)
// builds these from the real status source; this package projects them to the
// internal rigRow (which carries CSS classes). Keeping the exported type free
// of CSS keeps the boundary clean: the entrypoint never imports webui CSS
// conventions, and webui never imports internal/cli.
//
// Reachable / Lock are honest enums: "online"|"offline"|"unknown" and
// "locked"|"unlocked"|"" (empty = N/A). A provider MUST NOT fabricate "online"
// when it could not probe (WR-05) — it passes "unknown" and the dashboard
// renders the unknown dot.
type RigStatusRow struct {
	Name       string
	Reachable  string // "online" | "offline" | "unknown"
	Lock       string // "locked" | "unlocked" | "" (N/A)
	LastSeen   string // relative time, e.g. "2m ago"; "" = N/A
	CertDays   int    // days until cert expiry; only used when HasCert is true
	HasCert    bool   // false = cert expiry unknown (render N/A, never "0d")
	IsLocalRig bool
}

// StatusFunc is an EXPORTED adapter that lets the daemon entrypoint supply the
// fleet-status snapshot as a plain function (over the exported RigStatusRow
// type) without implementing the unexported statusProvider interface. The webui
// package converts the rows to its internal rigRow presentation.
type StatusFunc func(ctx context.Context) (online, total int, rigs []RigStatusRow)

// DoctorFunc is an EXPORTED adapter for the doctor findings source. modules.Finding
// is already a neutral (CSS-free) type, so it is returned directly.
type DoctorFunc func(ctx context.Context) []modules.Finding

// statusFuncAdapter bridges a StatusFunc to the unexported statusProvider,
// converting exported RigStatusRow values to internal presentation rigRows.
type statusFuncAdapter struct{ fn StatusFunc }

func (a statusFuncAdapter) FleetStatus(ctx context.Context) (int, int, []rigRow) {
	online, total, rows := a.fn(ctx)
	out := make([]rigRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, projectRigRow(r))
	}
	return online, total, out
}

// doctorFuncAdapter bridges a DoctorFunc to the unexported doctorProvider.
type doctorFuncAdapter struct{ fn DoctorFunc }

func (a doctorFuncAdapter) DoctorFindings(ctx context.Context) []modules.Finding {
	return a.fn(ctx)
}

// projectRigRow maps an exported, CSS-free RigStatusRow to the internal rigRow,
// resolving every visual distinction to a CSS class string in Go (WEB-06: never
// an inline style). Honest enums map to honest classes — "unknown" reachability
// becomes dot-unknown, an absent cert becomes lock/cert N/A, never a fabricated
// "online" or "0d".
func projectRigRow(r RigStatusRow) rigRow {
	statusClass, statusLabel := "dot-unknown", "unknown"
	switch r.Reachable {
	case "online":
		statusClass, statusLabel = "dot-online", "online"
	case "offline":
		statusClass, statusLabel = "dot-offline", "offline"
	}

	lockClass, lockStatus := "lock-na", "N/A"
	switch r.Lock {
	case "locked":
		lockClass, lockStatus = "lock-ok", "Locked"
	case "unlocked":
		lockClass, lockStatus = "lock-warn", "Unlocked"
	}

	certClass, certDays := "", "N/A"
	if r.HasCert {
		certDays = strconv.Itoa(r.CertDays) + "d"
		switch {
		case r.CertDays < 7:
			certClass = "cert-fatal"
		case r.CertDays < 30:
			certClass = "cert-warn"
		}
	}

	return rigRow{
		Name:        r.Name,
		StatusClass: statusClass,
		StatusLabel: statusLabel,
		LastSeen:    r.LastSeen,
		CertClass:   certClass,
		CertDays:    certDays,
		LockClass:   lockClass,
		LockStatus:  lockStatus,
	}
}

// HandlerDeps are the injected dependencies for the dashboard handlers. Keeping
// them in a struct makes the wiring (daemon seam, Plan 04) and the tests
// symmetric.
type HandlerDeps struct {
	Status       statusProvider
	Doctor       doctorProvider
	Ring         *NotifyRingBuffer
	AuditLogPath string
	RigHostname  string
	// AllowNotify mirrors webui.allow_notify. When true the notify view renders
	// the scaffolded POST form (with its CSRF token); when false (the default,
	// WEB-05) the form is omitted entirely so the only mutation path stays locked.
	AllowNotify bool
}

// Handlers holds the parsed template sets and injected dependencies for every
// dashboard route. Templates are parsed once at construction; a parse error is
// a programmer error surfaced from NewHandlers (fatal at the daemon seam).
type Handlers struct {
	deps HandlerDeps

	// One template set per full-page view (base.html + that view). They cannot
	// share a single set because every view defines the "content" block.
	statusTmpl *template.Template
	doctorTmpl *template.Template
	auditTmpl  *template.Template
	notifyTmpl *template.Template
	errorTmpl  *template.Template
}

// --- template data structs ---

// rigRow is one row of the fleet-status table. Every visual distinction is a
// CSS class string resolved in Go, never an inline style (WEB-06).
type rigRow struct {
	Name        string
	StatusClass string // dot-online | dot-offline | dot-unknown
	StatusLabel string // online | offline | unknown
	LastSeen    string // relative time, e.g. "2m ago"
	CertClass   string // "" | cert-warn | cert-fatal
	CertDays    string // e.g. "90d"
	LockClass   string // lock-ok | lock-warn | lock-na
	LockStatus  string // Locked | Unlocked | N/A
}

// statusData is the fleet-status template payload.
type statusData struct {
	pageData
	Online    int
	Total     int
	LastCheck string
	Rigs      []rigRow
}

// findingRow is one doctor finding projected with its badge presentation. The
// badge class/text are computed in Go so the template stays free of helper
// funcs (and of severity-int branching).
type findingRow struct {
	Check      string
	Message    string
	BadgeClass string // badge-fatal | badge-warn | badge-ok
	BadgeText  string // FATAL | WARN | PASS
}

// doctorGroup is a severity-grouped collapsible section.
type doctorGroup struct {
	Label         string // FATAL | WARNING | OK
	SeverityClass string // severity-fatal | severity-warn | severity-ok
	Open          bool
	Findings      []findingRow
}

// doctorData is the doctor template payload.
type doctorData struct {
	pageData
	Groups []doctorGroup
}

// auditData is the audit-timeline template payload. Entries is the projection
// struct slice — never []audit.Entry (WEB-07).
type auditData struct {
	pageData
	Entries  []AuditEntryView
	NextPage int // 0 means no further page
}

// notifyRow is one notify-history row with its priority badge class.
type notifyRow struct {
	Time          string
	Title         string
	Topic         string
	Priority      string
	PriorityClass string // badge-priority-high | -default | -low
}

// notifyData is the notify-history template payload.
type notifyData struct {
	pageData
	Events []notifyRow
	// AllowNotify gates whether the scaffolded POST form is rendered (WEB-05).
	AllowNotify bool
}

// pageData carries the shell fields every full-page view needs for base.html.
type pageData struct {
	HTMXIntegrity string
	LoginName     string
	ActiveView    string
	RigHostname   string
}

// errorData is the error-page payload.
type errorData struct {
	pageData
	Heading string
	Message string
}

// NewHandlers parses every template set and returns the wired Handlers. A
// template parse failure is returned as an error so the daemon entrypoint can
// fail loudly at startup (programmer error, not a runtime condition).
func NewHandlers(deps HandlerDeps) (*Handlers, error) {
	parse := func(view string) (*template.Template, error) {
		t, err := template.New("base.html").ParseFS(embedFS, "templates/base.html", "templates/"+view)
		if err != nil {
			return nil, fmt.Errorf("webui: parse template %s: %w", view, err)
		}
		return t, nil
	}

	h := &Handlers{deps: deps}
	var err error
	if h.statusTmpl, err = parse("status.html"); err != nil {
		return nil, err
	}
	if h.doctorTmpl, err = parse("doctor.html"); err != nil {
		return nil, err
	}
	if h.auditTmpl, err = parse("audit.html"); err != nil {
		return nil, err
	}
	if h.notifyTmpl, err = parse("notify.html"); err != nil {
		return nil, err
	}
	if h.errorTmpl, err = parse("error.html"); err != nil {
		return nil, err
	}
	return h, nil
}

// Register wires every dashboard route onto mux. Only safe GET routes are
// registered here; the read-only gate (middleware.go) is the authoritative
// mutation guard. ServeStaticAssets serves the embedded JS/CSS under /static/.
func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.handleRoot)
	mux.HandleFunc("GET /status-fragment", h.handleStatusFragment)
	mux.HandleFunc("GET /doctor", h.handleDoctor)
	mux.HandleFunc("GET /audit", h.handleAudit)
	mux.HandleFunc("GET /notify", h.handleNotify)
	// allow_notify mutation path (scaffolded; full dispatch deferred to Phase 20+).
	mux.HandleFunc("POST /notify", h.handleNotifyPost)
	ServeStaticAssets(mux)
}

// newPageData builds the shell fields for a full-page render of the given view.
func (h *Handlers) newPageData(r *http.Request, view string) pageData {
	login := loginNameFromContext(r.Context())
	if login == "" {
		login = "unknown"
	}
	return pageData{
		HTMXIntegrity: HTMXIntegrity,
		LoginName:     login,
		ActiveView:    view,
		RigHostname:   h.deps.RigHostname,
	}
}

// isPartial reports whether the request is an htmx partial swap (HX-Request
// header present). Full-page loads render base.html; partials render just the
// view's #main-content body.
func isPartial(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// setDynamicHTMLHeaders sets the response headers shared by every dynamically
// rendered view: HTML content type plus `Cache-Control: no-store` — the views
// carry live security-posture data (doctor findings, audit trail, fleet
// status) that must never be served from a browser/proxy cache.
func setDynamicHTMLHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
}

// render writes either the full page (base.html) or just the "content" block,
// depending on whether the request is an htmx partial. A render failure is
// logged via slog and answered with the styled error view (no stack trace to
// the client).
func (h *Handlers) render(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) {
	setDynamicHTMLHeaders(w)
	name := "base.html"
	if isPartial(r) {
		name = "content"
	}
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("webui: render failed", "template", name, "err", err)
		h.renderError(w, r, http.StatusInternalServerError, "Something went wrong",
			"The dashboard could not render this view. Check the rig logs.")
	}
}

// renderError serves the styled error.html view for a user-facing error
// response (403 / 404 / 500). It writes the status code first, then executes
// errorTmpl. Crucially it does NOT recurse into render() on a template failure:
// a second failure falls back to a bare http.Error so a broken error template
// can never loop. The body carries only approved copy — never a stack trace or
// internal detail (V7 error-handling posture).
func (h *Handlers) renderError(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	setDynamicHTMLHeaders(w)
	w.WriteHeader(status)
	name := "base.html"
	if isPartial(r) {
		name = "content"
	}
	data := errorData{pageData: h.newPageData(r, ""), Heading: heading, Message: message}
	if err := h.errorTmpl.ExecuteTemplate(w, name, data); err != nil {
		// Fail safe: status already written, so just log. Do not recurse.
		slog.Error("webui: error template render failed", "template", name, "err", err)
	}
}

// handleRoot renders the fleet-status view (the default screen). Partial htmx
// requests get just the status content; full loads get the page shell.
func (h *Handlers) handleRoot(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, h.statusTmpl, h.buildStatusData(r))
}

// handleStatusFragment renders ONLY the auto-polling status-panel block (not a
// full page, not even the view's content wrapper). htmx swaps it outerHTML
// every 10s.
func (h *Handlers) handleStatusFragment(w http.ResponseWriter, r *http.Request) {
	setDynamicHTMLHeaders(w)
	if err := h.statusTmpl.ExecuteTemplate(w, "status-panel", h.buildStatusData(r)); err != nil {
		slog.Error("webui: render failed", "template", "status-panel", "err", err)
		h.renderError(w, r, http.StatusInternalServerError, "Something went wrong",
			"The status panel could not render. Check the rig logs.")
	}
}

// buildStatusData assembles the fleet-status payload from the status provider.
func (h *Handlers) buildStatusData(r *http.Request) statusData {
	var online, total int
	var rigs []rigRow
	if h.deps.Status != nil {
		online, total, rigs = h.deps.Status.FleetStatus(r.Context())
	}
	return statusData{
		pageData:  h.newPageData(r, "status"),
		Online:    online,
		Total:     total,
		LastCheck: "just now",
		Rigs:      rigs,
	}
}

// handleDoctor groups the current findings by severity (FATAL, then WARNING,
// then OK) and renders the doctor view. FATAL and WARNING groups are open by
// default; OK is collapsed (UI-SPEC View 2).
func (h *Handlers) handleDoctor(w http.ResponseWriter, r *http.Request) {
	var findings []modules.Finding
	if h.deps.Doctor != nil {
		findings = h.deps.Doctor.DoctorFindings(r.Context())
	}

	var fatal, warn, ok []findingRow
	for _, f := range findings {
		switch f.Severity {
		case modules.SeverityFatal:
			fatal = append(fatal, findingRow{Check: f.Check, Message: f.Message, BadgeClass: "badge-fatal", BadgeText: "FATAL"})
		case modules.SeverityWarning:
			warn = append(warn, findingRow{Check: f.Check, Message: f.Message, BadgeClass: "badge-warn", BadgeText: "WARN"})
		default:
			ok = append(ok, findingRow{Check: f.Check, Message: f.Message, BadgeClass: "badge-ok", BadgeText: "PASS"})
		}
	}

	var groups []doctorGroup
	if len(fatal) > 0 {
		groups = append(groups, doctorGroup{Label: "FATAL", SeverityClass: "severity-fatal", Open: true, Findings: fatal})
	}
	if len(warn) > 0 {
		groups = append(groups, doctorGroup{Label: "WARNING", SeverityClass: "severity-warn", Open: true, Findings: warn})
	}
	if len(ok) > 0 {
		groups = append(groups, doctorGroup{Label: "OK", SeverityClass: "severity-ok", Open: false, Findings: ok})
	}

	h.render(w, r, h.doctorTmpl, doctorData{pageData: h.newPageData(r, "doctor"), Groups: groups})
}

// handleAudit reads the audit log, projects it to the metadata-only
// AuditEntryView (NEVER audit.Entry), paginates by auditPageSize, and renders
// the timeline newest-first. Pagination requests (?page=N>1) return only the
// <li> rows for hx-swap=beforeend.
func (h *Handlers) handleAudit(w http.ResponseWriter, r *http.Request) {
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 1 {
			page = n
		}
	}

	entries, err := audit.ReadLog(h.deps.AuditLogPath)
	if err != nil {
		slog.Warn("webui: audit read failed", "err", err)
		// Render an empty timeline rather than leaking the error detail.
		entries = nil
	}

	// Project newest-first. ReadLog returns oldest-first, so reverse after
	// projecting. The projection guarantees no Hash/PrevHash/Sig field exists.
	// limit 0 = project every entry, then paginate in memory. For the expected
	// single-rig audit-log size this full projection is acceptable; the positive
	// limit path on projectAuditEntries is exercised by tests and kept for a
	// future windowed projection if logs grow (performance is out of v1 scope,
	// IN-03).
	all := projectAuditEntries(entries, 0)
	reverseViews(all)

	start := (page - 1) * auditPageSize
	if start > len(all) {
		start = len(all)
	}
	end := start + auditPageSize
	if end > len(all) {
		end = len(all)
	}
	pageEntries := all[start:end]

	next := 0
	if end < len(all) {
		next = page + 1
	}

	data := auditData{pageData: h.newPageData(r, "audit"), Entries: pageEntries, NextPage: next}

	// A pagination request (page > 1) appends only the <li> rows.
	if page > 1 {
		setDynamicHTMLHeaders(w)
		if rerr := h.auditTmpl.ExecuteTemplate(w, "audit-rows", data); rerr != nil {
			slog.Error("webui: render failed", "template", "audit-rows", "err", rerr)
			h.renderError(w, r, http.StatusInternalServerError, "Something went wrong",
				"The audit timeline could not render. Check the rig logs.")
		}
		return
	}
	h.render(w, r, h.auditTmpl, data)
}

// handleNotify renders the notify-history view from the in-memory ring buffer.
func (h *Handlers) handleNotify(w http.ResponseWriter, r *http.Request) {
	var rows []notifyRow
	if h.deps.Ring != nil {
		for _, e := range h.deps.Ring.Snapshot() {
			rows = append(rows, notifyRow{
				Time:          e.Time.UTC().Format(auditTimeLayout),
				Title:         e.Title,
				Topic:         e.Topic,
				Priority:      e.Priority,
				PriorityClass: priorityClass(e.Priority),
			})
		}
	}
	data := notifyData{
		pageData:    h.newPageData(r, "notify"),
		Events:      rows,
		AllowNotify: h.deps.AllowNotify,
	}
	h.render(w, r, h.notifyTmpl, data)
}

// handleNotifyPost is the scaffolded allow_notify mutation path. It is only
// reachable when cfg.AllowNotify is true (gated by readOnlyMiddleware) and the
// request is same-origin (gated by CrossOriginProtection). Full dispatch is deferred to
// Phase 20+; for now it acknowledges the request without sending.
func (h *Handlers) handleNotifyPost(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("notify dispatch is not implemented in this phase"))
}

// priorityClass maps a notify priority string to its badge CSS class.
func priorityClass(p string) string {
	switch p {
	case "high", "urgent", "max":
		return "badge-priority-high"
	case "low", "min":
		return "badge-priority-low"
	default:
		return "badge-priority-default"
	}
}

// reverseViews reverses the slice in place so the timeline renders newest-first.
func reverseViews(v []AuditEntryView) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}
