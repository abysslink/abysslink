# TUI Review — area `modules` — 2026-06-25

## Executive Summary
1 findings. Severity: CRITICAL 0, HIGH 0, MEDIUM 1, LOW 0. Buckets: AUTO_FIXABLE 0, FLOW_FIX 0, LOG 1.

## Risk Assessment
Status **REVIEW**.

## Findings
#### T-037 — [MEDIUM/LOG] `internal/modules/webui/handlers.go:526` (missing-components)

- **Problem:** When cfg.webui.allow_notify is true (a real config key, config.go:444), the Notifications view renders a POST form with a 'Send notification' submit button (templates/notify.html:43-49, hx-post=/notify, hx-swap=innerHTML targeting #main-content). The registered POST /notify handler (handlers.go:530-534) unconditionally returns HTTP 501 with the plain-text body 'notify dispatch is not implemented in this phase'. The route comment (handlers.go:303) and module_test.go:654-662 confirm this is intentional scaffolding ('full dispatch deferred to Phase 20+').
- **Impact:** A user who opts into allow_notify sees a functional-looking 'Send notification' form. Submitting it does nothing useful: htmx swaps the dashboard's #main-content with the raw 501 string 'notify dispatch is not implemented in this phase', visually breaking the page (replacing the styled view with bare unstyled text). A button that renders and is activatable but is wired to an explicit not-implemented endpoint.
- **Before (rendered):** On the dashboard Notifications page, below the history table, a text input labelled 'Title' and a 'Send notification' button appear. Clicking the button replaces the entire main content area with the plain unstyled sentence 'notify dispatch is not implemented in this phase' — no notification is sent, the chrome/nav is gone, and the user is stuck on a broken-looking page.
- **Fix:** Until dispatch is implemented, do not render the form/button: gate the notify.html form block on a capability the handler actually fulfils (not just allow_notify), or have handleNotifyPost return a styled, htmx-friendly partial that says the feature is not yet available and keeps the page intact (and use a non-501 status that htmx will swap cleanly). Best: keep the form hidden behind a build/feature flag that is only true when POST /notify truly dispatches, so no dead button ships.
- **Confidence:** high  ·  verify None/0

## Checklist
- [ ] T-037 (MEDIUM/LOG) internal/modules/webui/handlers.go:526