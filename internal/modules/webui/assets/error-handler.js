// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Abysslink Contributors
//
// Minimal, CSP-compliant error banner toggle. Loaded as a same-origin
// <script src="/static/error-handler.js"> — no inline handlers, no eval.
// Listens for htmx:responseError and reveals #error-banner via a CSS class.
(function () {
  "use strict";
  function showError() {
    var banner = document.getElementById("error-banner");
    if (!banner) {
      return;
    }
    banner.textContent =
      "Could not load data. Check that abysslinkd is running and you are on the tailnet.";
    banner.classList.add("error-banner--visible");
  }
  document.body.addEventListener("htmx:responseError", showError);
  document.body.addEventListener("htmx:sendError", showError);
})();
