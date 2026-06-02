# NetBird SCIM Provisioning — Out of Scope

Abysslink supports [NetBird](https://netbird.io) as an alternative mesh backend and
exposes posture-check and audit-event management via `abysslink netbird posture` and
`abysslink netbird events`. This document explains why **SCIM 2.0 user provisioning is
out of scope for Abysslink v3** — Abysslink implements no SCIM integration.

## SCIM is a NetBird commercial-edition feature

SCIM 2.0 (System for Cross-domain Identity Management) provisioning in NetBird is
available only in the **commercial editions — NetBird Cloud and NetBird Enterprise**.
It is **not part of the open-source, self-hosted community edition**. There is no
open, self-hostable API surface for SCIM that a community deployment can call, so there
is nothing for Abysslink to integrate against.

## What SCIM would provide

For context, SCIM automates **user and group provisioning from an external identity
provider** (Okta, Microsoft Entra ID / Azure AD, Google Workspace, etc.) into NetBird:
when a user is added, removed, or moved between groups in the IdP, the change is pushed
to NetBird automatically, keeping access in sync without manual administration.

## Why SCIM is out of scope for Abysslink

Abysslink targets the **community / self-hosted NetBird** deployment. SCIM requires a
NetBird commercial license and the hosted SCIM endpoint that comes with it; there is no
self-hosted API to implement against, and coupling Abysslink to a paid tier would
contradict the project's open-source, self-hostable-by-default posture.

## Alternative: manual provisioning

Self-hosted NetBird users manage users and groups through the **NetBird admin UI** and
the open management API. Within Abysslink, use `abysslink netbird posture` to manage
posture checks that gate peer access, and audit changes with `abysslink netbird events`.
This covers access-control hardening without depending on a commercial SCIM tier.

---

*This is a scope-cut document — no SCIM implementation is included in Abysslink.*
