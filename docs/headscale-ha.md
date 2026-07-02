# Headscale High Availability — Out of Scope

Abysslink supports [Headscale](https://headscale.net) as an alternative control-plane
backend to Tailscale's coordination servers. This document explains why **high
availability (HA) for the Headscale control plane is out of scope for Abysslink v3**,
and records the known-workaround patterns for operators who need it — none of which
Abysslink implements.

## Headscale has no upstream HA

As of the Headscale v0.x series, Headscale ships with **no built-in clustering,
replication, or failover**. The default and recommended deployment is a **single
Headscale process backed by a single SQLite database**. There is no upstream support
for running multiple Headscale instances behind a load balancer against a shared,
replicated datastore. Running two Headscale processes against one SQLite file is
unsafe — SQLite is not designed for concurrent multi-writer access across processes.

This is a deliberate upstream design choice: the Headscale control plane is a low-traffic
coordination service, and most self-hosters run it as a single node. The tailnet data
plane (the WireGuard mesh between nodes) keeps working even if the control plane is
briefly unavailable — only new node registration and key exchange pause.

## Why HA is out of scope for Abysslink

Abysslink's ethos is a **single static binary that converges one machine's local
configuration**. Delivering Headscale HA would require Abysslink to provision and
manage a distributed datastore (PostgreSQL or MySQL), leader election, and a load
balancer — infrastructure that lives well outside a single-binary tool's remit and
cannot be made safe without significant upstream Headscale changes. Owning that
operational surface would also contradict the project's "no telemetry, no hidden
moving parts" posture.

## Known-workaround patterns (documented, not implemented)

Operators who genuinely need a fault-tolerant Headscale control plane typically reach
for one of these patterns. **Abysslink implements none of them**; they are recorded
here only so you know the lay of the land:

- **LiteFS / Litestream** — Replicate the SQLite database to object storage (S3) or to
  a read replica. LiteFS provides single-primary failover by fencing writes to one
  node; Litestream provides streaming backup + point-in-time restore. Both still leave
  you with a single write primary at any instant.
- **Consul / etcd leader election** — Run a standby Headscale node and use a
  Consul/etcd lock to ensure only the elected leader serves writes, promoting the
  standby on failure. This is an external orchestration layer, not a Headscale feature.
- **Managed PostgreSQL + community tooling** — Point Headscale at a managed,
  highly-available PostgreSQL provider and deploy via a community Helm chart. This
  shifts the HA burden onto your database provider.

## Recommendation

For most users, a single well-backed-up Headscale node is the right answer: run
`abysslink server headscale backup` and keep the SQLite database and node keys safe. If you require true
HA, use a managed PostgreSQL provider with a community deployment, or wait for upstream
Headscale to ship first-class HA support, and track the
[Headscale roadmap](https://github.com/juanfont/headscale).

---

*This is a scope-cut document — no HA implementation is included in Abysslink.*
