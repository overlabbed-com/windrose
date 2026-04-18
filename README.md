# Windrose

> Multi-user AI search and synthesis. A fork of [Vane](https://github.com/ItzCrazyKns/Vane) by [overlabbed](https://overlabbed.com).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Upstream: Vane](https://img.shields.io/badge/upstream-ItzCrazyKns%2FVane-blue)](https://github.com/ItzCrazyKns/Vane)
[![Status: Early](https://img.shields.io/badge/status-early-orange)]()

Windrose takes Vane — the open-source, privacy-focused AI answering engine — and extends it into a multi-user system. Where Vane is designed for a single operator on their own hardware, Windrose is built for small teams, households, and self-hosted deployments where more than one person needs their own account, their own history, and their own settings, all served from the same instance.

A windrose is the figure on a nautical chart showing the directions and frequencies of winds converging on a location. The name felt right for a tool where multiple users each point their own questions at the same shared engine and get their own answers back.

## What Windrose adds to Vane

- **Per-user accounts** with authentication (initial target: local credentials + OIDC)
- **Per-user search history**, settings, and provider keys — scoped and isolated
- **Role model** distinguishing administrators from regular users
- **Shared vs. private resources** — admins can configure provider pools and source policies that apply across all users
- **Admin surface** for user management, quota/usage visibility, and instance-wide settings

Everything Vane does today — SearxNG integration, Ollama + cloud LLM support, multiple search modes, cited answers, file uploads, widgets — Windrose continues to do. The goal is to be a strict superset that tracks upstream closely.

## Status

Windrose is in early development. Expect rough edges, breaking changes, and schema migrations until the 0.1 release. If you need a rock-solid single-user deployment today, run upstream Vane directly.

## Quick start

> Installation instructions will land here once the first tagged release is cut. For now, treat this as a development fork.

## Relationship to Vane

Windrose is an MIT-licensed fork, not a replacement or a criticism. Vane is excellent for its intended use case, and we intend to stay close to upstream — pulling in releases, contributing back fixes that aren't multi-user-specific, and keeping our architectural divergence documented and minimal. See [FORK.md](./FORK.md) for the full rationale and divergence plan.

## Contributing

Contributions welcome. Before opening a large PR, please read [FORK.md](./FORK.md) so you understand what belongs in Windrose vs. what should go upstream to Vane. Bug reports and issues that apply to both projects are generally better filed upstream first.

## License

MIT — see [LICENSE](./LICENSE). Original Vane copyright © 2026 ItzCrazyKns is preserved; Windrose-specific modifications © 2026 overlabbed.
