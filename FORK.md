# FORK.md

This document explains why Windrose exists as a fork of [Vane](https://github.com/ItzCrazyKns/Vane), what we intend to change, what we intend to leave alone, and how we plan to stay on good terms with upstream. It is the source of truth for scoping decisions: if a proposed change doesn't fit the rationale below, it probably belongs upstream in Vane, not in Windrose.

## Why fork rather than contribute upstream?

Vane is designed around a clear and deliberate model: one operator, one instance, one local search history, privacy-focused, self-hosted on their own hardware. That design decision shapes its architecture — authentication is absent by design, history is local and unscoped, settings are global to the instance, and there is no concept of a user identity.

Windrose serves a different use case: small teams, households, and self-hosted deployments where **more than one person shares a single Vane instance** and each person needs their own isolated experience. Introducing users, roles, per-user data scoping, and an admin surface is a structural change that touches the database schema, the API layer, the settings model, and the UI. It isn't a feature flag; it's a different product shape.

Rather than push a large, opinionated architectural change at upstream and ask them to maintain a use case they didn't set out to serve, we fork. This gives the upstream project room to stay focused on what it does well, and gives Windrose room to evolve its own shape without getting stuck in review.

## What Windrose will change

Scoped to these areas:

1. **Authentication and identity** — local username/password as the initial mechanism, with OIDC planned. No auth bypass, no "local mode" fallback that re-introduces single-user assumptions.
2. **User model and authorization** — at minimum, `admin` and `user` roles. Admins can manage users, pools, and instance settings; users can manage their own history, settings, and provider credentials within the policy set by admins.
3. **Data scoping** — search history, chat sessions, saved searches, and user-supplied API keys become per-user. Schema changes are explicit and migration-backed.
4. **Settings model** — split between *instance settings* (admin-only, e.g. SearxNG endpoint, default provider pool, source policies) and *user settings* (each user's own preferences and credentials).
5. **Admin surface** — minimal UI and API for user lifecycle, usage visibility, and instance configuration.
6. **Deployment** — updated `docker-compose`, environment variables, and documentation to reflect the multi-user deployment model.

## What Windrose will *not* change

To keep merge friction with upstream low, we intend to leave these alone unless absolutely necessary:

- **Search and synthesis logic** — the core RAG pipeline, SearxNG integration, provider abstractions, search modes, and citation handling should continue to match upstream behavior. Bug fixes here go upstream first.
- **UI chrome** — visual design, layout, and component structure stay close to upstream so we can cherry-pick UI improvements without painful conflicts.
- **Provider support** — new LLM providers added upstream should flow into Windrose; Windrose will not fork the provider abstraction.
- **Widgets and source integrations** — these are Vane's territory; improvements belong upstream.

If you find yourself needing to modify one of these areas to make multi-user work, that's a signal to stop and discuss before proceeding. There's usually a way to introduce a scoping shim at the edge rather than changing the core.

## Upstream relationship

- Windrose tracks Vane's `master` branch. We aim to merge or rebase upstream changes at least once per upstream minor release.
- Non-multi-user fixes discovered in Windrose are opened as PRs against upstream Vane first, then backported.
- We keep Windrose-specific changes in clearly labeled directories and modules where feasible, to minimize merge conflicts.
- We do not attempt to rebrand upstream code paths as "Windrose" internally. The app name changes in user-facing surfaces; internal module names, package paths, and architectural concepts that came from Vane keep their names.
- Credit to ItzCrazyKns and the Vane contributors is preserved in the LICENSE, README, and anywhere attribution is appropriate.

## Versioning

Windrose versions independently of Vane. Our version string includes the upstream version we were last synced against, e.g. `windrose-0.1.0+vane-1.12.1`. This makes it easy for operators and contributors to know what base they're running.

## Scope guardrails for contributors

Before opening a PR, ask:

1. **Does this change require the concept of a user to make sense?** If no, it probably belongs upstream.
2. **Does this change touch data that needs to be scoped per user?** If yes, it probably belongs here.
3. **Does this change introduce an admin-only capability?** If yes, it belongs here.
4. **Does this change modify the search/synthesis pipeline, provider abstractions, or widget system?** If yes, open an issue first and tag a maintainer — we want to be deliberate about any core divergence.
5. **Is this a general bug fix or UX polish?** File it upstream first; we'll pick it up on the next sync.

## License and attribution

Windrose is MIT-licensed, matching upstream. The original Vane copyright © 2026 ItzCrazyKns is preserved in the LICENSE file. Windrose-specific modifications are © 2026 overlabbed. Individual contributors retain copyright on their contributions under the MIT license terms.
