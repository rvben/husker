# ADR-0006: SQLite Schema Migrations

- Status: Accepted
- Date: 2026-07-03

## Context

`husker-state` persists all daemon state in SQLite. The schema evolves as
features land. Until now every change was additive - `CREATE TABLE IF NOT
EXISTS` and idempotent `ALTER TABLE ... ADD COLUMN` (the latter treating
"duplicate column name" as a no-op). That block runs on every daemon startup and
converges any database (fresh, or from an older husker) to the current schema
with no version tracking. It is robust and forward/backward tolerant, but it
cannot express non-additive changes (column rename/drop, type change, or a data
backfill), which a maturing schema eventually needs.

Adopting `PRAGMA user_version` later - once there is an installed base of
un-versioned databases - would require risky one-time baselining logic that
introspects each existing database and stamps the correct version, running on
every user's database at startup. Doing it now, while there is effectively no
installed base, avoids that risk entirely: the baseline is set before any
database we do not control exists.

## Decision

Layer versioning on top of the working idempotent block rather than rewriting it:

- The idempotent `CREATE TABLE` / `ADD COLUMN` block remains the **baseline**
  (`BASELINE_SCHEMA_VERSION = 1`). It bootstraps any database - fresh or
  pre-versioning - to the baseline schema, then `apply_migrations` stamps
  `user_version` to the baseline.
- Every schema change **from here on** is an ordered, one-shot entry in
  `MIGRATIONS: &[(u32, &str)]`, applied in its own transaction when
  `user_version` is below its number, then recording the new version. These may
  be non-additive. Do **not** extend the idempotent baseline block for new
  schema.
- Migrations are **append-only**: never edit, reorder, or renumber a migration
  that has shipped; numbers are strictly ascending and greater than the
  baseline.

## Consequences

- `user_version` fully describes the schema from the baseline onward; future
  migrations are clean numbered steps.
- The one-time baselining risk is avoided by establishing the baseline before an
  installed base exists.
- A failed migration rolls back its transaction and leaves `user_version`
  unchanged, so startup fails loudly instead of half-migrating.
- Non-additive migrations (rename/drop/backfill) are now possible; the first one
  should ship with an old-database fixture test alongside
  `migrates_a_genuinely_old_on_disk_schema`.
