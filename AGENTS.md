# AGENTS.md

## Repository purpose

This repository builds `entra`, a small read-only Rust CLI for Microsoft Entra
ID directory lookups through Microsoft Graph. It exists to inspect people,
addresses, manager relationships and reporting lines without widening the
permissions of unrelated Teams or Outlook tools.

The safety boundary is intentional: there is no directory write path. Keep it
that way unless a change explicitly introduces a reviewed write workflow.

This is a public repository. Never log or commit access tokens, refresh
tokens, tenant IDs, application (client) IDs, enterprise application object
IDs, organisation names, internal URLs or real directory data, in code,
fixtures, docs, commit messages or issues. Use placeholders such as
`<tenant-id>` and `<application-client-id>` in documentation, and
`00000000-0000-4000-8000-…` UUIDs and `example.test` or `example.com`
addresses in tests. Well-known Microsoft constants, such as the Microsoft
Graph application ID and published permission IDs, are fine.

```bash
cargo build --release
./target/release/entra --help
./target/release/entra user get someone@example.com
```

## Architecture

- `src/main.rs` is the async binary entry point.
- `src/cli.rs` defines the Clap command tree, resolves shared configuration and
  authentication, dispatches commands, and owns human/JSON error output.
- `src/graph.rs` is the only Microsoft Graph transport. It owns safe endpoint
  construction, retries, pagination, lookup fallback, permission
  classification and deep reads. Do not issue stray Graph requests from
  command handlers.
- `src/model.rs` contains the typed summary `User` model. Deep records remain
  `serde_json::Value` maps so new Graph properties are not silently dropped.
- `src/attributes.rs` defines the deep attribute groups and `$select` lists.
- `src/auth.rs` implements device-code and browser authorization-code login,
  refresh, account metadata and the compatibility format for existing tokens.
- `src/secrets.rs` stores refresh tokens in the operating-system keyring.
- `src/config.rs` stores non-secret account/app metadata as the existing JSON
  format under the platform config directory.
- `src/output.rs` implements table, plain TSV, JSON envelopes, field selection,
  terminal sanitisation, and untrusted-content wrapping.
- `contrib/create-entra-app.sh` provisions the Entra app registration.
  `contrib/resign.sh` gives local macOS builds a stable signing identity for
  keychain access. `contrib/install.sh` owns the verified signed installation
  to the per-user `~/.local/bin/entra` location.
- `.github/workflows/ci.yml` runs formatting, lint and tests on Linux, macOS
  and Windows. `.github/workflows/release.yml` builds the release archives
  when a `v*` tag is pushed; the tag must equal `v` plus the `Cargo.toml`
  version. The Homebrew formula lives in the separate `aberoham/homebrew-tap`
  repository, which reads new releases by itself.
- `docs/` and the root `SKILL.md` describe the shipped command contract.

## Command and output contracts

- Human table/detail output is the default. `--json` emits
  `{ "results": ..., "count": ... }`; `--results-only` removes that envelope.
- Deep `user get --all/--group` output is Graph's unmapped object in JSON/plain
  modes, matching the original command contract.
- JSON errors are `{ "error": { "code": ..., "status": ..., "message": ... } }`.
  Human errors go to stderr. Do not place diagnostics on JSON stdout.
- Commands return exit code `0` on success and `1` on failure, including
  argument validation failures.
- Sanitize directory-controlled strings before terminal output. Preserve
  `--wrap-untrusted` for typed JSON result types.
- `--no-write` is a capability guard even though every Graph command is read
  only. Any future mutation needs a new, explicitly reviewed safety design.
- `--no-input` must prevent prompts in automation.

## Graph client behaviour

All Graph calls go through `GraphClient`. Preserve these transport guarantees:

- Bearer tokens are never logged and redirects are disabled.
- User-controlled route values are encoded as one URL path segment; construct
  query parameters through `url::Url`, never string concatenation.
- OData literals go through `odata_literal`; keep the length,
  control-character and quote-doubling tests.
- Reads have a timeout and an 8 MiB response bound.
- Network failures, 429 and 5xx responses use bounded retries; 429 honours
  numeric `Retry-After`.
- Pagination accepts next links only from the configured Graph scheme/host,
  detects repeated links, and has a page ceiling.
- Graph errors remain typed by HTTP status and Graph code. Human messages may
  add context, but control flow must not depend on Microsoft's prose.

Microsoft Graph's `/users/{key}` route accepts an object id or
`userPrincipalName`, but a person's primary mail or proxy alias may differ.
User-facing commands therefore retry a direct 404 with a bounded OData search
over `mail`, `userPrincipalName`, and `proxyAddresses`, then use the resolved
object id for relationship and deep-attribute reads.

Preserve that behaviour across summary `user get`, `--all`, `--group`,
`manager`, `reports`, and `chain`. Do not treat Graph's generic
`Request_ResourceNotFound` reference-property wording as proof that an optional
attribute or relationship is absent. Only a typed not-found result triggers
the address fallback.

Deep attribute groups deliberately exclude navigation properties such as
`manager`, `directReports`, and `memberOf`. `signInActivity` remains opt-in
because it needs `AuditLog.Read.All`, an eligible Entra licence, and a supported
role on the signed-in account; Reports Reader is the least-privileged built-in
choice.

## Authentication and compatibility

Login uses delegated Microsoft Graph permissions. Basic profile reads use
`User.ReadBasic.All`; the `--directory` profile requests administrator-consented
`User.Read.All` and `AuditLog.Read.All`. Sign-in activity also needs an eligible
Entra licence and remains opt-in per query.

Tokens belong only in the OS keyring. Preserve service name `entra`, key
`entra:token:<lowercase-email>`, and the existing refresh-token JSON shape so
users do not have to log in again after an upgrade. Preserve the existing
`config.json` and account-file shapes for the same reason.

On Linux the `keyring` crate's `linux-native` feature stores tokens in the
kernel key-retention service (keyutils), not Secret Service. Those entries are
in memory only and do not survive a reboot; the documentation says so, and a
change of backend must update it.

For user commands without `--account`, try the default authenticated account
first and fall back to other stored identities only on typed authorization or
role failures. Explicit `--account` is strict but resolves primary mail, UPN
and proxy aliases against each stored identity's `/me` profile. Never switch an
explicitly selected identity, infer identity from display names, or treat a
network/data error as permission to use a different account.

On macOS and Linux, update the existing keyring item in place so refresh does
not discard its access-control list. On Windows, preserve the bounded raw-byte
chunk format headed by the canonical token key, its two alternating chunk slots
(a rewrite never touches the slot the live header uses), stale-chunk cleanup,
and legacy single-entry reads. Background refresh may fall back to a not-yet-
expired access token; explicit `auth refresh` must persist successfully.

macOS keychain items must retain the account-specific `entra — <account>` label
and Microsoft Entra ID token description. Without a label, the authorisation
dialog names the stored item as an empty string. Apply metadata updates in place
so fixing the prompt does not discard an existing access-control list.

The macOS keychain grant is tied to the binary signature. Rebuilds intended
for live use should be followed by:

```bash
cargo build --release && ./contrib/resign.sh
```

For a normal local installation from source, use `./contrib/install.sh`; do
not point the installed command into a build directory.

Tests must use in-memory credentials and synthetic directory records. They
must not touch the real keyring or Microsoft Graph.

## Implementation conventions

- Validate command arguments before authentication or network work.
- Prefer `EntraError` variants and typed predicates over parsing rendered
  errors. Human errors should state the failed operation and likely correction;
  machine errors must retain a useful Graph code and HTTP status.
- Use typed models for stable summary views and preserve unmapped JSON for deep
  records.
- Keep asynchronous I/O under Tokio and carry request timeouts through the
  shared clients.
- Use `wiremock` for HTTP behaviour, in-memory credential stores for token
  tests, and `assert_cmd` for process-level CLI contracts. Never require live
  tenant credentials in automated tests.
- Keep `README.md`, `docs/command-reference.md`, `docs/auth.md`,
  `docs/troubleshooting.md`, and `SKILL.md` consistent with user-visible flags,
  permissions, fallback behaviour, or output changes.

## Verification

For ordinary Rust changes, run:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

For shell changes, also run `bash -n` and ShellCheck. For workflow changes,
run `actionlint` and `zizmor`. Mock tests need loopback access because
`wiremock` binds a local port. A passing suite is not evidence that the tenant
granted the advertised scopes; report live Graph validation separately and use
only a test account you are authorised to use.

Before finishing, inspect `git diff --check` and the complete diff, preserve
unrelated worktree changes, and ensure no credentials, tenant identifiers or
real directory data entered tests, docs, logs, or commits.
