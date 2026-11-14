# Changelog

## v0.6.0 - 2026-11-14

- Name the next enabled manager on every row of `entra user disabled-manager` and `entra user list --disabled-manager`. It is the first enabled account above the disabled manager in the reporting line, offered as a suggestion for whom those people could report to instead. Table and `--plain` output add `NEXT ENABLED MANAGER` and `NEXT ENABLED SIGN-IN NAME` columns after the existing columns, and `--json` adds a `nextEnabledManager` object. `nextEnabledManager` is `null` when the reporting line ends with no manager, loops, reaches a manager whose `accountEnabled` state Microsoft Graph omits, leads back to the person on that row, or walks ten levels without finding an enabled account. Resolving suggestions makes extra manager reads after the directory listing, and the command exits with an error without printing rows if any of those reads fails or if Microsoft Graph returns a manager without an `id`.
- Filter `entra user disabled-manager` and `entra user list --disabled-manager` on the server to `accountEnabled eq true` unless `--include-disabled` is passed. Microsoft Graph returns at most 100 records per page when expanding `manager`, so skipping disabled accounts avoids fetching those pages. The default check no longer reads accounts for which Microsoft Graph holds no `accountEnabled` value.
- Show a running record count on standard error while a Microsoft Graph read spans more than one page, and clear the line when the read finishes. The counter runs only when standard error is a terminal and `--verbose` is not set.

## v0.5.0 - 2026-11-11

- Add `entra user disabled-manager`, and the same check as `entra user list --disabled-manager`, listing everyone whose manager's account is disabled, grouped by manager. People whose own account is disabled are left out unless `--include-disabled` is given. It needs `User.Read.All`, as `user list` does.
- Rewrite the help for every command and subcommand, with usage examples throughout. `user manager`, `user reports` and `user chain` now say which way each one looks: one level up, one level down, or the whole line upwards. Global options move under their own `Global Options` heading, and the rarely used ones appear only in `--help`, not `-h`.
- Report arguments that fail to parse as a JSON error on standard output when `--json` is given or `ENTRA_JSON=true`, as other argument errors already were.
- Refuse an empty `--group` name before signing in, instead of reading no attributes.
- Refuse a `--select` column name that the table or `--plain` output does not have, before signing in, listing the columns it does have. It used to print empty rows and succeed.
- When a lookup searches for an address, refuse one that two directory objects share, such as a guest whose mail matches a member's alias, with the error code `AmbiguousUser`, instead of using whichever Graph listed first. A sign-in name that Graph finds directly is still used as it is.
- Report a browser sign-in that Entra refused, such as a cancelled consent, in Entra's words instead of as a state mismatch.
- Move the default account to another stored account when it signs out, and make the next sign-in the default when the default names no stored account.
- Trim spaces around a person key, so a pasted object id or address is no longer searched for as a name.
- Retry a Graph response whose body is cut off part way, as a failed connection already was.
- Make `--wrap-untrusted` also mark `employeeType` and `employeeId`, which are free text set in the directory.

## v0.4.1 - 2026-11-07

- Make `auth login`, `auth logout`, `auth status` and `version` honour `--json`. `auth status` returns the signed-in profile with the account and the access token's expiry; `auth login` moves its `--directory` note to standard error in JSON mode.
- Serialise credential storage across `entra` processes on Windows with a per-user lock file, `%LOCALAPPDATA%\entra\credentials.lock`, so two processes refreshing one account at once can no longer interleave the pieces of its token, and a reader can no longer follow the header to pieces being deleted. An `entra` process started from an earlier version does not take the lock, so finish or close those before relying on it.

## v0.4.0 - 2026-11-07

- Add `entra reports copilot-usage`, listing each person's Microsoft 365 Copilot active days and prompts with their company; `--by-company` totals people, active people and prompts per company.
- Add `entra reports copilot-summary` (active users per Copilot app), `entra reports copilot-trend` (daily active users and prompts) and `entra reports settings` (whether usage reports conceal names). The three Copilot reports take `--period D7|D28|D90|D180`, defaulting to `D28`.
- Add `--reports` to `auth login` and `auth refresh`, requesting `Reports.Read.All` and `ReportSettings.Read.All`; the setup script now includes both. Because `auth refresh` now adds scopes, narrow a session's scopes by signing in again with `auth login`.
- Add `entra licences list`, showing each licence the tenant subscribes to with its SKU id and assigned and enabled counts.
- Add `entra licences holders --sku <name|sku-id>`, listing everyone who holds a licence; `--by-company` counts holders per company instead. A SKU id needs only `User.Read.All`. `licenses` is accepted as an alias.
- Add `--licences` to `auth login` and `auth refresh`, requesting `LicenseAssignment.Read.All`; the setup script now includes that permission.
- Make `auth refresh` with scope flags add those scopes to the ones already stored, instead of replacing them, so `auth refresh --licences` no longer drops `AuditLog.Read.All` or other permissions the session held.
- Accept a name as the key for `user get`, `manager`, `reports`, `chain` and `groups`. A key with no `@` that is not an object id is matched as a prefix of display name or surname, and exactly one person must match. Table output opens with a warning naming that person. `--json` and `--plain` accept only an exact display name or surname (error code `InexactNameMatch` otherwise) and add a `lookup` field to the JSON envelope. Several matches fail with the error code `AmbiguousUser` and a list of candidates.
- Remove invisible Unicode characters, such as zero-width spaces and bidirectional controls, from table, plain and detail output and from messages, so they can no longer hide characters or reorder what the terminal shows. Other non-ASCII text is kept. JSON output, including deep `--plain` records, keeps each value as Graph returned it.

## v0.3.0 - 2026-10-13

- Add `entra user groups`, listing every group a person belongs to with its kind, whether it is synchronised from on-premises Active Directory, and whether the membership is direct or nested; `--kind` keeps one kind.
- Add `--groups` to `auth login` and `auth refresh`, requesting `GroupMember.Read.All`; the setup script now includes that permission.

## v0.2.0 - 2026-09-29

- Add `entra user list`, a read-only export of every user in the directory, with optional full attributes, attribute groups, sign-in activity and each person's manager.
- Read the login app registration and tenant from `ENTRA_CLIENT_ID` and `ENTRA_TENANT_ID` when `--client-id` and `--tenant-id` are not given, and print which are in use.
- Reuse the app registration saved at an earlier login when neither flags nor environment variables supply one, so signing in again after a revoked token needs no IDs.
- Add `--lifecycle` to `auth login` and `auth refresh`, requesting `User-LifeCycleInfo.Read.All` so the employee leave date is populated; the setup script now includes that permission.
- Let `contrib/create-entra-app.sh` reuse the saved or environment tenant and client IDs, update a known registration in place, and skip the assignment requirement when the registration already enforces one.
- Refuse account addresses that are unsafe as file names instead of rewriting them, so two addresses can no longer share one account file.
- Publish a build provenance attestation for every release archive, verifiable with `gh attestation verify`.

## v0.1.1 - 2026-09-27

- Sign macOS release binaries with Developer ID, a stable identifier, hardened runtime, and a secure timestamp.
