# Changelog

## v0.4.0 - 2026-10-29

- Add `entra licences list`, showing each licence the tenant subscribes to with its SKU id and assigned and enabled counts.
- Add `entra licences holders --sku <name|sku-id>`, listing everyone who holds a licence; `--by-company` counts holders per company instead. A SKU id needs only `User.Read.All`.
- Add `--licences` to `auth login` and `auth refresh`, requesting `LicenseAssignment.Read.All`; the setup script now includes that permission.
- Make `auth refresh` with scope flags add those scopes to the ones already stored, instead of replacing them, so `auth refresh --licences` no longer drops `AuditLog.Read.All` or other permissions the session held.
- Add `entra reports copilot-usage`, listing each person's Microsoft 365 Copilot active days and prompts with their company; `--by-company` totals people, active people and prompts per company.
- Add `entra reports copilot-summary` (active users per Copilot app), `entra reports copilot-trend` (daily active users and prompts) and `entra reports settings` (whether usage reports conceal names).
- Add `--reports` to `auth login` and `auth refresh`, requesting `Reports.Read.All` and `ReportSettings.Read.All`; the setup script now includes both.
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
