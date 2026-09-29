# Changelog

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
