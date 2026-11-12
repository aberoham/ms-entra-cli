---
name: entra-cli
description: Look up people in Microsoft Entra ID (Azure Active Directory) from the terminal via the `entra` CLI — a person's manager, their direct reports, the management chain above them, extended record details including every email alias, group memberships, people whose manager's account is disabled, licence holders and Microsoft 365 Copilot usage reports. Use whenever a task needs a reporting line, a manager check, a sweep for people left under a disabled manager, resolving which of someone's two addresses is which, confirming whether two addresses are one mailbox or two, group membership, licence assignment or Copilot usage.
homepage: https://github.com/aberoham/ms-entra-cli
---

# entra-cli

Directory lookups against Microsoft Entra ID through the `entra` command-line
tool from https://github.com/aberoham/ms-entra-cli.

Read-only by design. Changing a manager belongs in the systems of record that
feed the directory, such as a human-resources system, not in a lookup tool.

## Why it exists

Chat and mail tools that call Microsoft Graph usually hold
`User.ReadBasic.All`, which returns a name, an address and a sign-in name.
The **manager relationship is not in that set**. It needs `User.Read.All`,
which covers the whole directory and needs administrator consent. `entra`
holds that grant on a separate, read-only app registration so that chat and
mail tools do not need it.

Consequence: `GET /users/{someone}/manager` returning
`Authorization_RequestDenied` from a chat or mail tool is expected and is not a
bug to investigate. Use this tool instead.

## Install and set up

```
brew install aberoham/tap/entra
```

Windows builds are `.zip` files on the GitHub releases page. To build from
source, run `./contrib/install.sh` in a checkout.

`entra` needs an app registration in the user's own directory. A person with
the right Entra roles creates it once, with `contrib/create-entra-app.sh` or in
the Microsoft Entra admin center; `docs/auth.md` covers both. The script
**refuses to run without a user or group assignment** unless
`ALLOW_ALL_TENANT_USERS=1` is set deliberately.

Registration and sign-in are interactive, so a person runs them. Do not guess
a client ID or tenant ID. Login uses `ENTRA_CLIENT_ID` and `ENTRA_TENANT_ID`
when set, and otherwise reuses the registration saved at an earlier login, so
signing in again needs neither. For a first sign-in with neither available,
ask the user for them.

## Signing in

```
entra auth login --browser --directory \
  --client-id <application-client-id> \
  --tenant-id <tenant-id>
```

- `--client-id` (or `ENTRA_CLIENT_ID`) is **required; `entra` has no default
  registration.** Use the application
  (client) ID of the registration, not the enterprise application's object ID.
  A client ID borrowed from another Graph tool signs in and then fails every
  manager lookup, because that registration was not consented for directory
  reads.
- `--directory` requests `User.Read.All` and `AuditLog.Read.All`. With no
  scope flags you get a login that reads your own profile and everyone's
  basic details: enough for `user search`, not enough for manager or
  sign-in-activity reads.
- `--lifecycle` adds `User-LifeCycleInfo.Read.All`. Without it (and a role
  such as Global Reader) `employeeLeaveDateTime` comes back `null`, which is
  not evidence that nobody is leaving.
- `--groups` adds `GroupMember.Read.All`, which `user groups` needs.
- `--lifecycle`, `--groups`, `--licences` and `--reports` each add
  `User.Read.All` too.
- `auth refresh` only adds scopes: `entra auth refresh --groups` keeps every
  scope the session already holds. Sign in again to drop one.
- `--licences` adds `LicenseAssignment.Read.All`, which `licences list` and a
  licence name in `licences holders --sku` need, together with a role such as
  Directory Readers. A SKU id in `--sku` needs only `User.Read.All`.
- `--reports` adds `Reports.Read.All` and `ReportSettings.Read.All`, which the
  `reports` commands need, together with a role such as Reports Reader or AI
  Administrator. Global Reader cannot read per-person `copilot-usage` rows.
- Device code is the default and shows an account picker. `--browser` also
  forces Microsoft's account picker rather than reusing the current browser
  session. Check `entra auth list` afterwards.

For user commands, omit `--account` unless a particular identity is required.
The default credential is tried first; a typed Graph permission or role refusal
makes the tool try the other signed-in accounts. An ordinary default account
and a separate administrator identity can therefore coexist without making
every lookup privileged. An explicit `--account` is strict, but may be any
primary email, sign-in name or proxy alias that Graph reports for that stored
identity.

## Commands

```
entra whoami                          Your own record
entra user get <upn|email|id|name>    Full record, including every alias
entra user get <upn|email|id|name> --sign-in-activity
                                      Focused sign-in timestamps and ages
entra user manager <upn|email|id|name> Their direct manager (one level up)
entra user reports <upn|email|id|name> Their direct reports (one level down only)
entra user chain <upn|email|id|name>  Management line upwards, indented
entra user groups <upn|email|id|name> [--kind distribution|mail-security|m365|security|other]
                                      Groups they belong to, direct or nested
entra user search <query> [-n 25]     Find people by name or address prefix
entra user list                       Everyone in the directory
entra user list --all --manager --json
                                      Every record and its manager, for scripts
entra user disabled-manager [--include-disabled]
                                      People whose manager is disabled, with
                                      the next enabled manager above; leaves
                                      out disabled people unless asked
                                      (also: user list --disabled-manager)
entra licences list                   Tenant licences: name, SKU id, assigned, enabled
entra licences holders --sku <name|sku-id> [--by-company]
                                      Who holds a licence, or holders per company
entra reports copilot-usage [--period D7|D28|D90|D180] [--by-company]
                                      Copilot activity per person, or per company
entra reports copilot-summary [--period D7|D28|D90|D180]
                                      Active and enabled Copilot users per app
entra reports copilot-trend [--period D7|D28|D90|D180]
                                      Daily active Copilot users and prompts
entra reports settings                Whether usage reports conceal names
entra auth login|refresh|logout|list|status
```

`licences` commands run as one account and do not fall back to another on a
refusal; pass `--account` to choose. Holders include disabled accounts and
guests. A holder count measures assignment, not use.

`reports` commands also run as one account. Copilot usage covers people who
hold, or recently held, a Microsoft 365 Copilot licence; unlicensed Copilot
Chat use is not in it. If `reports settings` says names are concealed, rows
carry opaque codes and cannot be matched to companies.

`user list --all`, `--group`, `--sign-in-activity` and `--manager` write JSON
only. `--manager` gives each record a `manager` object (`id`, `displayName`,
`userPrincipalName`, `accountEnabled`) or `null`, so a whole directory's
management lines can be analysed from one export instead of a lookup per
person.

`--json`, `--plain` and `--select COLUMN,COLUMN` control output. `--select`
picks table and `--plain` columns by header name, such as `NAME,EMAIL`; it has
no effect on `--json`. `--json`
applies to every command, including `auth status`, whose envelope adds
`"account"` and `"expiresAt"` so you can check sign-in before a run. Set
`--wrap-untrusted` when output feeds a language model: display names and job
titles are free text that people control.

## Two addresses, one person

A person's sign-in name and email address often differ: one person signs in as
`alex.smith@login.example.test` and receives mail at
`alex.smith@example.test`. Graph's direct lookup accepts the sign-in name or
object ID but not an arbitrary alias, and some projections require the object
ID. `entra` resolves address-shaped inputs over `mail`, `userPrincipalName` and
`proxyAddresses` before deep reads. Either address works; callers do not need
to paste an object ID.

A key with no `@` that is not an object ID is treated as a name, matched as a
prefix of display name or surname (not mail, unlike `user search`). Exactly
one match is required. With `--json` or `--plain` the key must equal that
person's display name or surname; a key that only starts it fails with
`InexactNameMatch`, naming the person it would have matched. An exact match
adds `"lookup": {"key", "matchedBy": "exactName", "id"}` to the JSON envelope.
Table output also accepts a prefix match but opens with a `WARNING:` line.
More than one match fails with `AmbiguousUser` and lists up to five
candidates. For audits and leaver checks, use full addresses or object IDs:
a leaver's name can match a current colleague with a similar name.

**`user get` is how you settle whether two addresses are one mailbox or two.**
It prints the alias list and marks the primary. A directory search showing two
separately named objects is suggestive but not proof.

Entra has **no `primaryEmail` / `secondaryEmail` pair**. That is Google
Workspace vocabulary, and looking for it here finds nothing. Addresses live
across four properties:

| Property | What it holds |
|---|---|
| `mail` | The primary address |
| `proxyAddresses` | Every address on the mailbox. `SMTP:` upper case marks the primary, `smtp:` lower case marks an alias |
| `otherMails` | Addresses recorded against the person but not on the mailbox, typically personal or recovery addresses |
| `userPrincipalName` | The sign-in name, which need not receive mail at all |

`user get` prints mailbox addresses and other addresses under separate
headings, because conflating them is how a personal address gets mistaken for
a work one. All of these except `mail` and `userPrincipalName` need
`User.Read.All`.

## Every attribute, machine-readable

`user get` defaults to a curated summary. `--all` requests every
attribute group except `signinactivity` and returns the directory's own JSON,
unmapped. Use it when feeding a script; Graph properties the tool has no
typed field for are kept rather than dropped.

```
entra user get someone@example.com --all --json
entra user get someone@example.com --group addresses --group onpremises --json
entra user get someone@example.com --sign-in-activity
entra user get someone@example.com --all --sign-in-activity
```

Groups: `identity`, `addresses`, `organisation`, `location`, `account`,
`credentials`, `onpremises`, and `signinactivity`. An unknown name is rejected
before authenticating, and the error lists the valid ones.

**`--sign-in-activity` needs more than the other reads.** Last sign-in needs
`AuditLog.Read.All`, which `auth login --directory` requests but
`User.Read.All` does not cover. It also needs a Microsoft Entra ID P1 or P2
licence and a supported Entra role, such as Reports Reader, on the signed-in
account. Used alone, the flag shows Graph's three raw timestamps and request
IDs, plus the age in seconds and in readable form. With `--all`, it adds the
raw activity object to the complete record.

Useful groups: `addresses` for the aliases a person accumulates,
`onpremises` for what on-premises Active Directory synchronised, `credentials`
and `account` for offboarding checks, and `organisation` for hire and leave
dates.

## Reading the errors

- `Authorization_RequestDenied` means the token lacks the scope, not that the
  person is missing. The tool rewrites it to name the relevant `User.Read.All`
  or `AuditLog.Read.All` permission. From `licences`, it can also mean the
  signed-in account lacks a role such as Directory Readers; the message names
  both.
- From `reports`, a refusal (HTTP 403, often `S2SUnauthorized`) means the
  token lacks `Reports.Read.All` or the account lacks a role such as Reports
  Reader; the message names both.
- `Authentication_RequestFromUnsupportedUserRole` means the token has the
  audit scope but the signed-in person lacks a reporting role. The focused
  command recommends Reports Reader; a full-record request warns and retries
  without sign-in activity.
- A person with **no manager** is reported plainly, not as an error. An empty
  manager field is a real state, and finding it is often the point.

## Documentation

- `docs/auth.md`: app registration, the delegated permission table, admin
  consent, sign-in and token storage.
- `docs/command-reference.md`: commands, the permission each needs, and flags.
- `docs/troubleshooting.md`: error message to cause to fix.
