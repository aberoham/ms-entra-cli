---
name: entra-cli
description: Look up people in Microsoft Entra ID (Azure Active Directory) from the terminal via the `entra` CLI — a person's manager, their direct reports, the management chain above them, and extended record details including every email alias. Use whenever a task needs a reporting line, a manager check, resolving which of someone's two addresses is which, or confirming whether two addresses are one mailbox or two.
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
- `--directory` requests `User.Read.All` and `AuditLog.Read.All`. Without it
  you get a login that reads your own profile and everyone's basic details:
  enough for `user search`, not enough for manager or sign-in-activity reads.
- `--lifecycle` adds `User-LifeCycleInfo.Read.All`. Without it (and a role
  such as Global Reader) `employeeLeaveDateTime` comes back `null`, which is
  not evidence that nobody is leaving.
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
entra user get <upn|email|id>         Full record, including every alias
entra user get <upn|email|id> --sign-in-activity
                                      Focused sign-in timestamps and ages
entra user manager <upn|email|id>     That person's manager
entra user reports <upn|email|id>     Everyone reporting to them
entra user chain <upn|email|id>       Management line upwards, indented
entra user search <query> [-n 25]     Find people by name or address prefix
entra user list                       Everyone in the directory
entra user list --all --manager --json
                                      Every record and its manager, for scripts
entra auth login|refresh|logout|list|status
```

`user list --all`, `--group`, `--sign-in-activity` and `--manager` write JSON
only. `--manager` gives each record a `manager` object (`id`, `displayName`,
`userPrincipalName`, `accountEnabled`) or `null`, so a whole directory's
management lines can be analysed from one export instead of a lookup per
person.

`--json`, `--plain` and `--select field,field` control output. Set
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

`user get` defaults to a curated summary. `--all` requests every scalar
attribute Graph exposes and returns the directory's own JSON, unmapped. Use it
when feeding a script; it also stops an attribute the tool has no field for
from silently vanishing.

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
  or `AuditLog.Read.All` permission.
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
