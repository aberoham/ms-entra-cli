# Command reference

A practical map of the current surface. Run `entra <command> --help` for the
exact generated help on the installed binary.

Every command reads. There is no write path: changing a person's manager or
attributes belongs in the systems of record — the human-resources system that
feeds the directory — not in a lookup tool.

## Permissions per command

| Command | Needs |
|---|---|
| `entra whoami` | `User.Read` |
| `entra user search` | `User.ReadBasic.All` |
| `entra user get` | `User.ReadBasic.All` for the basic fields, `User.Read.All` for the full record |
| `entra user get --sign-in-activity` | `User.Read.All`, `AuditLog.Read.All`, P1/P2 licence, and a supported role such as Reports Reader |
| `entra user manager` | `User.Read.All` |
| `entra user reports` | `User.Read.All` |
| `entra user chain` | `User.Read.All` |
| `entra user groups` | `User.Read.All` and `GroupMember.Read.All` |
| `entra user list` | `User.Read.All`; with `--sign-in-activity`, as for `user get --sign-in-activity` |
| `entra user disabled-manager` | `User.Read.All` |
| `entra licences list` | `LicenseAssignment.Read.All`, and a role such as Directory Readers or Global Reader |
| `entra licences holders` | `User.Read.All`; a licence name in `--sku` also needs what `licences list` needs |
| `entra reports copilot-*` | `Reports.Read.All`, and a role such as Reports Reader, AI Administrator or Global Reader; `copilot-usage` also needs `User.Read.All` |
| `entra reports settings` | `ReportSettings.Read.All`, and a role as for `copilot-*` |
| `entra auth *` | none beyond sign-in |

See [auth.md](auth.md) for which fields fall on each side of that line.

## Auth

```text
entra auth login [--client-id ID] [--browser] [--directory] [--lifecycle] [--groups] [--licences] [--reports] [--tenant-id ID] [--scope SCOPE]...
entra auth refresh [--directory] [--lifecycle] [--groups] [--licences] [--reports] [--scope SCOPE]...
entra auth logout [ACCOUNT]
entra auth list
entra auth status
```

Login takes the client ID from `--client-id` or `ENTRA_CLIENT_ID`, and the
tenant ID from `--tenant-id` or `ENTRA_TENANT_ID`. Without them it reuses the
registration saved at an earlier login (see
[auth.md](auth.md#sign-in)), so only the first sign-in needs them. `--directory` requests
`User.Read.All` and `AuditLog.Read.All`; without it, manager, reporting-line and
sign-in-activity lookups will not work. Sign-in activity additionally requires
an eligible licence and a supported role on the signed-in account.
`--lifecycle` requests `User-LifeCycleInfo.Read.All`, without which Graph
returns every employee leave date as `null`; the signed-in account also needs
Lifecycle Workflows Administrator, Global Reader or Global Administrator.
`--groups` requests `GroupMember.Read.All`, which `user groups` needs.
`--licences` requests `LicenseAssignment.Read.All`, which `licences list` and a
licence name in `licences holders --sku` need.
`--reports` requests `Reports.Read.All` and `ReportSettings.Read.All`, which the
`reports` commands need.
Each of `--lifecycle`, `--groups`, `--licences` and `--reports` also requests
`User.Read.All`.
`auth refresh` silently redeems the selected account's stored refresh token.
It only ever adds scopes: with no flags it keeps the stored scope set, and
flags add their scopes to that set once the matching consent has been granted.
To narrow a session, sign in again with `auth login`.

Every `auth` command and `version` honour `--json`, returning the usual
`{"results": ..., "count": ...}` envelope; `count` is the number of stored
accounts for `auth list` and 1 for the others. With `--wrap-untrusted`, the
display name in `auth login` and `auth status` is marked as untrusted:

| Command | `results` |
|---|---|
| `auth login` | `{"account", "displayName", "tenantId", "clientId"}`. Sign-in prompts and the `--directory` note go to standard error. |
| `auth refresh` | `{"account", "expiresAt", "scope"}` |
| `auth logout` | `{"account", "signedOut": true}` |
| `auth list` | One `{"email", "display_name", "tenant_id", "client_id", "login_time"}` per stored account |
| `auth status` | The signed-in account's profile, as `whoami --json` returns it. The envelope adds `"account"` and `"expiresAt"`, the expiry of the access token the check actually used, including a refreshed token that could not be stored; `--results-only` returns the profile alone. |
| `version` | `{"version", "commit", "built"}`; `commit` and `built` are `null` in a local build. |

Account files are keyed by the primary email shown by `entra auth list`, but
`--account` also accepts that identity's sign-in name/UPN or a proxy address.
Alternate forms are resolved against `/me`; an explicit account pins the
operation to that identity and never enables privilege fallback.

## Licences

```text
entra licences list
entra licences holders --sku <name|sku-id> [--by-company]
```

`licenses` is accepted in place of `licences`.

`licences list` shows each licence the tenant subscribes to: its name
(`skuPartNumber`), its SKU id, how many are assigned (`consumedUnits`) and how
many are enabled (`prepaidUnits.enabled`), sorted by name. Its rows are
Microsoft's licence catalogue, not text anyone in the directory can edit, so
`--wrap-untrusted` leaves them as they are.

`licences holders` lists every user who holds the licence, with name, sign-in
name, company and department; `--json` gives the same records as `user list`.
Disabled accounts and guests who hold the licence are included, because they
still hold an assignment. `--sku` takes the name shown by `licences list`, in
any case and ignoring any character outside printable ASCII, or the SKU id.
An id is used as given, without reading the tenant's licences, so it needs
only `User.Read.All`; an id the tenant does not use returns no holders rather
than an error. A name shared by two different SKU
ids is refused; pass the id instead.

`--by-company` replaces the list with one row per `companyName` and the number
of holders, largest first. Holders with no company are counted together, shown
as `(not set)` in a table and `null` in JSON
(`{"company": null, "holders": N}`). With `--json`, `count` is the number of
rows. A holder count is an assignment count, not a measure of use.

`licences` commands run as one account: the default, or the one named with
`--account`. Unlike `user` commands, a refusal does not move on to another
signed-in account; the error for the default account says to pass
`--account`.

## Reports

```text
entra reports copilot-usage [--period D7|D28|D90|D180] [--by-company]
entra reports copilot-summary [--period D7|D28|D90|D180]
entra reports copilot-trend [--period D7|D28|D90|D180]
entra reports settings
```

These read Microsoft 365 Copilot usage reports. `--period` is the number of
days the report covers, ending on the report date, and defaults to `D28`.
Microsoft refreshes the reports about once a day, a day or two behind.

`copilot-usage` lists one row per person in the report, with name, sign-in
name, company, last active date, active days and prompts in the period, most
prompts first. The report covers people who hold, or recently held, a
Microsoft 365 Copilot licence; unlicensed Copilot Chat use is not in it.
Company comes from the directory, matched by sign-in name, so the command also
reads every user's `companyName` and `department`. `--json` adds department,
prompts in Copilot Chat (work and web) and each app's last active date
(`lastActivityByApp`, keyed as Graph names the app).

`--by-company` replaces the list with one row per company: people in the
report, how many were active on at least one day, their prompts, and prompts
per active person. People with no company are counted together as `(not set)`
in a table and `null` in JSON. Counts of people are not licence counts: the
report can include someone whose licence was removed during the period.

`copilot-summary` shows active and enabled users per Copilot app, with the
total and average prompts in table output. `copilot-trend` shows each day's
active and enabled users and prompts, oldest first. With `--json`,
`copilot-summary` passes Graph's record through unchanged, and `copilot-trend`
gives Graph's daily records, oldest first.

`settings` shows whether the tenant conceals names in usage reports (Microsoft
365 admin centre: Settings > Org settings > Services > Reports). When it does,
the report carries opaque codes instead of names and addresses, so rows cannot
be matched to the directory: `copilot-usage` leaves company empty and
`--by-company` is refused.

The report routes are read from Graph's beta endpoint, because v1.0 serves
them only as CSV. Like `licences`, `reports` commands run as one account and
do not move to another on a refusal.

## User lookups

```text
entra user get <upn|email|id|name>
entra user manager <upn|email|id|name>
entra user reports <upn|email|id|name>
entra user chain <upn|email|id|name> [--depth 10]
entra user groups <upn|email|id|name> [--kind KIND]
entra user search <query> [-n 25]
```

Any of a person's sign-in name, primary email address or object id is accepted.
A direct lookup that misses is retried as a search over `mail`,
`userPrincipalName` and `proxyAddresses`, so either address form works. Deep reads recognise an
address-shaped key and resolve it before requesting attributes, because Graph
requires an immutable object id for some projections such as
`signInActivity`. Callers never need to resolve or paste that id themselves.

A key with no `@` that is not an object id can only be a name, because every
sign-in name contains `@`. `entra` looks for people whose display name or
surname starts with it. Unlike `user search`, it does not match mail or sign-in
name prefixes, so a short key cannot single out someone by an address such as
`announcements@`. The rules depend on the output format:

- **Table output** (the default) uses the one person found and opens with a
  `WARNING:` line naming them. The warning is stronger when the key only starts
  that person's name: `"Sam"` can find Samantha Jones when the Sam you meant
  has left.
- **`--json` and `--plain`** accept only an exact display name or surname,
  ignoring case, because scripts do not read warnings. A key that only starts
  someone's name fails with the error code `InexactNameMatch`, which names the
  person it would have matched. An exact match adds
  `"lookup": {"key": ..., "matchedBy": "exactName", "id": ...}` to the
  `{results, count}` envelope and writes a `notice:` line to standard error.
  Plain output, `--results-only` and deep `user get --all/--group` JSON have
  no envelope, so there the notice on standard error is the only sign.

If the name matches more than one person, the command fails with the code
`AmbiguousUser` and lists up to five of them. It never picks one for you. For
an audit or a leaver check, pass full addresses or object ids, not names.

`user get` prints every alias and marks which is primary — the way to establish
whether two addresses are one mailbox or two. Mailbox addresses
(`proxyAddresses`) and other addresses (`otherMails`) are listed separately,
because the second kind usually delivers somewhere else entirely. Entra has no
`primaryEmail`/`secondaryEmail` pair; see [auth.md](auth.md#there-is-no-primaryemail-or-secondaryemail).

`user manager` goes one level up and `user reports` one level down: it lists
direct reports only. `user chain` walks upwards from the named person, stopping
at the top of the line, at `--depth`, or on a cycle. `--depth` counts the
starting person, who is the first entry, so `--depth 1` shows only them;
`--depth 0` means the default of 10. No command walks the tree downwards; to
build one, export everyone with `entra user list --manager --json`. Directories do contain cycles: somebody
recorded as their own manager, or a pair pointing at each other.

`user search` matches a prefix of display name, mail, sign-in name or surname.

### Group memberships

`user groups` lists every group the person belongs to, including those they
reach only through another group. Each row gives the group's name, mail
address, kind, source and membership:

| Column | Values |
|---|---|
| `KIND` | `distribution` (a distribution list), `mail-security` (a mail-enabled security group), `m365` (a Microsoft 365 group), `security`, or `other` |
| `SOURCE` | `on-premises` when the group is synchronised from on-premises Active Directory, otherwise `cloud` |
| `MEMBERSHIP` | `direct`, or `nested` when the person belongs through another group |

Direct memberships come first. `--kind` keeps one kind, so
`--kind distribution` lists only distribution lists.

The source column says where the group is administered. A group synchronised
from on-premises Active Directory is read-only in Entra and Exchange Online,
so its membership has to change in the on-premises directory. Removing a
nested membership means removing the group that carries it, or the person
from that group.

Two kinds of group never appear. Exchange dynamic distribution groups are
Exchange objects with no Entra record, and an on-premises group outside the
synchronisation scope never reaches Entra at all.

Without `GroupMember.Read.All`, Graph returns each group stripped to its id
instead of refusing. `user groups` reports that as a permission error rather
than printing a list of nameless groups.

### Deep inspection

`user get` has two modes. By default it prints a curated summary. With
`--all` it requests the attributes of every attribute group below except
`signinactivity`, and returns them as unmapped Graph JSON:

```bash
entra user get someone@example.com --all --json
```

Returning Graph's response verbatim is deliberate. Flattening it into a struct
would silently drop any attribute this tool has no field for, and would lose
the nested shape of `employeeOrgData`, `onPremisesExtensionAttributes` and
`signInActivity`.

Graph's `/users/{key}` route accepts a sign-in name or object id, not every
deliverable email address, and some attribute combinations work only with an
object id. For a deep read, `entra` resolves any email/UPN-shaped input first
and fetches attributes by object id. A real miss is reported in those terms
instead of repeating Graph's ambiguous “reference-property objects are not
present” message.

Attributes are organised into groups, and `--group` fetches only what you need:

| Group | Contains |
|---|---|
| `identity` | Names, sign-in name, object id, user type, security identifier |
| `addresses` | `mail`, `otherMails`, `proxyAddresses`, `imAddresses`, phone numbers |
| `organisation` | Job title, department, company, employee id and type, hire and leave dates (the leave date needs `--lifecycle`, see [auth.md](auth.md)) |
| `location` | Street address through to usage and data-residency location |
| `account` | Enabled state, created and deleted timestamps, creation type, guest state |
| `credentials` | Last password change, password policies, token validity cut-offs |
| `onpremises` | Everything synchronised from on-premises Active Directory |
| `signinactivity` | Last sign-in — needs `AuditLog.Read.All`, see [auth.md](auth.md) |

```bash
entra user get someone@example.com --group addresses --group onpremises --json
entra user get someone@example.com --all --sign-in-activity
```

Used without `--all` or `--group`, `--sign-in-activity` is a focused view:

```bash
entra user get someone@example.com --sign-in-activity
```

It reports the last successful authentication, last interactive attempt and
last non-interactive authentication. Each row retains Entra's raw RFC 3339
timestamp and request id and adds both an exact age in seconds and a compact
human-readable age. The interactive value is an **attempt**, not proof of a
successful login; use `lastSuccessfulSignInDateTime` for that claim. JSON keeps
the original `signInActivity` object and adds `observedAt` and
`signInActivityAge` alongside it.

An unknown group name is rejected before the tool authenticates, and the error
lists the valid ones.

Navigation properties — `manager`, `directReports`, `memberOf` and the like —
are relationships rather than attributes and are not part of these groups.
Graph rejects a `$select` mixing the two. They have their own commands.

## Listing the whole directory

```text
entra user list [--all] [--group GROUP]... [--sign-in-activity] [--manager]
```

`user list` reads every user in the directory, one page after another, and
writes nothing until the last page has arrived. With no flags it prints the
same summary columns as `user search`, in any output format.

The flags turn it into an export of unmapped Graph records, written as JSON
only; any of them without `--json` is rejected before signing in.

| Flag | Adds |
|---|---|
| `--all` | Every attribute in the groups above except `signinactivity` |
| `--group GROUP` | Only these groups (repeatable; wins over `--all`) |
| `--sign-in-activity` | `signInActivity`, alongside the summary fields when used alone |
| `--manager` | A `manager` object on every record: `id`, `displayName`, `userPrincipalName` and `accountEnabled`, or `null` when none is recorded |

Every record carries its object `id`, whichever groups are chosen, so records
can be joined to each other. A manager's `id` matches the `id` of that
person's own record, which is how a script walks management lines without a
request per person. Every record also carries every property the flags
select, as `null` where Graph has no value; Graph itself leaves
`signInActivity` out for anyone who has never signed in. All records
therefore share one set of keys, which suits `jq`, data frames and CSV.

If any page fails, the command exits 1 and writes nothing to standard output,
so a script can never mistake a partial directory for a whole one.

```bash
entra user list --all --manager --json --results-only > directory.json
```

With `--sign-in-activity`, a refused request fails the whole command. It does
not drop the column and carry on, as `user get --all --sign-in-activity` does,
because an export missing data it was asked for would look complete to the
script reading it.

The export is not wrapped by `--wrap-untrusted`, the same as deep `user get`
output; the summary list is.

## People whose manager is disabled

```text
entra user disabled-manager [--include-disabled]
entra user list --disabled-manager [--include-disabled]
```

The two forms are the same check. It reads the whole directory once, with
each person's manager expanded, and lists the people whose manager's account
exists and is disabled (`accountEnabled` is `false`). These are the reporting
lines that need a new manager.

By default people whose own account is disabled are left out: a disabled
person under a disabled manager usually needs no action. `--include-disabled` lists them too, and the
`ENABLED` column tells them apart. A person whose enabled state Graph does not
return is listed, so a gap in the data cannot hide anyone. A manager whose
enabled state is not returned is not counted as disabled.

Rows are ordered by manager, then by name, so each disabled manager's people
sit together. The table and `--plain` columns are `NAME`, `SIGN-IN NAME`,
`ENABLED`, `DEPARTMENT`, `MANAGER` and `MANAGER SIGN-IN NAME`. `--json` gives
each person's summary record with a `manager` object (`id`, `displayName`,
`userPrincipalName`, `accountEnabled`), and honours `--wrap-untrusted`.

`--disabled-manager` cannot be combined with `--all`, `--group`,
`--sign-in-activity` or `--manager`; for those, filter the export instead.

```bash
# People whose manager is disabled, leaving out disabled accounts.
entra user disabled-manager

# Each disabled manager once.
entra user disabled-manager --plain --select "MANAGER SIGN-IN NAME" | sort -u
```

## Global flags

| Flag | Effect |
|---|---|
| `--json` | Machine-readable output with an envelope |
| `--plain` | Lists and tables as tab-separated values, no header row; the `user get` summary prints `Label: value` lines, `user get --all`/`--group` print JSON, and `auth` and `version` print sentences |
| `--select COLUMN,COLUMN` | Show only these table or `--plain` columns, by header name such as `NAME,EMAIL`; a name with no matching column is an error; no effect on `--json`, the `user chain` tree, or the `user get` record and its `--all`/`--group` views |
| `--results-only` | Drop the JSON envelope, leaving the result value |
| `--account ADDRESS` | Pin execution to a stored identity, selected by primary email, UPN or proxy address |
| `--timeout N` | Request timeout in seconds; 0 means 60, and values above 600 are clamped to 600 |
| `--verbose` | Underlying request detail on stderr |
| `--color auto\|never\|always` | Accepted for compatibility; output is not coloured |
| `--no-write` | Refuse any mutating operation; every command is read-only today |
| `--no-input` | Fail rather than prompt; use in automation |
| `--wrap-untrusted` | Mark directory free-text as untrusted content |

Each has an `ENTRA_`-prefixed environment variable; see
[auth.md](auth.md#environment-variables).

For user commands without `--account`, the default stored account is tried
first. Only a typed Graph authorization failure causes `entra` to try another
authenticated account. This is useful when a normal account handles ordinary
lookups but a separately stored admin identity is required for sign-in
activity. Diagnostics naming the rejected identity go to standard error,
keeping JSON stdout valid. Explicit `--account` disables this fallback.

`--wrap-untrusted` is worth setting whenever output feeds a language model.
Display names and job titles are free text that people control, and a directory
is not a trusted source of instructions.

## Examples

```bash
# Who does someone report to?
entra user manager jane.doe@example.com

# The management line upwards.
entra user chain jane.doe@example.com

# Is this address an alias of that one?
entra user get shared-inbox@example.com --group addresses --json

# Everyone reporting to a manager, tab-separated.
entra user reports manager@example.com --plain

# Which distribution lists is someone on, and where are they managed?
entra user groups jane.doe@example.com --kind distribution

# Resolve a half-remembered name.
entra user search "jane"

# Everyone, with their managers, for a script to analyse.
entra user list --manager --json --results-only
```
