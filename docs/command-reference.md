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
| `entra user list` | `User.Read.All`; with `--sign-in-activity`, as for `user get --sign-in-activity` |
| `entra auth *` | none beyond sign-in |

See [auth.md](auth.md) for which fields fall on each side of that line.

## Auth

```text
entra auth login --client-id ID [--browser] [--directory] [--tenant-id ID] [--scope SCOPE]...
entra auth refresh [--directory] [--scope SCOPE]...
entra auth logout [EMAIL]
entra auth list
entra auth status
```

`--client-id` is required at login and has no default. `--directory` requests
`User.Read.All` and `AuditLog.Read.All`; without it, manager, reporting-line and
sign-in-activity lookups will not work. Sign-in activity additionally requires
an eligible licence and a supported role on the signed-in account.
`auth refresh` silently redeems the selected account's stored refresh token.
With no scope flags it retains the stored scope set; flags request an explicit
scope upgrade after the matching consent has been granted.

Account files are keyed by the primary email shown by `entra auth list`, but
`--account` also accepts that identity's sign-in name/UPN or a proxy address.
Alternate forms are resolved against `/me`; an explicit account pins the
operation to that identity and never enables privilege fallback.

## User lookups

```text
entra user get <upn|email|id>
entra user manager <upn|email|id>
entra user reports <upn|email|id>
entra user chain <upn|email|id> [--depth 10]
entra user search <query> [-n 25]
```

Any of a person's sign-in name, primary email address or object id is accepted.
A direct lookup that misses is retried as a search over `mail` and
`proxyAddresses`, so either address form works. Deep reads recognise an
address-shaped key and resolve it before requesting attributes, because Graph
requires an immutable object id for some projections such as
`signInActivity`. Callers never need to resolve or paste that id themselves.

`user get` prints every alias and marks which is primary — the way to establish
whether two addresses are one mailbox or two. Mailbox addresses
(`proxyAddresses`) and other addresses (`otherMails`) are listed separately,
because the second kind usually delivers somewhere else entirely. Entra has no
`primaryEmail`/`secondaryEmail` pair; see [auth.md](auth.md#there-is-no-primaryemail-or-secondaryemail).

`user chain` walks upwards from the named person, stopping at the top of the
line, at `--depth`, or on a cycle. Directories do contain cycles: somebody
recorded as their own manager, or a pair pointing at each other.

`user search` matches a prefix of display name, mail, sign-in name or surname.

### Deep inspection

`user get` has two modes. By default it prints a curated summary. With
`--all` it requests every scalar attribute Graph exposes and returns the
directory's own JSON, unmapped:

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
| `organisation` | Job title, department, company, employee id and type, hire and leave dates |
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
| `--all` | Every attribute in the groups above |
| `--group GROUP` | Only these groups (repeatable; wins over `--all`) |
| `--sign-in-activity` | `signInActivity`, alongside the summary fields when used alone |
| `--manager` | A `manager` object on every record: `id`, `displayName`, `userPrincipalName` and `accountEnabled`, or `null` when none is recorded |

Every record carries its object `id`, whichever groups are chosen, so records
can be joined to each other. A manager's `id` matches the `id` of that
person's own record, which is how a script walks management lines without a
request per person.

```bash
entra user list --all --manager --json --results-only > directory.json
```

With `--sign-in-activity`, a refused request fails the whole command. It does
not drop the column and carry on, as `user get --all --sign-in-activity` does,
because an export missing data it was asked for would look complete to the
script reading it.

The export is not wrapped by `--wrap-untrusted`, the same as deep `user get`
output; the summary list is.

## Global flags

| Flag | Effect |
|---|---|
| `--json` | Machine-readable output with an envelope |
| `--plain` | Tab-separated, no header decoration |
| `--select field,field` | Restrict output to named fields |
| `--results-only` | Drop the JSON envelope, leaving the result value |
| `--account ADDRESS` | Pin execution to a stored identity, selected by primary email, UPN or proxy address |
| `--timeout N` | Request timeout in seconds, clamped to 600 |
| `--verbose` | Underlying request detail on stderr |
| `--no-write` | Refuse any mutating operation |
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

# The whole line up to the top.
entra user chain jane.doe@example.com

# Is this address an alias of that one?
entra user get shared-inbox@example.com --json --select proxyAddresses

# Everyone reporting to a manager, tab-separated.
entra user reports manager@example.com --plain

# Resolve a half-remembered name.
entra user search "jane"

# Everyone, with their managers, for a script to analyse.
entra user list --manager --json --results-only
```
