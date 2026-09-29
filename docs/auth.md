# Authentication and permissions

This guide takes you from nothing to a working `entra user get` in your own
Microsoft Entra ID directory. It explains the app registration the tool signs
in through, the delegated Microsoft Graph permissions each command needs, how
to sign in, and where tokens are stored.

The short version: **this tool exists because of one permission.** Reading
another person's manager needs delegated `User.Read.All`, an
administrator-consent permission that covers the whole directory. Keeping that
grant on a small read-only tool, rather than on a chat or mail client, means it
can be reviewed, assigned and revoked on its own.

## Before you start

`entra` does not ship with an app registration. Every organisation that uses it
creates its own, in its own directory. This section explains why.

An **app registration** is the record in Microsoft Entra ID that identifies an
application during sign-in. It carries an **application (client) ID**, the
permissions the application may request, and the addresses Microsoft may send
a sign-in response to. When you register an application, Entra ID also creates
an **enterprise application** (a service principal) in the same directory. The
enterprise application controls who may use the app and records the consent
that an administrator granted.

`entra` is a **public client**. It runs on your computer, so it cannot keep a
secret. It therefore uses no client secret and no certificate. Sign-in uses the
OAuth 2.0 device authorization grant ("device code") or the authorization code
flow with Proof Key for Code Exchange (PKCE). Both flows need only the client
ID and the directory (tenant) ID, and neither ID is a secret.

You need:

- A Microsoft Entra ID directory, and its **directory (tenant) ID**.
- A role that can register applications. By default any member user can; if
  your organisation has turned that off, you need Application Developer or a
  higher role.
- A role that can grant tenant-wide admin consent to delegated Microsoft Graph
  permissions: Cloud Application Administrator, Application Administrator or
  Privileged Role Administrator.
- The `entra` binary. See the [README](../README.md#install).

## Delegated permissions, and what each one allows

`entra` uses delegated permissions only. A delegated permission lets the tool
act as the signed-in person, so it can never read more than that person could.

| Permission | Admin consent | Needed by | What it lets the tool read |
|---|---|---|---|
| `User.Read` | No | `entra whoami`; every sign-in | Your own profile |
| `offline_access` | No | Every command after the first hour | Nothing; it issues a refresh token so you do not sign in every hour |
| `User.ReadBasic.All` | No | `entra user search`, basic `entra user get` | Display name, given name, surname, mail, sign-in name, object ID and photo for every user |
| `User.Read.All` | **Yes** | `entra user manager`, `user reports`, `user chain`, `user list`, the full record in `user get`, `--all` and `--group` | Every user's full profile and their manager and direct-report relationships |
| `AuditLog.Read.All` | **Yes** | `--sign-in-activity` on `user get` and `user list` only | Sign-in activity, and more generally the directory's audit and sign-in logs |

`entra auth login --directory` requests all five. Without `--directory`, the
tool requests only the first three.

The tool does not request `Directory.Read.All`, `Group.Read.All` or any write
permission. It cannot change a directory object.

### Sign-in activity has extra requirements

`AuditLog.Read.All` alone is not enough for `--sign-in-activity`. Microsoft
also requires:

- a **Microsoft Entra ID P1 or P2 licence** in the tenant, and
- a supported Entra role on the **signed-in account**. **Reports Reader** is
  the least-privileged built-in choice.

Without these, Graph fails the whole request. For this reason the
`signInActivity` field is opt-in per query, and `entra` retries a full-record
`user get` without it. `user list` does not: it fails, so that an export never
silently lacks a column it was asked for. The attribute is also empty for
anyone who has never signed in, or whose last sign-in was before April 2020.

### One attribute needs a permission `entra` does not request

`employeeLeaveDateTime`, in `--all` and the `organisation` group, is populated
only for callers who also hold `User-LifeCycleInfo.Read.All` and a supported
role. Without them Graph still answers the request, so `entra` does not
request that permission; the field is simply not reliable in its output.

`AuditLog.Read.All` grants read access to all of the tenant's sign-in and audit
logs, not just one field. If you do not need sign-in activity, leave it out:
set `SCOPES` without it when you run the setup script, and sign in without
`--directory` but with `--scope User.Read.All`.

### Which fields need `User.Read.All`

`User.ReadBasic.All` returns only this set for other people: `id`,
`displayName`, `givenName`, `surname`, `mail`, `userPrincipalName`,
`securityIdentifier` and the photo. See
[Working with users in Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/users).

Everything else `entra user get` prints needs `User.Read.All`, including:

```text
jobTitle            officeLocation      businessPhones
mobilePhone         department          employeeId
employeeType        accountEnabled      createdDateTime
proxyAddresses      otherMails          mailNickname
onPremisesSamAccountName                usageLocation
```

`proxyAddresses` is the property most people look for. It is the only reliable
way to find out whether two email addresses belong to one mailbox or to two.

### There is no primaryEmail or secondaryEmail

Those property names come from Google Workspace and do not exist in Microsoft
Graph. Asking for them returns nothing, which looks like a permissions problem
but is not one. The equivalents are:

| Property | What it holds | Permission |
|---|---|---|
| `mail` | The primary address | `User.ReadBasic.All` |
| `userPrincipalName` | The sign-in name, which need not receive mail | `User.ReadBasic.All` |
| `proxyAddresses` | Every address on the mailbox; `SMTP:` in upper case is primary, `smtp:` in lower case is an alias | `User.Read.All` |
| `otherMails` | Addresses recorded against the person but not on the mailbox, usually personal or recovery addresses | `User.Read.All` |
| `mailNickname` | The mail alias, that is, the local part | `User.Read.All` |

`entra user get` prints mailbox addresses and other addresses under separate
headings. A proxy address delivers to the mailbox you are looking at. An entry
in `otherMails` usually delivers somewhere else, often to a personal account.

## Create the app registration

Choose one of the two methods below. Both produce the same result.

### Method 1: the setup script

`contrib/create-entra-app.sh` does the whole sequence: registration, service
principal, API permissions, admin consent and user assignment. It needs the
[Azure command-line interface](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
(`az`) and Bash, and must run as a person who holds the roles listed in
[Before you start](#before-you-start).

```bash
export TENANT_ID=<tenant-id>
az login --tenant "$TENANT_ID"
ASSIGN_USERS="you@example.com" ./contrib/create-entra-app.sh
```

At the end it prints the new application (client) ID and the exact
`entra auth login` command to run next.

#### Why the script requires an assignment

**The script refuses to run without a user or group assignment** unless you set
`ALLOW_ALL_TENANT_USERS=1`. Admin consent is granted for the whole
organisation. An app that holds `User.Read.All` and has no assignment is a
directory-wide read that any user in the tenant can sign in and use.

When you give `ASSIGN_USERS` or `GROUP_OBJECT_ID`, the script sets
**Assignment required** on the enterprise application and assigns only those
principals. Other users then cannot sign in through the app, and get
`AADSTS50105` if they try.

`ALLOW_ALL_TENANT_USERS=1` lets the script run without an assignment. It does
not change **Assignment required**. On a new app that setting is off, so every
user in the tenant can sign in and read the full directory through the app. On
an app that already requires assignment, the restriction stays in place. Use
it only if that is what you want.

The script sets **Assignment required** before it grants admin consent. A run
that stops part way therefore never leaves a consented app open to every
user.

The script understands these variables:

| Variable | Effect |
|---|---|
| `TENANT_ID` | Required. The directory the app is created in. |
| `APP_NAME` | Display name; defaults to "Entra CLI (read-only directory lookups)". |
| `SCOPES` | Space-separated scope list; defaults to the five permissions above. |
| `GROUP_OBJECT_ID` | Assign a group, and require assignment. |
| `ASSIGN_USERS` | Space-separated sign-in names to assign, and require assignment. |
| `ALLOW_ALL_TENANT_USERS=1` | Allow any tenant user. Not the default. |

#### Running the script again

The script is safe to run again, for example to assign another person. It
patches the existing registration instead of creating a duplicate, reuses the
service principal, skips principals that are already assigned, and grants
admin consent again without harm.

A sign-in name that does not resolve is reported and skipped, so one typing
error does not stop the other assignments:

```bash
ASSIGN_USERS="alice@example.com bob@example.com" ./contrib/create-entra-app.sh
```

Use each person's **sign-in name** (user principal name), which is often not
their email address. `az ad user show --id <name> --query userPrincipalName -o
tsv` prints it.

### Method 2: the Microsoft Entra admin center

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com).
   Go to **Entra ID > App registrations > New registration**.
2. Enter a name, for example "Entra CLI (read-only directory lookups)".
3. Under **Supported account types**, select **Accounts in this organizational
   directory only** (single tenant).
4. Under **Redirect URI**, select **Public client/native (mobile & desktop)**
   and enter `http://localhost/callback`. Select **Register**.

   The browser sign-in listens on a random local port and sends
   `http://localhost:<port>/callback`. Entra ID ignores the port when it
   matches a `localhost` redirect URI, so the single entry above covers every
   port.
5. On the **Overview** page, copy the **Application (client) ID** and the
   **Directory (tenant) ID**. You need both to sign in.
6. Go to **Authentication**. Under **Advanced settings**, set **Allow public
   client flows** to **Yes**, then select **Save**. Device code sign-in needs
   this setting.
7. Go to **API permissions > Add a permission > Microsoft Graph > Delegated
   permissions**. Add `User.Read`, `offline_access`, `User.ReadBasic.All`,
   `User.Read.All` and `AuditLog.Read.All`. Leave out `AuditLog.Read.All` if
   you do not need sign-in activity.
8. Select **Grant admin consent for \<your organisation\>** and confirm. The
   **Status** column must show a green tick for every permission.
   `User.Read.All` and `AuditLog.Read.All` do not work until this is done.
9. Go to **Entra ID > Enterprise apps**, and open the application with the
   same name. Under **Properties**, set **Assignment required?** to **Yes** and
   select **Save**.
10. Under **Users and groups**, select **Add user/group** and add the people
    or groups who may use the tool.

The consent dialog says the grant applies to all users in your organisation.
That describes what the app may read; the assignment in steps 9 and 10
controls who can use it.

### Adding a permission to an existing registration

To add `AuditLog.Read.All` (for example) to an app you already have, use the
Microsoft Graph application ID and the permission's ID. Both are the same in
every tenant:

```bash
az ad app permission add \
  --id <application-client-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20=Scope
az ad app permission admin-consent --id <application-client-id>
entra auth refresh --directory
```

### Check that consent was granted

```bash
az ad app permission list-grants \
  --id <application-client-id> \
  --show-resource-name -o table
```

A test with the tool itself is better:

```bash
entra auth status
entra user manager someone-else@example.com
```

If `auth status` succeeds and `user manager` fails, the sign-in worked but
`User.Read.All` was not consented.

## Sign in

Use the two IDs from the app registration. `--client-id` is required and has
no default. Always pass `--tenant-id` for a single-tenant app: without it the
tool uses the `common` endpoint, which a single-tenant app rejects.

Device code is the default. The tool prints a code and a web address; open the
address on any device, enter the code and choose the account:

```bash
entra auth login --directory \
  --client-id <application-client-id> \
  --tenant-id <tenant-id>
```

`--browser` opens the system browser instead, and uses the authorization code
flow with PKCE and a local callback:

```bash
entra auth login --browser --directory \
  --client-id <application-client-id> \
  --tenant-id <tenant-id>
```

`--browser` always shows Microsoft's account picker, so it does not silently
reuse the account already signed in to the browser. Device code is the better
choice on a remote or headless machine, or to sign in as an account that is
not your browser session.

After sign-in, check which account landed:

```bash
entra auth list
entra whoami
```

`--directory` requests `User.Read.All` and `AuditLog.Read.All`. Without it the
sign-in works, but only `whoami`, `user search` and the basic `user get` fields
are available. The tool prints a reminder when you sign in without it. Extra
scopes can be added with repeatable `--scope` flags. They merge with the
defaults, and duplicates are removed without regard to case.

The client ID and tenant ID are saved with the account, so later commands and
refreshes do not need them again.

### Selecting among stored identities

You can sign in with more than one account. `entra auth list` shows the
primary email address used to store each one. `--account` accepts that
address, the sign-in name, or any proxy address that belongs to the same
identity:

```bash
entra --account alex.smith@login.example.test whoami
```

An explicit `--account` is strict: the tool uses only that credential. Without
`--account`, user lookups try the default account first. They move to another
stored account only after Graph returns a typed permission or role refusal, and
say so on standard error. A normal account can therefore coexist with a
separate administrator identity without making every command run as the
administrator.

The tool matches identities only on fields that Graph returns. It never guesses
from display names or similar-looking addresses, and a network or data error
never causes a switch to another account.

### Adding scopes without signing in again

After an administrator consents to another delegated permission, redeem the
stored refresh token for it without opening a browser:

```bash
entra auth refresh --directory
```

With no scope flags, `auth refresh` keeps the scopes already stored with the
token, so it never narrows a session by accident. Microsoft rejects the whole
refresh if any requested scope has not been consented.

## Token storage

Tokens are stored only in the operating system's credential store, under the
service name **`entra`** and the key `entra:token:<email>`. They are never
written to a file. The name is distinct from other Microsoft Graph tools, so
signing in here does not overwrite their tokens.

| Platform | Store | Notes |
|---|---|---|
| macOS | Keychain (login keychain) | One item per account, labelled `entra — <email>` and described as a Microsoft Entra ID access token. Refresh updates the item in place, which keeps its access-control list. |
| Windows | Credential Manager | An item holds at most 2560 bytes, which is smaller than many token bundles. The main item holds a small header, and numbered items such as `entra:token:<email>:0` hold the pieces. Each update writes a fresh set of pieces before switching the header, so a failed update leaves the previous sign-in intact. Logout removes every piece. |
| Linux | The kernel's key-retention service (keyutils) | One item per account, held in memory only. A reboot removes it, and the kernel expires it after a period without use, so expect to sign in again. It needs no desktop session. See [troubleshooting](troubleshooting.md#could-not-be-found-in-the-keyring). |

On macOS, the Keychain ties an "Always Allow" grant to the program's code
signature. A new binary, whether rebuilt or upgraded, asks again. See
[troubleshooting](troubleshooting.md#macos-keychain-prompts-after-every-upgrade)
to make the grant persist.

Non-secret account metadata (the client ID, tenant ID and default account) is
in an `entra` directory under the platform's configuration directory:

| Platform | Location |
|---|---|
| macOS | `~/Library/Application Support/entra/` |
| Linux | `$XDG_CONFIG_HOME/entra/`, usually `~/.config/entra/` |
| Windows | `%APPDATA%\entra\` |

On Unix-like systems the directories are created with mode `0700`. Set
`ENTRA_CONFIG_DIR` to use a different location.

Access tokens are reused until they are close to expiry. If a background
refresh fails for a transient reason, the tool uses the still-valid access
token until it expires. An explicit `auth refresh` treats any failure as an
error.

## Diagnostics

```bash
entra auth list            # which accounts have tokens, and which is default
entra auth status          # is the active token usable right now
entra whoami               # what the directory thinks you are
entra --verbose <command>  # request detail on standard error
```

`auth status` makes a real Graph call. A token that parses is not the same as a
token the directory still accepts.

## Environment variables

| Variable | Equivalent flag |
|---|---|
| `ENTRA_ACCOUNT` | `--account` |
| `ENTRA_JSON` | `--json` |
| `ENTRA_PLAIN` | `--plain` |
| `ENTRA_SELECT` | `--select` |
| `ENTRA_RESULTS_ONLY` | `--results-only` |
| `ENTRA_TIMEOUT` | `--timeout` |
| `ENTRA_VERBOSE` | `--verbose` |
| `ENTRA_NO_WRITE` | `--no-write` |
| `ENTRA_NO_INPUT` | `--no-input` |
| `ENTRA_WRAP_UNTRUSTED` | `--wrap-untrusted` |
| `ENTRA_CONFIG_DIR` | none (configuration location) |

## Microsoft references

- [Register an application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
- [Redirect URI restrictions, including localhost ports](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Grant tenant-wide admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)
- [Restrict an application to a set of users](https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users)
- [User.Read.All in the permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference#userreadall)
- [AuditLog.Read.All in the permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference#auditlogreadall)
- [Roles allowed to read sign-in activity](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-analyze-activity-logs-with-microsoft-graph#common-errors)
- [List a user's manager](https://learn.microsoft.com/en-us/graph/api/user-list-manager)
