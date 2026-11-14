# Authentication and permissions

`entra` requires an app registration in your own Microsoft Entra ID directory.
It uses delegated Microsoft Graph permissions to inspect users, email
addresses, reporting lines, group memberships, licences and Copilot usage
reports without modifying directory data.

Reading another person's manager requires delegated `User.Read.All`. That
permission needs administrator consent and covers the whole directory. Keeping
the grant on a separate read-only tool rather than on a chat or mail client
lets administrators review, assign and revoke it independently.

## Before you start

`entra` does not ship with a built-in app registration. Every organisation
creates its own registration in its own directory.

An **app registration** identifies the application during sign-in. It defines
an **application (client) ID**, the permissions the application may request,
and the redirect addresses Microsoft accepts. Registering the application in
the admin center also creates an **enterprise application** (service
principal) in the same directory; the setup script creates or reuses it
explicitly. The enterprise application records administrator consent and
controls which users or groups may sign in through the app.

`entra` is a **public client**. Because it runs on user workstations, it holds
no client secret and no certificate. Sign-in uses the Open Authorization
(OAuth) 2.0 device authorization grant ("device code") or the authorization
code flow with Proof Key for Code Exchange (PKCE). Both flows require only the
application (client) ID and the directory (tenant) ID. Neither identifier is a
secret.

Before setting up the registration, confirm you have:

- A Microsoft Entra ID directory and its **directory (tenant) ID** (a
  universally unique identifier, UUID).
- A role permitted to register applications. Microsoft Entra allows member
  users to register applications by default. If your organisation restricts
  registration, you need Application Developer or a higher role.
- A role permitted to grant tenant-wide administrator consent for delegated
  Microsoft Graph permissions, such as Cloud Application Administrator,
  Application Administrator or Privileged Role Administrator.
- The `entra` binary. See the [README](../README.md#install).

## Delegated permissions, and what each one allows

`entra` requests delegated permissions. Delegated access runs as the signed-in
user, within the limits of Microsoft Graph's permission and role checks for
that account.

| Permission | Admin consent | Requested by | Needed by | Microsoft Graph access |
|---|---|---|---|---|
| `User.Read` | No | Every sign-in | `entra whoami`; sign-in `/me` check | Read the signed-in user's profile |
| `offline_access` | No | Every sign-in | Token renewal and `entra auth refresh` | Issue refresh tokens so you do not sign in again when the access token needs renewal |
| `User.ReadBasic.All` | No | Every sign-in | `entra user search`; basic `entra user get` | Read display name, given name, surname, mail, sign-in name, object ID and photo for all users |
| `User.Read.All` | Yes | `--directory`, `--lifecycle`, `--groups`, `--licences`, `--reports` | `user manager`, `user reports`, `user chain`, `user list`, `user disabled-manager`, full `user get`, `--all`, `--group` | Read all users' full profiles, manager relationships and direct reports |
| `AuditLog.Read.All` | Yes | `--directory` | `--sign-in-activity` and `--group signinactivity` on `user get` and `user list` | Read directory audit and sign-in logs, including `signInActivity` |
| `User-LifeCycleInfo.Read.All` | Yes | `--lifecycle` | `employeeLeaveDateTime` in `--all` and `--group organisation` | Read users' lifecycle dates, including scheduled leave dates |
| `GroupMember.Read.All` | Yes | `--groups` | `entra user groups` | Read all groups' basic properties and memberships |
| `LicenseAssignment.Read.All` | Yes | `--licences` | `entra licences list`; licence names in `licences holders --sku` | Read subscribed stock-keeping units (SKUs) and user licence assignments |
| `Reports.Read.All` | Yes | `--reports` | `entra reports copilot-usage`, `copilot-summary`, `copilot-trend` | Read Microsoft 365 usage reports, including per-user activity |
| `ReportSettings.Read.All` | Yes | `--reports` | `entra reports settings` | Read tenant report settings, such as whether user names are concealed |

Note: Microsoft defines which permissions require administrator consent and
what each scope allows. Tenant policies can also restrict user consent.

With no scope flags, `entra auth login` requests `offline_access`, `User.Read`
and `User.ReadBasic.All`. Adding `--directory` also requests `User.Read.All`
and `AuditLog.Read.All`. The flags `--lifecycle`, `--groups`, `--licences` and
`--reports` each add `User.Read.All` plus their feature-specific scope or
scopes. All four combine with `--directory`.

The built-in scope flags do not request `Directory.Read.All`, `Group.Read.All`
or any write permission. However, `auth login` and `auth refresh` accept
arbitrary `--scope` values without a read-only allowlist. The setup script
likewise accepts custom `SCOPES`. Every Graph request that `entra` sends uses
HTTP `GET`, so its directory commands remain read-only.

`AuditLog.Read.All` grants read access to all tenant sign-in and audit logs,
not only one user property. If you do not want that grant, omit
`AuditLog.Read.All` from `SCOPES` when running the setup script. Then sign in
without `--directory` by passing `--scope User.Read.All`.

`--lifecycle`, `--groups`, `--licences` and `--reports` stay outside
`--directory` because requesting an unconsented permission typically causes
sign-in or refresh to fail. Keeping them separate lets `--directory` work in
tenants that consented only to `User.Read.All` and `AuditLog.Read.All`.

### Sign-in activity requirements and fallback

Request sign-in activity with `--sign-in-activity` or `--group signinactivity`
on `user get` and `user list`. Both forms have the same permission
requirements. According to Microsoft documentation, reading `signInActivity`
requires `AuditLog.Read.All` plus:

- A **Microsoft Entra ID P1 or P2** licence in the tenant.
- A supported Microsoft Entra role on the **signed-in account**. **Reports
  Reader** is the least-privileged built-in role.

When Microsoft Graph rejects a request that includes `signInActivity` with a
typed permission or unsupported-role error, `entra` handles it as follows:

- Without `--account`, `user` commands first retry the full request across any
  other stored accounts.
- If `user get` ran with `--sign-in-activity` together with `--all` or
  `--group`, and no tried account is permitted, `entra` warns on standard
  error and retries the read without `--sign-in-activity`.
- Standalone `user get --sign-in-activity` does not use that omission
  fallback. Neither does `user list`, or a request that selects sign-in
  activity only through `--group signinactivity`. Those commands fail so
  focused queries and directory exports never omit requested data.

`signInActivity` is absent for accounts with no recorded sign-ins. Microsoft
documents different start dates per timestamp. Interactive sign-in history
(`lastSignInDateTime`, which records interactive attempts including failures)
begins in April 2020. Non-interactive history
(`lastNonInteractiveSignInDateTime`) begins in May 2020.
`lastSuccessfulSignInDateTime` became available in December 2023 without
backfill for earlier sign-ins.

### Scheduled leave dates

`employeeLeaveDateTime` (included in `--all` and `--group organisation`)
requires delegated `User-LifeCycleInfo.Read.All` and a supported role on the
signed-in account. Supported roles include Lifecycle Workflows Administrator,
Global Reader and Global Administrator. Before reading a `null` leave date
as "no leave date scheduled", check that the permission was consented and
that the signed-in account holds one of those roles. Microsoft documents
those prerequisites but not what Graph returns without them.

After an administrator grants consent, add the scope to your session:

```bash
entra auth refresh --directory --lifecycle
```

### Group memberships

`entra user groups` reads `memberOf` and `transitiveMemberOf`. Microsoft
documents that with `User.Read.All` alone, Microsoft Graph returns limited
membership objects containing only object IDs and types, without group display
names. `entra` requires `GroupMember.Read.All` to read group properties. It
treats any returned group with an empty display name as a permission error
rather than printing nameless rows.

After an administrator grants consent, add the scope:

```bash
entra auth refresh --groups
```

### Tenant licences

`entra licences list` reads `/subscribedSkus`. `entra licences holders --sku
<name>` also reads `/subscribedSkus` when given a licence name rather than a
UUID SKU ID. Microsoft documents that delegated callers need
`LicenseAssignment.Read.All` and a supported directory role on the signed-in
account, such as Directory Readers or Global Reader. Passing a SKU ID (UUID)
to `licences holders --sku` skips `/subscribedSkus` and requires only
`User.Read.All`. Because a 403 refusal on `/subscribedSkus` can reflect either
a missing scope or a missing role, `entra` names both in its error message.

After an administrator grants consent, add the scope:

```bash
entra auth refresh --licences
```

### Copilot usage reports

The `entra reports` commands read Microsoft 365 Copilot usage reports from
Microsoft Graph's beta `/copilot/reports` routes and `/admin/reportSettings`
on v1.0. `copilot-usage`, `copilot-summary` and `copilot-trend` require
`Reports.Read.All`. `reports settings` requires `ReportSettings.Read.All`.
Microsoft's documentation for `/copilot/reports` lists AI Administrator and
Reports Reader as supported roles, and omits Global Reader for per-user
Copilot usage detail. Because report endpoints return HTTP 403 (with codes
such as `S2SUnauthorized`) for both missing scopes and missing roles, `entra`
reports both possibilities together.

`reports copilot-usage` also reads users' `companyName` and `department` from
`/users` (requiring `User.Read.All`) when at least one returned report row has
an unconcealed identity. Empty reports or reports where every row has a
concealed user name skip that directory read.

After an administrator grants consent, add the report scopes:

```bash
entra auth refresh --reports
```

### Which fields need `User.Read.All`

According to [Working with users in Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/users),
`User.ReadBasic.All` limits reads of other users to `id`, `displayName`,
`givenName`, `surname`, `mail`, `userPrincipalName` and `photo` (Microsoft's
user profile documentation also notes `securityIdentifier` in basic contexts).

Other user properties that `entra user get` requests in summary mode or with
`--all` and `--group` require `User.Read.All`, including:

```text
jobTitle            officeLocation      businessPhones
mobilePhone         department          employeeId
employeeType        accountEnabled      createdDateTime
proxyAddresses      otherMails          mailNickname
onPremisesSamAccountName                usageLocation
```

`proxyAddresses` lists the email aliases configured on a user's directory
record. Inspecting it shows whether two addresses belong to one directory user
object or two.

### There is no primaryEmail or secondaryEmail

The Microsoft Graph `user` resource has neither `primaryEmail` nor
`secondaryEmail`, so looking for them in Graph output finds nothing even when
`User.Read.All` is granted. Microsoft
Graph stores user addresses across these properties:

| Property | Directory meaning | Permission |
|---|---|---|
| `mail` | Primary Simple Mail Transfer Protocol (SMTP) address recorded on the user | `User.ReadBasic.All` |
| `userPrincipalName` | User principal name (UPN), the sign-in name; often uses email syntax, though it need not receive mail | `User.ReadBasic.All` |
| `proxyAddresses` | Mailbox proxy addresses recorded in the directory; uppercase `SMTP:` marks the primary address and lowercase `smtp:` marks an alias | `User.Read.All` |
| `otherMails` | Additional email addresses recorded for the user | `User.Read.All` |
| `mailNickname` | Mail alias (local part) | `User.Read.All` |

`entra user get` prints `proxyAddresses` under `Mailbox addresses:` and
`otherMails` under `Other addresses:`, displaying the two directory
properties separately. Actual mail delivery depends on your mail
routing configuration.

## Create the app registration

Register the application with either the included setup script or the
Microsoft Entra admin center.

### Method 1: the setup script

`contrib/create-entra-app.sh` creates or updates the app registration, creates
or reuses its enterprise application (service principal), adds delegated
Microsoft Graph permissions, restricts assignment when requested, and grants
tenant-wide admin consent.

Prerequisites:

- Bash and the [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (`az`).
- An active `az login` session in the target tenant, signed in with the roles
  listed in [Before you start](#before-you-start). The script checks `az
  account show` and exits if the active Azure CLI tenant does not match
  `TENANT_ID`.
- `jq`, if you rely on automatic discovery of a saved `TENANT_ID` or
  `CLIENT_ID` from `entra`'s `config.json`. Saved-ID discovery matches
  `ENTRA_ACCOUNT` (or `default_account`) against canonical keys in
  `config.json`, ignoring case. It looks in macOS
  (`~/Library/Application Support/entra`) or X Desktop Group (XDG)
  (`${XDG_CONFIG_HOME:-$HOME/.config}/entra`) paths. On Windows Bash, set
  `ENTRA_CONFIG_DIR` explicitly or pass `TENANT_ID` and `CLIENT_ID`.

Run the script for a new registration:

```bash
export TENANT_ID=<tenant-id>
az login --tenant "$TENANT_ID"
ASSIGN_USERS="you@example.com" ./contrib/create-entra-app.sh
```

At completion, the script prints the application (client) ID, a verification
command and the `entra auth login` command to run next.

#### Assignment requirements and access control

Tenant-wide admin consent applies to the application across the directory. If
an enterprise application does not require user assignment, ordinary users in
the tenant can sign in through it and exercise consented delegated scopes such
as `User.Read.All`.

To prevent accidental tenant-wide exposure, the script refuses to run unless
at least one of these conditions holds:

- You set `ASSIGN_USERS` or `GROUP_OBJECT_ID`.
- You update an existing registration (`CLIENT_ID`) whose service principal
  already has `appRoleAssignmentRequired=true`.
- You set `ALLOW_ALL_TENANT_USERS=1`.

How assignment settings behave:

- When `ASSIGN_USERS` or `GROUP_OBJECT_ID` is set, the script sets
  `appRoleAssignmentRequired=true` on the service principal **before**
  granting admin consent. It then adds app-role assignments (using the default
  all-zero `appRoleId`) for the supplied principals. Existing user or group
  assignments on the service principal remain in place; the supplied variables
  add principals rather than replacing the current access list.
- Unassigned regular users receive `AADSTS50105` when they try to sign in.
  Microsoft documents that the assignment requirement does not apply to
  Global Administrators; see Microsoft's
  guide on [restricting an app to a set of users](https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users).
- When `ALLOW_ALL_TENANT_USERS=1` is set without `ASSIGN_USERS` or
  `GROUP_OBJECT_ID`, the script leaves `appRoleAssignmentRequired` unchanged.
  On a newly created app, `appRoleAssignmentRequired` defaults to `false`, so
  any tenant user can sign in. On an app that already requires assignment,
  that restriction stays enabled.

#### Script environment variables

| Variable | Effect |
|---|---|
| `TENANT_ID` | Target directory (tenant) UUID. Falls back to `ENTRA_TENANT_ID`, then to the tenant saved in `config.json` (`common` is rejected). |
| `CLIENT_ID` | Existing application (client) ID to update. Falls back to `ENTRA_CLIENT_ID`, then to the client ID saved in `config.json`. When unset, the script creates a new app registration even if another registration already has `APP_NAME`. |
| `APP_NAME` | Display name for a newly created registration. Defaults to `Entra CLI (read-only directory lookups)`. |
| `SCOPES` | Space-separated Microsoft Graph delegated permission names to resolve and add. Defaults to all ten permissions in the table above. |
| `GROUP_OBJECT_ID` | Group object UUID to assign, and enable `appRoleAssignmentRequired=true`. |
| `ASSIGN_USERS` | Space-separated UPNs or user object IDs to assign, and enable `appRoleAssignmentRequired=true`. |
| `ALLOW_ALL_TENANT_USERS=1` | Permit running without `ASSIGN_USERS` or `GROUP_OBJECT_ID` when the app is not already restricted; leaves `appRoleAssignmentRequired` unchanged. |

#### Running the script again

After you sign in once with `entra auth login`, `config.json` holds the
account's `client_id` and `tenant_id`. On macOS and Linux with `jq` installed
(or with `ENTRA_CONFIG_DIR` set on Windows), re-running the script updates
that registration in place without needing `CLIENT_ID` or `TENANT_ID`. If the
service principal already requires assignment, you do not need to pass
assignment variables again:

```bash
./contrib/create-entra-app.sh
entra auth refresh --directory --lifecycle
```

Permission declarations and assignments are additive on a re-run: removing
an entry from an input variable does not delete it. The script grants admin
consent again on every run, and Microsoft warns that granting tenant-wide
consent can change existing tenant-wide grants, so check the grants afterwards
(see [Check that consent was granted](#check-that-consent-was-granted)).

- The script queries Microsoft Graph's service principal
  (`00000003-0000-0000-c000-000000000000`) dynamically for each scope name's
  permission UUID and adds missing delegated scopes. Removing a scope from
  `SCOPES` does not remove it from the app registration.
- Removing a user or group from `ASSIGN_USERS` or `GROUP_OBJECT_ID` does not
  delete their existing assignment. Already-assigned principals are skipped.
- When updating an existing `CLIENT_ID`, the script does not modify the
  registration's display name, sign-in audience, redirect URIs or
  `isFallbackPublicClient` setting.
- Each entry in `ASSIGN_USERS` is looked up with `az ad user show --id`, which
  accepts a UPN or object ID. Because a person's UPN can differ from their
  email address, check it with `az ad user show --id <upn-or-id> --query
  userPrincipalName -o tsv`. Unresolved users print a warning and are skipped
  without making the script exit non-zero. Other `az rest` assignment errors
  abort the script.

### Method 2: the Microsoft Entra admin center

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com)
   and open **Entra ID > App registrations > New registration**.
2. Enter a display name, such as `Entra CLI (read-only directory lookups)`.
3. Under **Supported account types**, select **Accounts in this organizational
   directory only** (single tenant).
4. Under **Redirect URI**, select **Public client/native (mobile & desktop)**
   and enter `http://localhost/callback`. Select **Register**.

   Browser sign-in binds a random loopback port on `127.0.0.1` and sends
   `http://localhost:<port>/callback`. Microsoft Entra ignores the port when
   matching `http://localhost` redirect URIs on public clients, so one entry
   covers any port.
5. On **Overview**, copy **Application (client) ID** and **Directory (tenant)
   ID**.
6. Open **Authentication**. Under **Advanced settings**, set **Allow public
   client flows** to **Yes** and select **Save**. Device-code sign-in requires
   this setting.
7. Open **API permissions > Add a permission > Microsoft Graph > Delegated
   permissions**. Add `User.Read`, `offline_access`, `User.ReadBasic.All` and
   `User.Read.All`, plus any optional scopes your users need:
   `AuditLog.Read.All` (sign-in activity), `User-LifeCycleInfo.Read.All`
   (scheduled leave dates), `GroupMember.Read.All` (`user groups`),
   `LicenseAssignment.Read.All` (`licences list` and SKU names), and
   `Reports.Read.All` with `ReportSettings.Read.All` (`reports`).
8. To restrict who may use the app before granting tenant-wide consent, open
   **Entra ID > Enterprise applications** and select the application with the
   same name. Under **Properties**, set **Assignment required?** to **Yes**
   and select **Save**.
9. Under **Users and groups** on that enterprise application, select **Add
   user/group** and assign the users or groups permitted to run `entra`.
10. Return to the app registration's **API permissions** page, select **Grant
    admin consent for \<your organisation\>** and confirm. Every required
    permission should show granted status.

The admin-consent prompt states that consent applies to all users in the
organisation. Setting **Assignment required?** to **Yes** and assigning
specific users or groups restricts who can sign in (subject to Microsoft
Entra's Global Administrator exemption).

### Adding a permission to an existing registration

To add a single Microsoft Graph permission with Azure CLI, pass the published
Microsoft Graph application ID (`00000003-0000-0000-c000-000000000000`) and
the delegated scope ID (for example `e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20` for
`AuditLog.Read.All`). Then grant admin consent and refresh:

```bash
az ad app permission add \
  --id <application-client-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20=Scope
az ad app permission admin-consent --id <application-client-id>
entra auth refresh --directory
```

### Check that consent was granted

List the delegated permission grants recorded in Entra ID:

```bash
az ad app permission list-grants \
  --id <application-client-id> \
  --show-resource-name -o table
```

Then test with `entra`, pinning `--account` so `user manager` cannot switch to
another signed-in identity:

```bash
entra --account you@example.com auth status
entra --account you@example.com user manager someone-else@example.com
```

If `auth status` succeeds, the selected identity's token can read `/me`. A
failure on `user manager` does not automatically prove missing admin consent:
inspect the actual error code, the scopes requested at sign-in, the target
user and the account used. Without `--account`, `user` commands can also
switch to another stored identity on authorization refusals.

## Sign in

Sign in with `entra auth login` using your registration's client ID and tenant
ID.

### Registration resolution and ID validation

At `auth login`, `entra` resolves the client ID in this order:

1. `--client-id`, or `ENTRA_CLIENT_ID`.
2. The registration saved in `config.json` for `--account` (matched
   case-insensitively against canonical stored account emails only, without
   `/me` alias lookups), or else for `default_account`.
3. The single registration shared by every entry in `config.json`, when all
   saved entries have the same client ID and tenant ID. If saved accounts use
   different registrations, `entra` fails and asks for `--client-id` or
   `--account`.

The tenant ID resolves in this order:

1. `--tenant-id`, or `ENTRA_TENANT_ID`.
2. When `--client-id` was given explicitly: the tenant saved for `--account`
   (or `default_account`) if that entry used the same client ID, or else the
   single tenant shared by all saved entries for that client ID. If that
   client ID is saved against multiple tenants, `entra` fails and asks for
   `--tenant-id` or `--account`.
3. When reusing a saved client ID: that entry's saved tenant ID.
4. `common` (which single-tenant app registrations reject with `AADSTS50194`).

Validation rules:

- Client IDs must parse as UUIDs.
- Tenant IDs must parse as UUIDs or equal `common`, `organizations` or
  `consumers`. Tenant domain names such as `example.com` are rejected.
- `--no-input` (or `ENTRA_NO_INPUT=true`) rejects `auth login` before
  authentication starts because both login flows are interactive.

`auth login` prints the chosen client ID and tenant ID (and the saved account
name when reusing one) to standard error before starting authentication. After
sign-in succeeds, both IDs are saved in `config.json` and in the account file.
Later logins, token refreshes and Graph commands do not need `--client-id`,
`--tenant-id` or the environment variables. Post-login commands read the IDs
saved for the selected account and ignore `ENTRA_CLIENT_ID` and
`ENTRA_TENANT_ID`. Administrators can distribute `ENTRA_CLIENT_ID` and
`ENTRA_TENANT_ID` to users through shell profiles or device management, so the
first sign-in needs no flags.

### Device-code and browser flows

Device-code sign-in is the default. It prints a verification URL and a user
code on standard error. Open that URL in a browser, on this or any other
device, enter the code and sign in. It suits headless or remote machines:

```bash
entra auth login --directory \
  --client-id <application-client-id> \
  --tenant-id <tenant-id>
```

Device polling clamps the server interval to 1-120 seconds and expiry to at
most 3600 seconds. It backs off on `slow_down` and suggests retrying with
`--browser` if Microsoft returns `access_denied` or `invalid_grant` (for
example when Conditional Access blocks device-code flows or requires a
compliant device).

Pass `--browser` to use the authorization code flow with PKCE and a loopback
listener on `127.0.0.1`:

```bash
entra auth login --browser --directory \
  --client-id <application-client-id> \
  --tenant-id <tenant-id>
```

`--browser` sends `prompt=select_account` so Microsoft shows its account
picker rather than silently reusing an active browser session. It prints the
authorization URL on standard error if the system browser cannot open, waits
up to 15 minutes for the loopback callback, and validates the OAuth `state`
parameter before accepting a code or reporting a callback error. OAuth
requests, and the `/me` request that completes sign-in, use a fixed 30-second
timeout; `--timeout` and `ENTRA_TIMEOUT` apply to the Microsoft Graph requests
that commands make.

When sign-in finishes, `entra` reads `/me` and stores the account under
lowercase `mail`, falling back to lowercase `userPrincipalName` when `mail` is
empty. Confirm the stored account with:

```bash
entra auth list
entra whoami
```

If you sign in without `--directory`, `entra` prints a reminder that full
directory and sign-in-activity lookups need `--directory`. Add extra scopes
with repeatable `--scope <SCOPE>` flags; `entra` trims whitespace and removes
case-insensitive duplicates.

### Selecting among stored identities

You can store multiple signed-in accounts at once. Account selection and
fallback follow these rules:

- **Default account:** `auth login` sets `default_account` in `config.json`
  only when `default_account` is empty or does not match any stored account
  file. Subsequent logins preserve an existing valid default. When no valid
  default exists, selection starts with the first stored account in
  case-insensitive email order.
- **Privilege fallback (`user` commands only):** When `--account` is omitted,
  `entra user` commands try the default account first. If Microsoft Graph
  returns a typed permission or sign-in-activity role refusal, `entra` writes
  a `notice:` line to standard error and tries the remaining stored accounts
  in case-insensitive email order. Network, timeout and data errors never
  switch accounts.
- **Single-account commands:** `licences`, `reports`, `whoami`, `auth status`
  and `auth refresh` use one selected account (the default or `--account`) and
  never fall back. When a `licences` or `reports` command is refused under the
  default account, the error suggests `--account <email>`.
- **Explicit `--account`:** For commands that use stored credentials,
  `--account` (or `ENTRA_ACCOUNT`) pins execution to that selected identity
  and disables fallback. During `auth login`, `--account` selects saved
  registration metadata in `config.json`; it does not constrain which identity
  authenticates in the browser or device-code prompt.

How `--account` resolves an identifier against stored credentials:

1. If the identifier matches a stored account's canonical email
   case-insensitively, `entra` selects it locally without network calls.
2. Otherwise, `entra` reads `/me` for stored accounts and compares the
   identifier case-insensitively against `mail`, `userPrincipalName` and the
   address part of `proxyAddresses`. It never matches on display names.
3. A single `/me` match is selected even if another stored account could not
   be inspected. Multiple matches fail as ambiguous. If no match is found, the
   error lists the stored accounts and any accounts whose profiles were
   unavailable. Windows credential-lock errors (`CredentialLockBusy`,
   `CredentialLockFailed`) are returned directly rather than treated as an
   unmatched account.

```bash
entra --account alex.smith@login.example.test whoami
```

### Adding scopes without signing in again

After an administrator consents to a new permission, run `entra auth refresh`
to redeem the stored refresh token non-interactively (`auth refresh` remains
available when `--no-input` is set):

```bash
entra auth refresh --directory
```

`auth refresh` accepts `--directory`, `--lifecycle`, `--groups`, `--licences`,
`--reports` and repeatable `--scope <SCOPE>`:

```bash
entra auth refresh --scope User.Read.All
```

**Refresh is strictly additive.** With no scope flags, it requests the scopes
stored with the token. With flags, it strips any
`https://graph.microsoft.com/` prefix from stored scopes and merges the
requested scopes with every stored scope case-insensitively. Refresh never
narrows a session. To request fewer scopes, run `entra auth login` with only
the flags you want (note that Microsoft Entra may still return previously
consented scopes in issued tokens unless grants are revoked).

Microsoft Entra rejects the refresh if any requested or stored scope lacks
consent. If an administrator withdraws consent for a stored scope, run
`entra auth login` again without it.

### Signing out

Remove a stored account's local credential and account file with:

```bash
entra auth logout
entra auth logout jane.doe@example.com
```

`auth logout` chooses the account in this order: positional `ACCOUNT`, then
`--account` (or `ENTRA_ACCOUNT`), then the default account. Alias lookup works
the same way as `--account`.

Logout deletes the credential from the operating system (OS) store and removes
`accounts/<lowercase-email>.json`. Removing the current `default_account`
moves `default_account` to the first remaining stored account in
case-insensitive email order, or clears it when none remain. Logout does not
revoke Microsoft sessions or remove saved registration entries from
`config.json`.

## Token storage

Tokens live only in the OS credential store under service name **`entra`** and
key `entra:token:<lowercase-email>`. Here `<lowercase-email>` is the lowercase
`mail` (or lowercase `userPrincipalName` when `mail` is empty) from `/me`.
Tokens are never written to plain files, and the service name stays separate
from other Microsoft Graph tools.

| Platform | Credential store | Behaviour |
|---|---|---|
| macOS | Login Keychain | One generic-password item per account, carrying an account-specific `entra` label and description `Microsoft Entra ID access token`. Updates modify the item and metadata in place so Keychain access-control lists (ACLs) remain intact. |
| Windows | Credential Manager | Because Credential Manager limits a single blob to 2560 bytes, `entra` splits each token across several entries and serialises access with a per-user lock file (`%LOCALAPPDATA%\entra\credentials.lock`). |
| Linux | Kernel key-retention service (`keyutils`) | One entry per account in kernel memory only (not Secret Service). Entries need no desktop session, do not survive a reboot, and expire after kernel inactivity timeouts; see [troubleshooting](troubleshooting.md#could-not-be-found-in-the-keyring). |

Platform details:

- **macOS item label and code signing:** Keychain items carry an
  account-specific label, `entra — <lowercase-email>`, and the description
  "Microsoft Entra ID access token", so authorization prompts identify both
  the CLI and the account.
  Keychain "Always Allow" grants are tied to the binary's code-signing
  identity. Official releases from `v0.1.1` onward use a stable Developer ID
  signature (`com.aberoham.entra`, team `2VLHJGU477`), so grants can survive
  upgrades. Local `cargo build` binaries use ad-hoc signatures that change on
  every build and can trigger new prompts; use `./contrib/resign.sh` or
  `./contrib/install.sh` for source builds (see
  [troubleshooting](troubleshooting.md#macos-keychain-prompts-after-every-upgrade)).
  `--no-input` does not suppress OS credential-store authorization dialogs.
- **Windows lock and update guarantees:** The exclusive lock file is per OS
  user, covers Credential Manager reads, writes and deletes, and is released
  before network refresh calls. It stays under `%LOCALAPPDATA%\entra\` even
  when `ENTRA_CONFIG_DIR` moves config files. Contention times out after 10
  seconds with `CredentialLockBusy`; failures finding, creating, opening or
  locking the file return `CredentialLockFailed`. The lock covers one machine
  only and does not serialise roaming credentials across machines. The token
  is split into numbered chunks; the canonical entry holds a header pointing
  to the chunks in one of two alternating sets, and sign-out deletes the
  header before removing the chunks from both sets. During writes, failures before the header entry switches preserve the previous
  credential; after the header switches, the new credential is live, though a
  failure while deleting old entries still makes the operation return an
  error.

### Configuration and account metadata files

Non-secret metadata is stored under the platform configuration directory
(override with `ENTRA_CONFIG_DIR`):

| Platform | Default configuration directory |
|---|---|
| macOS | `~/Library/Application Support/entra/` |
| Linux | `$XDG_CONFIG_HOME/entra/` (usually `~/.config/entra/`) |
| Windows | `%APPDATA%\entra\` |

Metadata files:

- `config.json`: holds `default_account` and the `clients` map of `client_id`
  and `tenant_id` per account. Loading `config.json` rejects symlinks and, on
  Unix-like systems, repairs file permissions broader than `0600`.
- `accounts/<lowercase-email>.json`: holds `email`, `display_name`,
  `tenant_id`, `client_id` and `login_time` for each signed-in account.

On Unix-like systems, directories are created with mode `0700` and metadata
files are written atomically with mode `0600`.

### Token renewal and fallback

Commands reuse the stored access token until 60 seconds before its recorded
expiry (`expires_at`). When background refresh runs:

- If background refresh fails for any reason, `entra` reuses the existing
  access token while its recorded expiry has not passed (logged in
  `--verbose` output). Once hard-expired, the command fails.
- If refresh succeeds on the network but saving to the credential store fails,
  the current command uses the newly issued token and reports the persistence
  failure only in `--verbose` output.
- Explicit `entra auth refresh` requires both the network refresh and
  credential-store persistence to succeed.

## Diagnostics

Check saved accounts, live token validity and request details with:

```bash
entra auth list            # list saved account metadata (* marks default)
entra auth status          # test the selected account's token against /me
entra whoami               # show the directory profile of the selected account
entra --verbose <command>  # print Graph URLs and OAuth steps on standard error
```

`auth list` enumerates saved `accounts/*.json` metadata only. It does not
check whether credentials still exist in the OS store or whether Microsoft
Entra still accepts them (important after a Linux reboot or keyring expiry).
Use `auth status` to perform a live Microsoft Graph `/me` call.

### JSON output and error codes

All `auth` commands honour `--json`, returning `{"results": ..., "count":
...}` (or the inner value alone with `--results-only`):

- `auth login --json`: `{"account", "displayName", "tenantId", "clientId"}`
  (`displayName` honours `--wrap-untrusted`).
- `auth refresh --json`: `{"account", "expiresAt", "scope"}`.
- `auth logout --json`: `{"account", "signedOut": true}`.
- `auth list --json`: array of `{"email", "display_name", "tenant_id",
  "client_id", "login_time"}` objects.
- `auth status --json`: the `whoami` user profile in `results`, with
  `"account"` and `"expiresAt"` (the actual expiry of the token used, even if
  persistence failed) added to the envelope.

In `--json` mode, errors print `{"error": {"code": ..., "status": ...,
"message": ...}}` on standard output and exit `1`:

| Error code | Meaning |
|---|---|
| `Authorization_RequestDenied` | HTTP 403 missing-permission error classified by `entra` |
| `Authentication_RequestFromUnsupportedUserRole` | HTTP 403 unsupported Entra role for `signInActivity` |
| `CredentialLockBusy` | Windows `credentials.lock` timed out after 10 seconds (`status` 0) |
| `CredentialLockFailed` | Windows `credentials.lock` could not be found, opened or locked (`status` 0) |
| Preserved Graph or OAuth code | Server error code (such as `S2SUnauthorized`) with HTTP status. Exceptions return `CommandFailed` with `status` 0: device-code `access_denied` and `invalid_grant`, browser callback errors, and a failed profile request during sign-in |
| `CommandFailed` | Local validation, keyring or wrapped error (`status` 0); `consent_required` / `AADSTS65001` on `auth refresh` is converted to `CommandFailed` with remedial guidance |

## Environment variables

Every global flag and login ID flag has an environment variable equivalent:

| Variable | Equivalent flag | Notes |
|---|---|---|
| `ENTRA_CLIENT_ID` | `auth login --client-id` | Read by `auth login` and `create-entra-app.sh`; ignored by post-login commands |
| `ENTRA_TENANT_ID` | `auth login --tenant-id` | Read by `auth login` and `create-entra-app.sh`; ignored by post-login commands |
| `ENTRA_ACCOUNT` | `--account` | Selects stored identity (or saved registration at `auth login`); also read by `create-entra-app.sh` |
| `ENTRA_JSON` | `--json` | Boolean (`true` or `false`) |
| `ENTRA_PLAIN` | `--plain` | Tab-separated or plain output |
| `ENTRA_SELECT` | `--select` | Comma-separated table or `--plain` column names |
| `ENTRA_RESULTS_ONLY` | `--results-only` | Omit the `{results, count}` JSON envelope |
| `ENTRA_TIMEOUT` | `--timeout` | Per-request timeout in seconds for command Graph requests (`0` means `60`, max `600`); OAuth requests and the sign-in `/me` request use a fixed 30-second timeout |
| `ENTRA_VERBOSE` | `--verbose` | Print request and authentication steps on standard error |
| `ENTRA_COLOR` | `--color` | Accepts `auto`, `never` or `always`; output is not coloured |
| `ENTRA_NO_WRITE` | `--no-write` | Guards against directory mutations; does not stop `auth login`, `auth refresh` or `auth logout` from updating local credentials and metadata |
| `ENTRA_NO_INPUT` | `--no-input` | Rejects `auth login` before authentication starts; `auth refresh` stays available; does not suppress OS credential-store dialogs |
| `ENTRA_WRAP_UNTRUSTED` | `--wrap-untrusted` | Mark directory free text with `[UNTRUSTED:<id>]` wrappers in JSON output; deep records, several `user list` exports and `auth list` are not wrapped, as `entra --help` lists under `--wrap-untrusted` |
| `ENTRA_CONFIG_DIR` | none | Override directory for `config.json` and `accounts/`; does not move OS keyring items or Windows `credentials.lock` |

## Microsoft references

- [Register an application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
- [Redirect URI restrictions, including localhost ports](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Grant tenant-wide admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)
- [Restrict an application to a set of users](https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users)
- [Access tokens in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [User.Read.All in the permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference#userreadall)
- [AuditLog.Read.All in the permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference#auditlogreadall)
- [GroupMember.Read.All in the permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference#groupmemberreadall)
- [LicenseAssignment.Read.All in the permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference#licenseassignmentreadall)
- [Working with users in Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/users)
- [User resource type properties](https://learn.microsoft.com/en-us/graph/api/resources/user)
- [signInActivity resource type](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity)
- [Roles allowed to read sign-in activity](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-analyze-activity-logs-with-microsoft-graph#common-errors)
- [List subscribed licences, with the roles a delegated caller needs](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list)
- [List a user's direct memberships](https://learn.microsoft.com/en-us/graph/api/user-list-memberof)
- [List a user's manager](https://learn.microsoft.com/en-us/graph/api/user-list-manager)
- [Get Microsoft 365 Copilot usage user detail](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/api/admin-settings/reports/copilotreportroot-getmicrosoft365copilotusageuserdetail)
