# Troubleshooting

## Quick diagnostics

```bash
entra auth list      # who is signed in, and which account is default
entra auth status    # does the active token still work
entra whoami         # what the directory says you are
```

Run those three in order before anything else. Most reported faults here are
one of: wrong account active, missing scope, or an address that is not the one
the directory keys on.

## `Authorization_RequestDenied`

The token lacks the scope. It is **not** a statement about the person you
looked up, and no amount of correcting their address will fix it.

`entra` rewrites this error to name the missing permission, because the raw
Graph message reliably sends people hunting for a typo instead. If you see the
raw form, it came from something other than this tool.

Fix: make sure an administrator has consented to the permission named in the
error (`User.Read.All` or `AuditLog.Read.All`) for the app registration, then
refresh the current session or log in again:

```bash
entra auth refresh --directory
entra auth login --browser --directory \
  --client-id <application-client-id> \
  --tenant-id <tenant-id>
```

If login succeeds and the error persists, consent was never granted. See
[auth.md](auth.md#check-that-consent-was-granted).

## Sign-in fails with an `AADSTS` code

Microsoft reports sign-in failures as `AADSTS` error codes. These are the
common ones for this tool:

| Code | Cause | Fix |
|---|---|---|
| `AADSTS65001` or `consent_required` | An administrator has not consented to a requested permission. | Grant admin consent on the app registration, then sign in or refresh again. See [auth.md](auth.md#create-the-app-registration). |
| `AADSTS50105` | The app requires assignment and the signed-in user is not assigned. | Add the user, or a group they belong to, under **Enterprise apps > \<app\> > Users and groups**, or run the setup script again with `ASSIGN_USERS`. |
| `AADSTS700016` | The client ID was not found in the directory you signed in to. | Check `--client-id`, and pass the `--tenant-id` of the directory where the app is registered. |
| `AADSTS50194` | A single-tenant app was used with the `common` endpoint. | Pass `--tenant-id <tenant-id>`. The tool uses `common` only when no tenant is given. |
| `AADSTS7000218` | Public client flows are turned off, so device code sign-in fails. | Set **Authentication > Allow public client flows** to **Yes**. |
| `AADSTS50011` | The redirect URI does not match, so `--browser` sign-in fails. | Add the **Public client/native** redirect URI `http://localhost/callback`. |

## `no directory user matches "..."`

The address does not resolve. Two common causes, in order of likelihood:

1. **You used the wrong one of the person's two addresses.** Sign-in name and
   email address differ frequently — one person signs in as
   `alex.smith@login.example.test` and receives mail at
   `alex.smith@example.test`. `entra` already retries a direct miss as a
   search over `mail` and `proxyAddresses`, so a genuine failure here usually
   means neither form is right. Try `entra user search <surname>`.
2. **The account no longer exists.** People who leave are removed from the
   directory, but can remain in other systems that were never updated. If you
   are comparing another system against the directory, treat this as a
   finding.

The message means `entra` tried the value as a sign-in name/object id and also
searched primary mail and proxy addresses. Microsoft Graph's raw 404 adds “or
one of its queried reference-property objects are not present”; for `user get`
that wording is usually a distraction, because the direct `/users/{key}` route
simply does not accept an otherwise-valid mail alias. Deep `--all` and `--group`
lookups resolve address-shaped inputs to an immutable object id before reading
attributes, including when `signInActivity` is requested.

## `Authentication_RequestFromUnsupportedUserRole`

The app and token can have `AuditLog.Read.All` while the signed-in person still
lacks the Entra role Microsoft requires for sign-in reporting. If that person
needs the data, assign **Reports Reader**, the least-privileged built-in role,
then refresh or sign in again. If they do not need it, omit
`--sign-in-activity`; ordinary directory reads do not require that role.

`entra` identifies this Graph code directly. A focused activity request returns
the role guidance, while `--all --sign-in-activity` warns and retries the full
record without the unavailable field.

## "X has no manager recorded in the directory"

Not an error. The person exists and their manager field is empty.

This is a real and reasonably common state. Any process that routes work to a
person's manager, such as an approval flow, has nowhere to go for that person.
The tool reports it plainly rather than as a failure, so it can be counted.

## `no authenticated accounts are available`

No stored credential is available. Sign in, then inspect the canonical account
names:

```bash
entra auth login --directory --client-id <application-client-id> --tenant-id <tenant-id>
entra auth list
```

## `no authenticated account matches "..."`

`--account` accepts a stored identity's primary email, sign-in name/UPN or
proxy address, but does not guess based on display name. The error lists the
canonical stored accounts. Check the intended identity with `entra auth list`;
an address on somebody's normal employee account does not select a separate
admin account unless it is genuinely recorded as an alias of that admin
identity.

When `--account` is omitted, user commands try the default credential and then
other stored credentials only for typed authorization failures. Supplying
`--account` intentionally disables that fallback.

## Login succeeded as the wrong person

`--browser` login forces Microsoft's account picker, so the wrong account was
selected in it.

```bash
entra auth list          # confirm who actually landed
entra auth logout <email>
```

Sign in again and select the intended account. The device-code flow also shows
an account picker.

## "could not be found in the keyring"

This reads like "not logged in" and usually means "wrong address".

Tokens are keyed by the account's **primary email address**, not its sign-in
name. Check with `entra auth list`, which prints the addresses actually
stored.

On Linux, the same error usually means the token has gone from the kernel
keyring. `entra` stores Linux tokens in the kernel's key-retention service
(keyutils), which holds them in memory only. A reboot removes them, and the
kernel expires a user's persistent keyring after a period without use; the
default is a few days. Sign in again. There is no file fallback, and
`ENTRA_CONFIG_DIR` changes only where non-secret metadata is stored. The kernel
keyring needs no desktop session, so this works the same on a headless
machine.

## Token refresh fails

Normal commands refresh an access token shortly before expiry. A transient
failure during that early window does not discard a token that is still valid;
the command uses it until hard expiry. Once the access token has expired, a
failed or revoked refresh token requires a new login.

To pick up a newly consented permission deliberately, use `auth refresh`:

```bash
entra auth refresh --directory
```

If Microsoft returns `AADSTS65001` or `consent_required`, an administrator has
not granted every requested scope. Grant the permission to this app
registration, then repeat the refresh.

## Windows Credential Manager says the token is too large

`entra` splits a token bundle across 2560-byte raw credential entries on
Windows. The main `entra:token:<account>` entry holds a small header, and
numbered entries such as `entra:token:<account>:0` or
`entra:token:<account>:s1:0` hold the data. An update writes a complete new
set before switching the header, so an interrupted update keeps the previous
sign-in. `auth logout` removes every entry. If a size-limit error still appears, report it as a bug with the
output of `entra --verbose auth status`, after removing any tokens from it.

## Manager lookups work but `user get` shows few fields

You are signed in without `--directory`. `User.ReadBasic.All` returns only
display name, given name, surname, mail, sign-in name and object ID for other
people. Job title, office, phone numbers, `department`, `employeeId`,
`accountEnabled`, `createdDateTime` and `proxyAddresses` all need
`User.Read.All`.

## `query is too long` or `query contains a control character`

Input to `user search` and `user get` is bounded at 256 characters and rejects
control characters, so that malformed input fails locally with a clear message
rather than becoming an opaque Graph error. Shorten the query.

## macOS keychain prompts after every upgrade

macOS ties a keychain authorisation to the **identity of the program** that
asked for it. Releases from `v0.1.1` on are Developer ID signed with the stable
identifier `com.aberoham.entra`, so "Always Allow" persists from one signed
release to the next. Expect one more prompt on the first upgrade from an
earlier, ad-hoc-signed release or from a binary you re-signed yourself.

Check what is installed:

```bash
codesign -dv "$(realpath "$(brew --prefix)/bin/entra")"
```

A signed release shows `TeamIdentifier=2VLHJGU477`. **Do not run
`contrib/resign.sh` on it**: that replaces the Developer ID signature, and the
prompts return on every upgrade.

`cargo build` still produces an ad-hoc-signed binary whose identity changes
with every build. For source builds, `contrib/resign.sh` explains how to create
a free self-signed code-signing certificate in Keychain Access, then signs
with it. It looks for a certificate named `entra-cli-signer`, or the name in
`SIGN_IDENTITY`. The installer builds, tests, signs and installs
`~/.local/bin/entra` in one step:

```bash
./contrib/install.sh
```

The next prompt after signing is the last one. Click "Always Allow".

Silent refresh updates the existing keychain item in place, preserving its
access-control list. It does not delete and recreate the item.

## The keychain prompt has an empty name

If the dialog reads `entra wants to use your confidential information stored
in "" in your keychain`, the stored item predates the account-specific label.
New and refreshed items are labelled `entra — <account>` and described as a
Microsoft Entra ID access token. A token refresh updates that metadata in place,
so it repairs the prompt without discarding an existing access-control list.

Refresh the current account to repair it:

```bash
entra auth refresh
```

If the refresh token is no longer valid, sign in again with `entra auth login`.

## Rate limiting

Graph throttles directory reads. `user chain` makes one request per level, so a
deep hierarchy across many people adds up. If you are sweeping the whole
directory, add your own pacing between calls — this tool does not batch.

## Nothing works and the tenant looks wrong

Confirm which directory you are actually in:

```bash
entra whoami --json
```

A single-tenant registration only works in the tenant it was created in.
Signing in without `--tenant-id`, or with `--tenant-id common`, fails for a
single-tenant app with `AADSTS50194`.
