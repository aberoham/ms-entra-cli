# entra

Microsoft Entra ID directory lookups from the command line: a person's
manager, their direct reports, the management chain above them, and the
extended attributes on their record.

```bash
entra user manager jane.doe@example.com
entra user chain jane.doe@example.com
entra user get shared-inbox@example.com   # every alias, primary marked
entra user search "jane"
entra user list --manager --json          # everyone, with their managers
```

Read-only. There is no write path: changing a person's manager belongs in the
systems of record that feed the directory, not in a lookup tool.

## Why it exists

Reading another person's **manager** through Microsoft Graph needs the
delegated `User.Read.All` permission. It covers the whole directory and needs
administrator consent. Chat and mail tools usually hold only
`User.ReadBasic.All`, which stops at name, address and sign-in name.

Rather than widen the permissions of a chat client or a mail client, `entra`
holds the broad grant on a small read-only tool that does nothing else. It can
be reviewed, assigned and revoked on its own.

## Install

### macOS and Linux (Homebrew)

```bash
brew install aberoham/tap/entra
```

From `v0.1.1`, the macOS binaries are signed with a Developer ID
(`TeamIdentifier=2VLHJGU477`, identifier `com.aberoham.entra`). Keychain access
granted once therefore carries over to later releases. Upgrading from `v0.1.0`
or earlier asks one more time; choose **Always Allow**. See
[troubleshooting](docs/troubleshooting.md#macos-keychain-prompts-after-every-upgrade).

### Windows

1. Download `entra-<version>-x86_64-pc-windows-msvc.zip` and
   `checksums-sha256.txt` from the
   [latest release](https://github.com/aberoham/ms-entra-cli/releases/latest).
2. Check the download against the published checksum. In PowerShell:

   ```powershell
   (Get-FileHash .\entra-<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash.ToLower()
   Select-String x86_64-pc-windows-msvc .\checksums-sha256.txt
   ```

   The two hashes must be identical.
3. Extract the archive. It holds one folder,
   `entra-<version>-x86_64-pc-windows-msvc`; copy `bin\entra.exe` from inside
   it to a folder on your `PATH`.
4. Run `entra --help`.

The Windows binary is not code-signed. Microsoft Defender SmartScreen may warn
on the first run. Select **More info**, then **Run anyway**, once you have
checked the hash.

### Other platforms, or from source

Release archives for macOS (Apple silicon and Intel), Linux (x86-64 and Arm64,
statically linked) and Windows are on the
[releases page](https://github.com/aberoham/ms-entra-cli/releases). Each
archive contains `bin/entra` and the documentation under `share/doc/entra/`.
From `v0.1.1`, the macOS binaries are Developer ID signed and notarized by
Apple. Gatekeeper accepts a browser-downloaded copy after an online check the
first time it runs. Check the archive against `checksums-sha256.txt` as usual.

To build from source you need a current stable Rust toolchain:

```bash
cargo build --release --locked
./target/release/entra --help
```

`cargo build` produces an ad-hoc-signed binary, whose identity changes with
every build. On macOS, `./contrib/install.sh` runs the tests, builds, signs the
binary with your own stable local certificate, and installs it as
`~/.local/bin/entra`. That stops the Keychain from asking again after every
rebuild. A source build and a Homebrew release have different identities, so
switching between them asks once; see
[troubleshooting](docs/troubleshooting.md#macos-keychain-prompts-after-every-upgrade).

## Set up

`entra` does not ship with an app registration. You create one in your own
Microsoft Entra ID directory, grant it admin consent, then sign in with its
IDs. [docs/auth.md](docs/auth.md) walks through every step, both with the
included script and in the Microsoft Entra admin center.

With the [Azure command-line interface](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
and a role that can grant admin consent, the script does it in one pass:

```bash
export TENANT_ID=<tenant-id>
az login --tenant "$TENANT_ID"
ASSIGN_USERS="you@example.com" ./contrib/create-entra-app.sh
```

The script **refuses to run without a user or group assignment** unless you
set `ALLOW_ALL_TENANT_USERS=1` deliberately. Admin consent applies to the whole
organisation, so an app that holds `User.Read.All` with nobody assigned is a
directory-wide read that any user in the tenant can use.

Then sign in with the application (client) ID the script prints:

```bash
entra auth login --browser --directory \
  --client-id <application-client-id> \
  --tenant-id <tenant-id>
entra user get you@example.com
```

`--directory` requests `User.Read.All` and `AuditLog.Read.All`. Both need
administrator consent. Sign-in activity (`--sign-in-activity`) also needs a
Microsoft Entra ID P1 or P2 licence and a supported role, such as Reports
Reader, on the signed-in account.

When `--account` is omitted, user commands try the default signed-in account
first. If Graph returns a typed permission or role refusal, `entra` tries the
other stored accounts in a fixed order and reports the switch on standard
error. Network failures and ordinary lookup errors never cause a change of
identity. An explicit `--account` is strict:

```bash
entra --account alex.smith@login.example.test user get someone@example.com
```

## Documentation

- [docs/auth.md](docs/auth.md): app registration, permissions, admin consent, sign-in, token storage
- [docs/command-reference.md](docs/command-reference.md): commands, the permission each needs, flags
- [docs/troubleshooting.md](docs/troubleshooting.md): error, cause and fix

## Two addresses, one person

A person's sign-in name and email address often differ: one person signs in
as `alex.smith@login.example.test` and receives mail at
`alex.smith@example.test`. Either works. Where Graph reads reliably only by
object ID, `entra` resolves an address-shaped key over `mail`,
`userPrincipalName` and `proxyAddresses`, and uses the object ID internally.

`entra user get` prints the full alias list and marks the primary. That is how
to settle whether two addresses are one mailbox or two.

For a focused last-sign-in view, with Graph's raw timestamps, the exact age in
seconds and a readable age:

```bash
entra user get someone@example.com --sign-in-activity
```

## Implementation

The tool uses one small `reqwest` client and handwritten Microsoft Graph REST
calls. Transport, retries, pagination, URL construction and error
classification sit in one module, without a generated software development kit
for a read-only tool with few endpoints. Stable summary output is typed; `--all`
records stay as unmapped JSON, so directory attributes added later are not
silently dropped.

Every request passes through the same client. Redirects are disabled so the
bearer token is never forwarded, response sizes and page counts are bounded,
user-controlled path segments are encoded, and HTTP mocks exercise the Graph
behaviour the commands rely on.

## Licence

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
