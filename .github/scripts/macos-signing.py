#!/usr/bin/env python3
"""Sign release binaries using an isolated, short-lived macOS keychain."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import zipfile


def run(*args):
    # Child tools receive paths or explicit arguments, never the secret environment.
    child_env = {key: value for key, value in os.environ.items()
                 if key not in {"MACOS_CERTIFICATE_P12_BASE64", "MACOS_CERTIFICATE_PASSWORD",
                                "APPLE_NOTARY_KEY_P8_BASE64"}}
    result = subprocess.run(args, capture_output=True, text=True, env=child_env)
    if result.returncode:
        # Do not include argv: security import receives the bundle password.
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()}")
    return result.stdout if args[0] == "xcrun" else result.stdout + result.stderr


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required setting: {name}")
    return value


def decode_secret(name):
    # Tolerate line wrapping or a trailing newline from `base64 | gh secret set`.
    return base64.b64decode("".join(required(name).split()), validate=True)


def state_file():
    return Path(required("RUNNER_TEMP")) / "macos-signing-state.json"


def prepare():
    state_path = state_file()
    if state_path.exists():
        raise RuntimeError("Signing state already exists; clean up before retrying")
    identity = required("MACOS_SIGNING_IDENTITY")
    team = required("APPLE_TEAM_ID")
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", identity):
        raise RuntimeError("MACOS_SIGNING_IDENTITY must be a certificate SHA-1")
    if not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise RuntimeError("Invalid APPLE_TEAM_ID")
    bundle = decode_secret("MACOS_CERTIFICATE_P12_BASE64")
    password = required("MACOS_CERTIFICATE_PASSWORD")
    directory = Path(tempfile.mkdtemp(prefix="macos-signing-", dir=required("RUNNER_TEMP")))
    keychain = str(directory / "release.keychain-db")
    original = shlex.split(run("security", "list-keychains", "-d", "user"))
    state = {"directory": str(directory), "keychain": keychain, "original": original,
             "identity": identity, "team": team}
    state_path.write_text(json.dumps(state))
    bundle_path = directory / "identity.p12"
    bundle_path.write_bytes(bundle)
    keychain_password = secrets.token_urlsafe(32)
    run("security", "create-keychain", "-p", keychain_password, keychain)
    run("security", "set-keychain-settings", "-lut", "7200", keychain)
    run("security", "unlock-keychain", "-p", keychain_password, keychain)
    run("security", "list-keychains", "-d", "user", "-s", keychain, *original)
    intermediate = Path(__file__).resolve().parent.parent / "certificates" / "DeveloperIDG2CA.pem"
    run("security", "import", str(intermediate), "-k", keychain)
    run("security", "import", str(bundle_path), "-k", keychain, "-P", password,
        "-T", "/usr/bin/codesign")
    run("security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:",
        "-s", "-k", keychain_password, keychain)
    bundle_path.unlink()
    identities = run("security", "find-identity", "-v", "-p", "codesigning", keychain)
    if identity.upper() not in identities or "1 valid identities found" not in identities:
        raise RuntimeError("Expected exactly one valid signing identity matching the configured fingerprint")
    print("Prepared isolated Developer ID signing keychain")


def sign(binary, identifier, notarize):
    state = json.loads(state_file().read_text())
    binary = Path(binary).resolve(strict=True)
    if not re.fullmatch(r"[A-Za-z0-9.-]+", identifier):
        raise RuntimeError("Invalid signing identifier")
    run("codesign", "--force", "--options", "runtime", "--timestamp", "--keychain",
        state["keychain"], "--sign", state["identity"], "--identifier", identifier, str(binary))
    run("codesign", "--verify", "--strict", "--verbose=2", str(binary))
    details = run("codesign", "-dvvv", str(binary))
    expected = [f"Identifier={identifier}\n", f"TeamIdentifier={state['team']}\n",
                "Authority=Developer ID Application:", "Authority=Developer ID Certification Authority",
                "Authority=Apple Root CA", "Timestamp=", "(runtime)"]
    if any(value not in details for value in expected):
        raise RuntimeError("Signature is missing the expected identity, chain, timestamp or hardened runtime")
    print(details)
    print(run("codesign", "-d", "-r-", str(binary)))
    if notarize:
        with tempfile.TemporaryDirectory(prefix="notarize-", dir=state["directory"]) as temp:
            archive = Path(temp) / "submission.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
                zipped.write(binary, binary.name)
            # Decode only for this submission and wait; TemporaryDirectory removes
            # the key on success or error. The job cleanup also covers cancellation.
            key = Path(temp) / "AuthKey.p8"
            key.write_bytes(decode_secret("APPLE_NOTARY_KEY_P8_BASE64"))
            auth = ["--key", str(key), "--key-id", required("APPLE_NOTARY_KEY_ID"),
                    "--issuer", required("APPLE_NOTARY_ISSUER_ID")]
            submission = json.loads(run("xcrun", "notarytool", "submit", str(archive),
                                        *auth, "--output-format", "json"))
            print("Apple notarization submission:", submission["id"], flush=True)
            submission = json.loads(run("xcrun", "notarytool", "wait", submission["id"],
                                        *auth, "--timeout", "45m", "--output-format", "json"))
            print(json.dumps(submission, indent=2), flush=True)
            if submission.get("status") != "Accepted":
                raise RuntimeError("Apple did not accept the notarization submission")
            if os.environ.get("GITHUB_STEP_SUMMARY"):
                with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                    summary.write(f"Notarized `{binary.name}`: `{submission['id']}` (Accepted).\n")


def cleanup():
    path = state_file()
    if not path.exists():
        return
    state = json.loads(path.read_text())
    try:
        if Path(state["keychain"]).exists():
            run("security", "delete-keychain", state["keychain"])
    finally:
        try:
            run("security", "list-keychains", "-d", "user", "-s", *state["original"])
        finally:
            shutil.rmtree(state["directory"])
            path.unlink()
    print("Removed signing credentials and restored the keychain search list")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    commands.add_parser("cleanup")
    signing = commands.add_parser("sign")
    signing.add_argument("binary")
    signing.add_argument("identifier")
    signing.add_argument("--notarize", action="store_true")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    elif args.command == "cleanup":
        cleanup()
    else:
        sign(args.binary, args.identifier, args.notarize)


if __name__ == "__main__":
    main()
