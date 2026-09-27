"""Credential-free tests of key lifetime and fail-closed notarization."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("signing", Path(__file__).with_name("macos-signing.py"))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class NotarizationTests(unittest.TestCase):
    def check_submission(self, status="Accepted", fail=False):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            binary = directory / "example"
            binary.write_bytes(b"fake binary; never executed")
            state = {"directory": temp, "keychain": "fake", "identity": "fake", "team": "2VLHJGU477"}
            (directory / "macos-signing-state.json").write_text(json.dumps(state))
            calls = []

            def tool(*args):
                calls.append(args)
                if args[0] == "xcrun":
                    key = Path(args[args.index("--key") + 1])
                    self.assertTrue(key.is_file())
                    self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                    if fail:
                        raise RuntimeError("simulated service failure")
                    return json.dumps({"id": "test-submission", "status": status})
                if args[:2] == ("codesign", "-dvvv"):
                    return ("Identifier=com.aberoham.olk\nTeamIdentifier=2VLHJGU477\n"
                            "Authority=Developer ID Application: Example\n"
                            "Authority=Developer ID Certification Authority\n"
                            "Authority=Apple Root CA\nTimestamp=test\n(runtime)\n")
                return ""

            env = {"RUNNER_TEMP": temp, "APPLE_NOTARY_KEY_P8_BASE64": base64.b64encode(b"test fixture").decode(),
                   "APPLE_NOTARY_KEY_ID": "TEST", "APPLE_NOTARY_ISSUER_ID": "TEST"}
            old_umask = os.umask(0o077)
            try:
                with patch.dict(os.environ, env, clear=True), patch.object(signing, "run", side_effect=tool):
                    if fail or status != "Accepted":
                        with self.assertRaises(RuntimeError):
                            signing.sign(binary, "com.aberoham.olk", True)
                    else:
                        signing.sign(binary, "com.aberoham.olk", True)
                self.assertEqual(list(directory.rglob("*.p8")), [])
                self.assertEqual(list(directory.glob("notarize-*")), [])
                self.assertTrue(any(call[0] == "xcrun" for call in calls))
            finally:
                os.umask(old_umask)

    def test_accepted_submission_removes_key(self):
        self.check_submission()

    def test_rejection_fails_and_removes_key(self):
        self.check_submission(status="Invalid")

    def test_tool_failure_removes_key(self):
        self.check_submission(fail=True)

    def test_subprocesses_do_not_inherit_secret_environment(self):
        secrets = {name: "test fixture" for name in
                   ["MACOS_CERTIFICATE_P12_BASE64", "MACOS_CERTIFICATE_PASSWORD", "APPLE_NOTARY_KEY_P8_BASE64"]}
        with patch.dict(os.environ, secrets), patch.object(signing.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = run.return_value.stderr = ""
            signing.run("codesign", "--verify", "fake")
            self.assertTrue(set(secrets).isdisjoint(run.call_args.kwargs["env"]))


class DecodeSecretTests(unittest.TestCase):
    def test_wrapped_or_newline_terminated_base64_decodes(self):
        encoded = base64.b64encode(b"synthetic bytes " * 8).decode()
        wrapped = "\n".join(encoded[i:i + 20] for i in range(0, len(encoded), 20)) + "\n"
        with patch.dict(os.environ, {"EXAMPLE_SECRET": wrapped}):
            self.assertEqual(signing.decode_secret("EXAMPLE_SECRET"), b"synthetic bytes " * 8)

    def test_non_base64_is_rejected(self):
        with patch.dict(os.environ, {"EXAMPLE_SECRET": "not*base64"}):
            with self.assertRaises(ValueError):
                signing.decode_secret("EXAMPLE_SECRET")


if __name__ == "__main__":
    unittest.main()
