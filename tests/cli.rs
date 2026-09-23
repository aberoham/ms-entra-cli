use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_command_is_available_without_configuration() {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("entra 0.1.0"));
}

#[test]
fn group_validation_happens_before_authentication() {
    let temporary = tempfile::tempdir().unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .args(["user", "get", "person@example.test", "--group", "identitty"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown attribute group"))
        .stderr(predicate::str::contains("no account configured").not());
}

#[test]
fn json_errors_stay_on_stdout() {
    let temporary = tempfile::tempdir().unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .args([
            "user",
            "get",
            "person@example.test",
            "--group",
            "identitty",
            "--json",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains(r#""code": "CommandFailed""#))
        .stderr(predicate::str::is_empty());
}

#[test]
fn no_input_refuses_interactive_login() {
    let temporary = tempfile::tempdir().unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .args([
            "auth",
            "login",
            "--client-id",
            "00000000-0000-4000-8000-000000000001",
            "--no-input",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "login is interactive and --no-input was given",
        ));
}

#[test]
fn auth_refresh_is_part_of_the_public_command_tree() {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .args(["auth", "refresh", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Silently redeem"))
        .stdout(predicate::str::contains("--directory"))
        .stdout(predicate::str::contains("--scope"));
}
