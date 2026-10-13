use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_command_is_available_without_configuration() {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(concat!(
            "entra ",
            env!("CARGO_PKG_VERSION"),
            " "
        )));
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
        .stdout(predicate::str::contains("--lifecycle"))
        .stdout(predicate::str::contains("--directory"))
        .stdout(predicate::str::contains("--scope"));
}

#[test]
fn login_without_an_app_registration_says_how_to_supply_one() {
    let temporary = tempfile::tempdir().unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .env_remove("ENTRA_CLIENT_ID")
        .args(["auth", "login"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--client-id"))
        .stderr(predicate::str::contains("ENTRA_CLIENT_ID"));
}

#[test]
fn login_reads_its_app_registration_from_the_environment() {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CLIENT_ID", "00000000-0000-4000-8000-000000000003")
        .env("ENTRA_TENANT_ID", "00000000-0000-4000-8000-000000000004")
        .args(["auth", "login", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ENTRA_CLIENT_ID=00000000-0000-4000-8000-000000000003",
        ))
        .stdout(predicate::str::contains(
            "ENTRA_TENANT_ID=00000000-0000-4000-8000-000000000004",
        ));
}

#[test]
fn user_list_offers_its_export_flags() {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .args(["user", "list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--all"))
        .stdout(predicate::str::contains("--group"))
        .stdout(predicate::str::contains("--sign-in-activity"))
        .stdout(predicate::str::contains("--manager"));
}

#[test]
fn deep_user_list_without_json_fails_before_authentication() {
    let temporary = tempfile::tempdir().unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .args(["user", "list", "--manager"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("add --json"))
        .stderr(predicate::str::contains("no authenticated accounts").not());
}

#[test]
fn user_list_group_validation_reports_json_errors_on_stdout() {
    let temporary = tempfile::tempdir().unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .args(["user", "list", "--group", "identitty", "--json"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("unknown attribute group"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn user_groups_offers_its_kind_filter() {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .args(["user", "groups", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--kind"))
        .stdout(predicate::str::contains("distribution"))
        .stdout(predicate::str::contains("mail-security"));
}

#[test]
fn unknown_group_kind_fails_before_authentication() {
    let temporary = tempfile::tempdir().unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .args(["user", "groups", "person@example.test", "--kind", "mailing"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mailing"))
        .stderr(predicate::str::contains("no account configured").not());
}

#[test]
fn login_and_refresh_offer_the_group_scope() {
    for subcommand in ["login", "refresh"] {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
        command
            .args(["auth", subcommand, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--groups"))
            .stdout(predicate::str::contains("GroupMember.Read.All"));
    }
}

#[test]
fn oversized_group_lookup_key_fails_before_authentication() {
    let temporary = tempfile::tempdir().unwrap();
    let key = format!("{}@example.test", "a".repeat(300));
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("entra"));
    command
        .env("ENTRA_CONFIG_DIR", temporary.path())
        .args(["user", "groups", key.as_str()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("query is too long"))
        .stderr(predicate::str::contains("no authenticated accounts").not())
        .stderr(predicate::str::contains("no account configured").not());
}
