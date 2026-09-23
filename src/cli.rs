use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use clap::{error::ErrorKind, Args, Parser, Subcommand};
use serde_json::{json, Value};

use crate::attributes::{
    all_properties, group_properties, AttributeGroup, ATTRIBUTE_GROUPS, SIGN_IN_ACTIVITY_GROUP,
};
use crate::auth::{directory_scopes, merge_scopes, AccountInfo, Authenticator};
use crate::config::{ClientConfig, Config, DEFAULT_TENANT_ID};
use crate::error::{EntraError, Result};
use crate::graph::GraphClient;
use crate::model::User;
use crate::output::{
    sanitize, sanitize_multiline, write_pretty_json, write_rows, write_users, OutputFormat,
    OutputOptions,
};
use crate::secrets::{CredentialStore, KeyringStore};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "entra",
    about = "Microsoft Entra ID directory lookups — manager hierarchy and extended staff details — from the command line"
)]
pub struct Cli {
    #[arg(long, global = true, env = "ENTRA_JSON", help = "Output as JSON")]
    json: bool,
    #[arg(long, global = true, env = "ENTRA_PLAIN", help = "Output as plain TSV")]
    plain: bool,
    #[arg(
        long,
        global = true,
        env = "ENTRA_ACCOUNT",
        help = "Authenticated account to use, by primary email, sign-in name or proxy address"
    )]
    account: Option<String>,
    #[arg(
        long,
        short = 'v',
        global = true,
        env = "ENTRA_VERBOSE",
        help = "Verbose output"
    )]
    verbose: bool,
    #[arg(
        long,
        global = true,
        env = "ENTRA_COLOR",
        default_value = "auto",
        value_parser = ["auto", "never", "always"],
        help = "Color mode: auto|never|always"
    )]
    color: String,
    #[arg(
        long,
        global = true,
        env = "ENTRA_SELECT",
        default_value = "",
        help = "Comma-separated fields to output"
    )]
    select: String,
    #[arg(
        long,
        global = true,
        env = "ENTRA_RESULTS_ONLY",
        help = "Output only the result value (no envelope)"
    )]
    results_only: bool,
    #[arg(
        long,
        global = true,
        env = "ENTRA_TIMEOUT",
        default_value_t = 60,
        help = "Request timeout in seconds"
    )]
    timeout: u64,
    #[arg(
        long,
        global = true,
        env = "ENTRA_NO_WRITE",
        help = "Refuse any mutating operation"
    )]
    no_write: bool,
    #[arg(
        long,
        global = true,
        env = "ENTRA_NO_INPUT",
        help = "Fail instead of prompting (headless/agent safety)"
    )]
    no_input: bool,
    #[arg(
        long,
        global = true,
        env = "ENTRA_WRAP_UNTRUSTED",
        help = "Wrap directory free-text in untrusted-content markers"
    )]
    wrap_untrusted: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    #[command(about = "Authentication commands")]
    Auth(AuthArgs),
    #[command(about = "Look up people in the directory")]
    User(UserArgs),
    #[command(about = "Show the signed-in user's own profile")]
    Whoami,
    #[command(about = "Show version information")]
    Version,
}

#[derive(Debug, Clone, Args)]
struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum AuthCommand {
    #[command(about = "Sign in to a Microsoft account")]
    Login(AuthLogin),
    #[command(about = "Silently redeem the stored refresh token")]
    Refresh(AuthRefresh),
    #[command(about = "Remove stored credentials")]
    Logout { email: Option<String> },
    #[command(about = "List authenticated accounts")]
    List,
    #[command(about = "Show authentication status")]
    Status,
}

#[derive(Debug, Clone, Args)]
struct AuthLogin {
    #[arg(long, help = "Application (client) id of the app registration")]
    client_id: String,
    #[arg(
        long,
        default_value = DEFAULT_TENANT_ID,
        help = "Directory (tenant) id"
    )]
    tenant_id: String,
    #[arg(
        long,
        help = "Request User.Read.All and AuditLog.Read.All for full directory reads (needs administrator consent)"
    )]
    directory: bool,
    #[arg(long, help = "Sign in via the system browser instead of device code")]
    browser: bool,
    #[arg(long, action = clap::ArgAction::Append, help = "Additional OAuth scope to request (repeatable)")]
    scope: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct AuthRefresh {
    #[arg(
        long,
        help = "Request User.Read.All and AuditLog.Read.All while refreshing (needs administrator consent)"
    )]
    directory: bool,
    #[arg(
        long,
        action = clap::ArgAction::Append,
        help = "Additional OAuth scope to request (repeatable)"
    )]
    scope: Vec<String>,
}

#[derive(Debug, Clone, Args)]
struct UserArgs {
    #[command(subcommand)]
    command: UserCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum UserCommand {
    #[command(about = "Show one person's full directory record")]
    Get(UserGet),
    #[command(about = "Show a person's manager")]
    Manager { key: String },
    #[command(about = "Show everyone reporting to a person")]
    Reports { key: String },
    #[command(about = "Walk the management line upwards from a person")]
    Chain {
        key: String,
        #[arg(long, default_value_t = 10, help = "Maximum number of people to walk")]
        depth: usize,
    },
    #[command(about = "Find people by name or address")]
    Search {
        query: String,
        #[arg(short = 'n', long, default_value_t = 25, help = "Maximum results")]
        top: usize,
    },
}

#[derive(Debug, Clone, Args)]
struct UserGet {
    #[arg(help = "Sign-in name, email address or object id")]
    key: String,
    #[arg(long, help = "Retrieve every directory attribute, not the summary set")]
    all: bool,
    #[arg(
        long = "group",
        action = clap::ArgAction::Append,
        help = "Retrieve only these attribute groups (repeatable); implies --all behaviour"
    )]
    groups: Vec<String>,
    #[arg(
        long,
        help = "Show sign-in timestamps and ages; with --all/--group, include activity in that record (needs AuditLog.Read.All, a supported Entra role, and P1/P2)"
    )]
    sign_in_activity: bool,
}

pub async fn execute() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let _ = error.print();
            return if informational { 0 } else { 1 };
        }
    };
    let json_mode = cli.json;
    match run(cli).await {
        Ok(()) => 0,
        Err(error) => {
            write_command_error(json_mode, &error);
            1
        }
    }
}

async fn run(mut cli: Cli) -> Result<()> {
    validate_command(&cli.command)?;
    if cli.timeout == 0 {
        cli.timeout = 60;
    } else if cli.timeout > 600 {
        eprintln!(
            "warning: --timeout {} exceeds maximum, clamping to 600s",
            cli.timeout
        );
        cli.timeout = 600;
    }
    let _capability_guard = cli.no_write;
    let _color_contract = &cli.color;
    let output = OutputOptions {
        format: if cli.json {
            OutputFormat::Json
        } else if cli.plain {
            OutputFormat::Plain
        } else {
            OutputFormat::Table
        },
        select: cli.select.clone(),
        results_only: cli.results_only,
        wrap_untrusted: cli.wrap_untrusted,
    };
    let store: Arc<dyn CredentialStore> = Arc::new(KeyringStore);
    match cli.command.clone() {
        Command::Version => {
            println!(
                "entra {} (commit {}, built {})",
                env!("CARGO_PKG_VERSION"),
                option_env!("ENTRA_BUILD_COMMIT").unwrap_or("none"),
                option_env!("ENTRA_BUILD_DATE").unwrap_or("unknown")
            );
            Ok(())
        }
        Command::Auth(args) => run_auth(&cli, &output, store, args.command).await,
        Command::Whoami => {
            let graph = graph_client(&cli, store).await?;
            let user = graph.me().await?;
            write_users(io::stdout(), &output, &[user])
        }
        Command::User(args) => run_user_with_accounts(&cli, &output, store, args.command).await,
    }
}

fn validate_command(command: &Command) -> Result<()> {
    if let Command::User(UserArgs {
        command: UserCommand::Get(get),
    }) = command
    {
        selected_properties(get)?;
    }
    Ok(())
}

async fn run_auth(
    cli: &Cli,
    output: &OutputOptions,
    store: Arc<dyn CredentialStore>,
    command: AuthCommand,
) -> Result<()> {
    match command {
        AuthCommand::Login(login) => {
            if cli.no_input {
                return Err(EntraError::message(
                    "login is interactive and --no-input was given",
                ));
            }
            let scopes = merge_scopes(
                if login.directory {
                    directory_scopes()
                } else {
                    crate::auth::default_scopes()
                },
                &login.scope,
            );
            let auth = Authenticator::new(store, &login.client_id, &login.tenant_id)?;
            let info = if login.browser {
                auth.login_browser(&scopes, cli.verbose).await
            } else {
                auth.login_device_code(&scopes, cli.verbose).await
            }
            .map_err(|error| error.context("login failed"))?;
            let mut config = Config::load().map_err(|error| error.context("loading config"))?;
            config.clients.insert(
                info.email.clone(),
                ClientConfig {
                    client_id: login.client_id,
                    tenant_id: login.tenant_id,
                },
            );
            if config.default_account.is_empty() {
                config.default_account = info.email.clone();
            }
            config
                .save()
                .map_err(|error| error.context("saving config"))?;
            println!(
                "Logged in as {} ({})",
                sanitize(&info.display_name),
                sanitize(&info.email)
            );
            if !login.directory {
                println!(
                    "Note: full directory and sign-in-activity lookups need 'entra auth login --directory',\nwhich requests User.Read.All and AuditLog.Read.All and requires administrator consent."
                );
            }
            Ok(())
        }
        AuthCommand::Refresh(refresh) => {
            let config = Config::load().map_err(|error| error.context("loading config"))?;
            let account = select_account(cli, store.clone(), &config, None).await?;
            let email = account.email.clone();
            let auth = authenticator_for_account(store, &config, &account)?;
            let requested = if refresh.directory || !refresh.scope.is_empty() {
                Some(merge_scopes(
                    if refresh.directory {
                        directory_scopes()
                    } else {
                        crate::auth::default_scopes()
                    },
                    &refresh.scope,
                ))
            } else {
                None
            };
            let token = auth
                .refresh(&email, requested.as_deref(), cli.verbose)
                .await
                .map_err(|error| annotate_refresh_error(error, &email))?;
            if output.format == OutputFormat::Json {
                let result = json!({
                    "account": email,
                    "expiresAt": token.expires_at,
                    "scope": token.scope,
                });
                return write_pretty_json(io::stdout(), &output.json_value(&result, 1)?);
            }
            println!("Refreshed token for {email}");
            if !token.scope.is_empty() {
                println!("Granted scopes: {}", sanitize(&token.scope));
            }
            println!("Expires: {}", sanitize(&token.expires_at));
            Ok(())
        }
        AuthCommand::Logout { email } => {
            let config = Config::load().map_err(|error| error.context("loading config"))?;
            let account = select_account(cli, store.clone(), &config, email.as_deref()).await?;
            let email = account.email;
            let auth = Authenticator::new(store, "", DEFAULT_TENANT_ID)?;
            auth.logout(&email)?;
            println!("Signed out {email}");
            Ok(())
        }
        AuthCommand::List => {
            let auth = Authenticator::new(store, "", DEFAULT_TENANT_ID)?;
            let accounts = auth.list_accounts()?;
            let config = Config::load().map_err(|error| error.context("loading config"))?;
            if output.format == OutputFormat::Json {
                return write_pretty_json(
                    io::stdout(),
                    &output.json_value(&accounts, accounts.len())?,
                );
            }
            let rows: Vec<_> = accounts
                .iter()
                .map(|account| {
                    vec![
                        account.email.clone(),
                        account.display_name.clone(),
                        if account.email == config.default_account {
                            "*".into()
                        } else {
                            String::new()
                        },
                    ]
                })
                .collect();
            write_rows(io::stdout(), output, &["EMAIL", "NAME", "DEFAULT"], &rows)
        }
        AuthCommand::Status => {
            let config = Config::load().map_err(|error| error.context("loading config"))?;
            let account = select_account(cli, store.clone(), &config, None).await?;
            let email = account.email.clone();
            let graph = graph_client_for_account(cli, store, &config, &account).await?;
            let me = graph
                .me()
                .await
                .map_err(|error| error.context(format!("token for {email} is not usable")))?;
            println!(
                "Account: {email}\nStatus: Authenticated as {}",
                sanitize(&me.display_name)
            );
            Ok(())
        }
    }
}

async fn run_user_with_accounts(
    cli: &Cli,
    output: &OutputOptions,
    store: Arc<dyn CredentialStore>,
    command: UserCommand,
) -> Result<()> {
    let config = Config::load().map_err(|error| error.context("loading config"))?;
    let accounts = ordered_accounts(crate::auth::list_accounts()?, &config.default_account);
    if accounts.is_empty() {
        return Err(EntraError::message(
            "no authenticated accounts are available. Run 'entra auth login' first",
        ));
    }

    if let Some(requested) = cli.account.as_deref() {
        let account =
            resolve_account_identifier(cli, store.clone(), &config, &accounts, requested).await?;
        let graph = graph_client_for_account(cli, store, &config, &account).await?;
        return run_user(output, &graph, command, true).await;
    }

    let mut refused_accounts = Vec::new();
    let mut last_refusal = None;
    for (index, account) in accounts.iter().enumerate() {
        let graph = graph_client_for_account(cli, store.clone(), &config, account).await?;
        match run_user(output, &graph, command.clone(), false).await {
            Ok(()) => return Ok(()),
            Err(error) if error.is_authorization_failure() => {
                refused_accounts.push(account.email.clone());
                if index + 1 < accounts.len() {
                    let next = &accounts[index + 1];
                    eprintln!(
                        "notice: account {} is not permitted to run this command; retrying with {}",
                        sanitize(&account.email),
                        sanitize(&next.email)
                    );
                }
                last_refusal = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    if user_command_can_omit_sign_in_activity(&command) {
        let first = &accounts[0];
        let graph = graph_client_for_account(cli, store, &config, first).await?;
        return run_user(output, &graph, command, true).await;
    }

    let error = last_refusal.unwrap_or_else(|| {
        EntraError::message("no authenticated account could run the requested command")
    });
    Err(error.context(format!(
        "none of the authenticated accounts is permitted to run this command; tried {}",
        refused_accounts.join(", ")
    )))
}

async fn run_user(
    output: &OutputOptions,
    graph: &GraphClient,
    command: UserCommand,
    allow_sign_in_activity_fallback: bool,
) -> Result<()> {
    match command {
        UserCommand::Get(mut get) => {
            let sign_in_activity_only = get.sign_in_activity && !get.all && get.groups.is_empty();
            if get.all || !get.groups.is_empty() || get.sign_in_activity {
                let mut properties = selected_properties(&get)?;
                let record = match graph.get_user_attributes(&get.key, &properties).await {
                    Ok(record) => record,
                    Err(error)
                        if get.sign_in_activity
                            && !sign_in_activity_only
                            && allow_sign_in_activity_fallback
                            && is_sign_in_activity_refusal(&error) =>
                    {
                        eprintln!(
                            "warning: sign-in activity unavailable ({}); retrying without it",
                            error
                        );
                        get.sign_in_activity = false;
                        properties = selected_properties(&get)?;
                        graph.get_user_attributes(&get.key, &properties).await?
                    }
                    Err(error) => return Err(error),
                };
                if sign_in_activity_only {
                    return write_sign_in_activity(
                        io::stdout(),
                        output,
                        &get.key,
                        &record,
                        Utc::now(),
                    );
                }
                return write_deep_record(output, &get.key, &record);
            }
            let user = graph.get_user(&get.key).await?;
            if output.format == OutputFormat::Json {
                return write_pretty_json(io::stdout(), &output.user_json_value(&user)?);
            }
            write_user_detail(io::stdout(), &user)
        }
        UserCommand::Manager { key } => {
            let manager = graph.get_manager(&key).await?;
            match manager {
                Some(user) => write_users(io::stdout(), output, &[user]),
                None if output.format == OutputFormat::Json => {
                    write_users(io::stdout(), output, &[])
                }
                None => {
                    println!("{key} has no manager recorded in the directory.");
                    Ok(())
                }
            }
        }
        UserCommand::Reports { key } => {
            let reports = graph.get_direct_reports(&key).await?;
            write_users(io::stdout(), output, &reports)
        }
        UserCommand::Chain { key, depth } => {
            let chain = graph.get_chain(&key, depth).await?;
            if matches!(output.format, OutputFormat::Json | OutputFormat::Plain) {
                write_users(io::stdout(), output, &chain)
            } else {
                for (depth, person) in chain.iter().enumerate() {
                    println!(
                        "{}{} ({})",
                        "  ".repeat(depth),
                        sanitize(&person.display_name),
                        sanitize(&person.job_title)
                    );
                }
                Ok(())
            }
        }
        UserCommand::Search { query, top } => {
            let found = graph.search_users(&query, top).await?;
            write_users(io::stdout(), output, &found)
        }
    }
}

async fn graph_client(cli: &Cli, store: Arc<dyn CredentialStore>) -> Result<GraphClient> {
    let config = Config::load().map_err(|error| error.context("loading config"))?;
    let account = select_account(cli, store.clone(), &config, None).await?;
    graph_client_for_account(cli, store, &config, &account).await
}

async fn graph_client_for_account(
    cli: &Cli,
    store: Arc<dyn CredentialStore>,
    config: &Config,
    account: &AccountInfo,
) -> Result<GraphClient> {
    let auth = authenticator_for_account(store, config, account)?;
    let token = auth
        .access_token(&account.email, cli.verbose)
        .await
        .map_err(|error| error.context(format!("getting credentials for {}", account.email)))?;
    GraphClient::new(token, Duration::from_secs(cli.timeout), cli.verbose)
}

fn authenticator_for_account(
    store: Arc<dyn CredentialStore>,
    config: &Config,
    account: &AccountInfo,
) -> Result<Authenticator> {
    let configured = config
        .clients
        .iter()
        .find(|(email, _)| email.eq_ignore_ascii_case(&account.email))
        .map(|(_, client)| client);
    let client_id = configured
        .map(|client| client.client_id.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or(&account.client_id);
    let tenant_id = configured
        .map(|client| client.tenant_id.as_str())
        .filter(|value| !value.is_empty())
        .or_else(|| (!account.tenant_id.is_empty()).then_some(account.tenant_id.as_str()))
        .unwrap_or(DEFAULT_TENANT_ID);
    if client_id.is_empty() {
        return Err(EntraError::message(format!(
            "no application client id is configured for {}; run 'entra auth login --client-id <app-id>'",
            account.email
        )));
    }
    Authenticator::new(store, client_id, tenant_id)
}

async fn select_account(
    cli: &Cli,
    store: Arc<dyn CredentialStore>,
    config: &Config,
    override_identifier: Option<&str>,
) -> Result<AccountInfo> {
    let accounts = ordered_accounts(crate::auth::list_accounts()?, &config.default_account);
    let requested = override_identifier.or(cli.account.as_deref());
    if let Some(requested) = requested {
        return resolve_account_identifier(cli, store, config, &accounts, requested).await;
    }
    accounts.into_iter().next().ok_or_else(|| {
        EntraError::message("no authenticated accounts are available. Run 'entra auth login' first")
    })
}

async fn resolve_account_identifier(
    cli: &Cli,
    store: Arc<dyn CredentialStore>,
    config: &Config,
    accounts: &[AccountInfo],
    requested: &str,
) -> Result<AccountInfo> {
    let requested = requested.trim();
    if let Some(account) = accounts
        .iter()
        .find(|account| account.email.eq_ignore_ascii_case(requested))
    {
        return Ok(account.clone());
    }

    let mut matches = Vec::new();
    let mut unavailable = Vec::new();
    for account in accounts {
        let graph = match graph_client_for_account(cli, store.clone(), config, account).await {
            Ok(graph) => graph,
            Err(error) => {
                if cli.verbose {
                    eprintln!(
                        "[verbose] could not inspect authenticated account {}: {}",
                        sanitize(&account.email),
                        sanitize_multiline(&error.to_string())
                    );
                }
                unavailable.push(account.email.clone());
                continue;
            }
        };
        match graph.me().await {
            Ok(profile) if user_has_account_identifier(&profile, requested) => {
                matches.push(account.clone());
            }
            Ok(_) => {}
            Err(error) => {
                if cli.verbose {
                    eprintln!(
                        "[verbose] could not read identity for authenticated account {}: {}",
                        sanitize(&account.email),
                        sanitize_multiline(&error.to_string())
                    );
                }
                unavailable.push(account.email.clone());
            }
        }
    }

    match matches.len() {
        1 => Ok(matches.remove(0)),
        count if count > 1 => Err(EntraError::message(format!(
            "account identifier {requested:?} is ambiguous; it matches stored credentials for {}. Use one of those primary account emails with --account",
            matches
                .iter()
                .map(|account| account.email.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        _ => {
            let known = accounts
                .iter()
                .map(|account| account.email.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let unavailable = if unavailable.is_empty() {
                String::new()
            } else {
                format!(" Could not inspect: {}.", unavailable.join(", "))
            };
            Err(EntraError::message(format!(
                "no authenticated account matches {requested:?} by primary email, sign-in name or proxy address. Stored accounts: {known}.{unavailable} Run 'entra auth list' to see the canonical account names"
            )))
        }
    }
}

fn ordered_accounts(mut accounts: Vec<AccountInfo>, default_account: &str) -> Vec<AccountInfo> {
    accounts.sort_by(|left, right| {
        left.email
            .to_ascii_lowercase()
            .cmp(&right.email.to_ascii_lowercase())
    });
    if let Some(index) = accounts
        .iter()
        .position(|account| account.email.eq_ignore_ascii_case(default_account))
    {
        let default = accounts.remove(index);
        accounts.insert(0, default);
    }
    accounts
}

fn user_has_account_identifier(user: &User, requested: &str) -> bool {
    let requested = requested.trim();
    user.mail.eq_ignore_ascii_case(requested)
        || user.user_principal_name.eq_ignore_ascii_case(requested)
        || user.proxy_addresses.iter().any(|address| {
            address
                .split_once(':')
                .map(|(_, value)| value.trim())
                .unwrap_or_else(|| address.trim())
                .eq_ignore_ascii_case(requested)
        })
}

fn user_command_can_omit_sign_in_activity(command: &UserCommand) -> bool {
    matches!(
        command,
        UserCommand::Get(get)
            if get.sign_in_activity && (get.all || !get.groups.is_empty())
    )
}

fn annotate_refresh_error(error: EntraError, email: &str) -> EntraError {
    if error.is_consent_required() {
        EntraError::message(format!(
            "{error}. The requested scopes have not been consented for this app; grant administrator consent, then retry, or run 'entra auth login --directory' for interactive consent"
        ))
    } else {
        error.context(format!("refreshing token for {email}"))
    }
}

fn selected_properties(get: &UserGet) -> Result<Vec<&'static str>> {
    if get.sign_in_activity && !get.all && get.groups.is_empty() {
        return Ok(vec![
            "id",
            "displayName",
            "userPrincipalName",
            "signInActivity",
        ]);
    }
    let mut properties = if get.groups.is_empty() {
        all_properties()
    } else {
        group_properties(&get.groups)?
    };
    if get.sign_in_activity && !properties.contains(&"signInActivity") {
        properties.extend_from_slice(SIGN_IN_ACTIVITY_GROUP.properties);
    }
    Ok(properties)
}

fn is_sign_in_activity_refusal(error: &EntraError) -> bool {
    error.is_sign_in_activity_role_refusal() || {
        let lower = error.to_string().to_ascii_lowercase();
        lower.contains("signinactivity") || lower.contains("auditlog") || error.is_permission()
    }
}

const SIGN_IN_TIMESTAMPS: [(&str, &str, &str); 3] = [
    (
        "Last successful sign-in",
        "lastSuccessfulSignInDateTime",
        "lastSuccessfulSignInRequestId",
    ),
    (
        "Last interactive attempt",
        "lastSignInDateTime",
        "lastSignInRequestId",
    ),
    (
        "Last non-interactive sign-in",
        "lastNonInteractiveSignInDateTime",
        "lastNonInteractiveSignInRequestId",
    ),
];

fn write_sign_in_activity(
    mut writer: impl Write,
    output: &OutputOptions,
    key: &str,
    record: &BTreeMap<String, Value>,
    observed_at: DateTime<Utc>,
) -> Result<()> {
    let activity = record.get("signInActivity").cloned().unwrap_or(Value::Null);
    let activity_object = activity.as_object();
    let mut ages = serde_json::Map::new();
    let mut rows = Vec::new();

    for (label, timestamp_field, request_id_field) in SIGN_IN_TIMESTAMPS {
        let raw = activity_object
            .and_then(|object| object.get(timestamp_field))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if raw.is_empty() {
            continue;
        }
        let request_id = activity_object
            .and_then(|object| object.get(request_id_field))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let age = sign_in_age(raw, observed_at);
        let (seconds, human) = age
            .as_ref()
            .map(|age| (age.seconds.to_string(), age.human.clone()))
            .unwrap_or_else(|| (String::new(), "unparseable timestamp".into()));
        if let Some(age) = age {
            ages.insert(
                timestamp_field.into(),
                json!({"seconds": age.seconds, "human": age.human}),
            );
        }
        rows.push(vec![
            label.into(),
            raw.into(),
            seconds,
            human,
            request_id.into(),
        ]);
    }

    if output.format == OutputFormat::Json {
        let mut result = serde_json::Map::new();
        for field in ["id", "displayName", "userPrincipalName"] {
            if let Some(value) = record.get(field) {
                result.insert(field.into(), value.clone());
            }
        }
        result.insert(
            "observedAt".into(),
            Value::String(observed_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
        result.insert("signInActivity".into(), activity);
        result.insert("signInActivityAge".into(), Value::Object(ages));
        return write_pretty_json(&mut writer, &output.json_value(&Value::Object(result), 1)?);
    }

    if output.format == OutputFormat::Table {
        let identity = record
            .get("displayName")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(key);
        writeln!(writer, "Sign-in activity for {}", sanitize(identity))?;
        writeln!(
            writer,
            "Observed at: {}\n",
            observed_at.to_rfc3339_opts(SecondsFormat::Secs, true)
        )?;
    }
    if rows.is_empty() {
        writeln!(
            writer,
            "No sign-in activity is recorded for {}.",
            sanitize(key)
        )?;
        return Ok(());
    }
    write_rows(
        &mut writer,
        output,
        &[
            "ACTIVITY",
            "ENTRA TIMESTAMP",
            "AGE SECONDS",
            "AGE",
            "REQUEST ID",
        ],
        &rows,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignInAge {
    seconds: i64,
    human: String,
}

fn sign_in_age(raw: &str, observed_at: DateTime<Utc>) -> Option<SignInAge> {
    let timestamp = DateTime::parse_from_rfc3339(raw).ok()?.with_timezone(&Utc);
    let seconds = observed_at.signed_duration_since(timestamp).num_seconds();
    Some(SignInAge {
        seconds,
        human: human_age(seconds),
    })
}

fn human_age(seconds: i64) -> String {
    if seconds == 0 {
        return "now".into();
    }
    let mut remaining = seconds.saturating_abs();
    let units = [
        (31_536_000, "year"),
        (86_400, "day"),
        (3_600, "hour"),
        (60, "minute"),
        (1, "second"),
    ];
    let mut parts = Vec::new();
    for (unit_seconds, name) in units {
        let count = remaining / unit_seconds;
        if count == 0 {
            continue;
        }
        remaining %= unit_seconds;
        parts.push(format!(
            "{count} {name}{}",
            if count == 1 { "" } else { "s" }
        ));
        if parts.len() == 2 {
            break;
        }
    }
    let duration = parts.join(" ");
    if seconds > 0 {
        format!("{duration} ago")
    } else {
        format!("in {duration}")
    }
}

fn write_command_error(json_mode: bool, error: &EntraError) {
    if json_mode {
        let (code, status) = error.metadata();
        let value = json!({
            "error": {
                "code": code,
                "status": status,
                "message": error.to_string(),
            }
        });
        if write_pretty_json(io::stdout(), &value).is_err() {
            eprintln!("Error: JSON error output failed");
        }
    } else {
        eprintln!("Error: {}", sanitize_multiline(&error.to_string()));
    }
}

fn write_deep_record(
    output: &OutputOptions,
    key: &str,
    record: &BTreeMap<String, Value>,
) -> Result<()> {
    if matches!(output.format, OutputFormat::Json | OutputFormat::Plain) {
        return write_pretty_json(io::stdout(), &serde_json::to_value(record)?);
    }
    println!("# {}", sanitize(key));
    print_group(record, &SIGN_IN_ACTIVITY_GROUP);
    for group in ATTRIBUTE_GROUPS {
        print_group(record, group);
    }
    Ok(())
}

fn print_group(record: &BTreeMap<String, Value>, group: &AttributeGroup) {
    let lines: Vec<_> = group
        .properties
        .iter()
        .filter_map(|property| {
            record
                .get(*property)
                .filter(|value| !is_empty_value(value))
                .map(|value| format!("  {property:<34} {}", render_value(value)))
        })
        .collect();
    if lines.is_empty() {
        return;
    }
    println!("\n## {} — {}", group.name, group.description);
    for line in lines {
        println!("{line}");
    }
}

fn is_empty_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        _ => false,
    }
}

fn render_value(value: &Value) -> String {
    match value {
        Value::String(value) => sanitize(value),
        Value::Array(values) => values
            .iter()
            .map(render_value)
            .collect::<Vec<_>>()
            .join(", "),
        other => sanitize(&serde_json::to_string(other).unwrap_or_else(|_| other.to_string())),
    }
}

fn write_user_detail(mut writer: impl Write, user: &User) -> Result<()> {
    let enabled = user
        .account_enabled
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".into());
    let fields = [
        ("Display name", user.display_name.as_str()),
        ("Email", user.mail.as_str()),
        ("Sign-in name", user.user_principal_name.as_str()),
        ("Object id", user.id.as_str()),
        ("Job title", user.job_title.as_str()),
        ("Department", user.department.as_str()),
        ("Company", user.company_name.as_str()),
        ("Office", user.office_location.as_str()),
        ("Employee id", user.employee_id.as_str()),
        ("Employee type", user.employee_type.as_str()),
        ("Account enabled", enabled.as_str()),
        ("Created", user.created_date()),
        (
            "On-premises name",
            user.on_premises_sam_account_name.as_str(),
        ),
        ("Usage location", user.usage_location.as_str()),
    ];
    for (label, value) in fields {
        if !value.is_empty() {
            writeln!(writer, "{:<18} {}", format!("{label}:"), sanitize(value))?;
        }
    }
    if !user.mail_nickname.is_empty() {
        writeln!(
            writer,
            "{:<18} {}",
            "Mail alias:",
            sanitize(&user.mail_nickname)
        )?;
    }
    write_addresses(&mut writer, user)
}

fn write_addresses(writer: &mut impl Write, user: &User) -> Result<()> {
    if !user.proxy_addresses.is_empty() {
        writeln!(writer, "\nMailbox addresses:")?;
        for address in &user.proxy_addresses {
            let (kind, value) = classify_proxy_address(address);
            writeln!(writer, "  {kind:<10} {}", sanitize(&value))?;
        }
    }
    if !user.other_mails.is_empty() {
        writeln!(writer, "\nOther addresses:")?;
        for address in &user.other_mails {
            writeln!(writer, "  other      {}", sanitize(address))?;
        }
    }
    Ok(())
}

pub fn classify_proxy_address(address: &str) -> (String, String) {
    let Some((prefix, value)) = address.split_once(':') else {
        return ("address".into(), address.trim().into());
    };
    let kind = if prefix == "SMTP" {
        "primary".into()
    } else if prefix.eq_ignore_ascii_case("smtp") {
        "alias".into()
    } else if prefix.eq_ignore_ascii_case("x500") {
        "x500".into()
    } else {
        prefix.to_ascii_lowercase()
    };
    (kind, value.trim().into())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn account(email: &str) -> AccountInfo {
        AccountInfo {
            email: email.into(),
            display_name: "Test Account".into(),
            tenant_id: "00000000-0000-4000-8000-000000000001".into(),
            client_id: "00000000-0000-4000-8000-000000000002".into(),
            login_time: "2026-08-31T00:00:00Z".into(),
        }
    }

    #[test]
    fn global_flags_are_accepted_after_the_leaf_command() {
        let cli = Cli::try_parse_from([
            "entra",
            "user",
            "get",
            "person@example.test",
            "-v",
            "--all",
            "--json",
        ])
        .unwrap();
        assert!(cli.verbose);
        assert!(cli.json);
    }

    #[test]
    fn misspelled_group_is_validated_without_authentication() {
        let cli = Cli::try_parse_from([
            "entra",
            "user",
            "get",
            "person@example.test",
            "--group",
            "identitty",
        ])
        .unwrap();
        let error = validate_command(&cli.command).unwrap_err();
        assert!(error.to_string().contains("available"));
    }

    #[test]
    fn bare_sign_in_activity_requests_only_identity_and_activity() {
        let get = UserGet {
            key: "person@example.test".into(),
            all: false,
            groups: Vec::new(),
            sign_in_activity: true,
        };
        assert_eq!(
            selected_properties(&get).unwrap(),
            ["id", "displayName", "userPrincipalName", "signInActivity"]
        );
    }

    #[test]
    fn authenticated_accounts_try_the_default_then_stable_email_order() {
        let accounts = ordered_accounts(
            vec![
                account("zulu@example.test"),
                account("admin@example.test"),
                account("person@example.test"),
            ],
            "PERSON@example.test",
        );
        assert_eq!(
            accounts
                .iter()
                .map(|account| account.email.as_str())
                .collect::<Vec<_>>(),
            [
                "person@example.test",
                "admin@example.test",
                "zulu@example.test"
            ]
        );
    }

    #[test]
    fn account_identifier_accepts_mail_upn_and_proxy_but_not_unrelated_mail() {
        let user = User {
            mail: "primary@example.test".into(),
            user_principal_name: "signin@example.test".into(),
            proxy_addresses: vec![
                "SMTP:primary@example.test".into(),
                "smtp:alias@example.test".into(),
            ],
            other_mails: vec!["personal@example.test".into()],
            ..User::default()
        };
        for identifier in [
            "PRIMARY@example.test",
            "signin@example.test",
            "alias@example.test",
        ] {
            assert!(user_has_account_identifier(&user, identifier));
        }
        assert!(!user_has_account_identifier(&user, "personal@example.test"));
    }

    #[test]
    fn only_combined_sign_in_reads_may_degrade_after_all_accounts_refuse() {
        let focused = UserCommand::Get(UserGet {
            key: "person@example.test".into(),
            all: false,
            groups: Vec::new(),
            sign_in_activity: true,
        });
        let full = UserCommand::Get(UserGet {
            key: "person@example.test".into(),
            all: true,
            groups: Vec::new(),
            sign_in_activity: true,
        });
        assert!(!user_command_can_omit_sign_in_activity(&focused));
        assert!(user_command_can_omit_sign_in_activity(&full));
    }

    #[test]
    fn sign_in_activity_view_keeps_raw_timestamp_and_adds_both_ages() {
        let record = BTreeMap::from([
            ("id".into(), json!("00000000-0000-4000-8000-000000000044")),
            ("displayName".into(), json!("Test Person")),
            ("userPrincipalName".into(), json!("person@example.test")),
            (
                "signInActivity".into(),
                json!({
                    "lastSuccessfulSignInDateTime": "2026-08-30T00:00:00Z",
                    "lastSuccessfulSignInRequestId": "00000000-0000-4000-8000-000000000045"
                }),
            ),
        ]);
        let observed_at = DateTime::parse_from_rfc3339("2026-08-31T01:01:01Z")
            .unwrap()
            .with_timezone(&Utc);
        let options = OutputOptions {
            format: OutputFormat::Table,
            select: String::new(),
            results_only: false,
            wrap_untrusted: false,
        };
        let mut output = Vec::new();
        write_sign_in_activity(
            &mut output,
            &options,
            "person@example.test",
            &record,
            observed_at,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("2026-08-30T00:00:00Z"));
        assert!(output.contains("90061"));
        assert!(output.contains("1 day 1 hour ago"));
        assert!(output.contains("00000000-0000-4000-8000-000000000045"));
    }

    #[test]
    fn sign_in_activity_json_preserves_graph_object_and_has_derived_age() {
        let record = BTreeMap::from([(
            "signInActivity".into(),
            json!({
                "lastSignInDateTime": "2026-08-31T00:00:00Z",
                "lastSignInRequestId": "request-id"
            }),
        )]);
        let observed_at = DateTime::parse_from_rfc3339("2026-08-31T00:01:30Z")
            .unwrap()
            .with_timezone(&Utc);
        let options = OutputOptions {
            format: OutputFormat::Json,
            select: String::new(),
            results_only: false,
            wrap_untrusted: false,
        };
        let mut output = Vec::new();
        write_sign_in_activity(
            &mut output,
            &options,
            "person@example.test",
            &record,
            observed_at,
        )
        .unwrap();
        let output: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            output["results"]["signInActivity"]["lastSignInDateTime"],
            "2026-08-31T00:00:00Z"
        );
        assert_eq!(
            output["results"]["signInActivityAge"]["lastSignInDateTime"]["seconds"],
            90
        );
        assert_eq!(
            output["results"]["signInActivityAge"]["lastSignInDateTime"]["human"],
            "1 minute 30 seconds ago"
        );
    }

    #[test]
    fn future_sign_in_timestamp_is_reported_as_clock_skew_not_negative_ago() {
        assert_eq!(human_age(-65), "in 1 minute 5 seconds");
    }

    #[test]
    fn proxy_prefix_case_identifies_the_primary_address() {
        assert_eq!(
            classify_proxy_address("SMTP:primary@example.test"),
            ("primary".into(), "primary@example.test".into())
        );
        assert_eq!(
            classify_proxy_address("smtp:alias@example.test"),
            ("alias".into(), "alias@example.test".into())
        );
    }

    #[test]
    fn auth_refresh_accepts_directory_and_repeatable_scope_upgrades() {
        let cli = Cli::try_parse_from([
            "entra",
            "auth",
            "refresh",
            "--directory",
            "--scope",
            "AuditLog.Read.All",
            "--scope",
            "People.Read",
        ])
        .unwrap();
        let Command::Auth(AuthArgs {
            command: AuthCommand::Refresh(refresh),
        }) = cli.command
        else {
            panic!("expected auth refresh command");
        };
        assert!(refresh.directory);
        assert_eq!(refresh.scope, ["AuditLog.Read.All", "People.Read"]);
    }

    #[test]
    fn refresh_consent_failure_has_actionable_guidance() {
        let error = EntraError::OAuth {
            status: 400,
            operation: "refresh token failed".into(),
            code: "invalid_grant".into(),
            description: "AADSTS65001 consent required".into(),
        };
        let message = annotate_refresh_error(error, "person@example.test").to_string();
        assert!(message.contains("administrator consent"));
        assert!(message.contains("entra auth login --directory"));
    }
}
