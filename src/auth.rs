use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use url::Url;
use uuid::Uuid;

use crate::config::{self, atomic_write};
use crate::error::{EntraError, Result};
use crate::secrets::{delete_value, get_value, store_value, token_key, CredentialStore};

pub const SCOPE_USER: &str = "User.Read";
pub const SCOPE_USER_READ_BASIC_ALL: &str = "User.ReadBasic.All";
pub const SCOPE_USER_READ_ALL: &str = "User.Read.All";
pub const SCOPE_AUDIT_LOG_READ_ALL: &str = "AuditLog.Read.All";
pub const SCOPE_OFFLINE_ACCESS: &str = "offline_access";

const AUTHORITY_BASE: &str = "https://login.microsoftonline.com";
const GRAPH_ME_URL: &str = "https://graph.microsoft.com/v1.0/me";
const MAX_OAUTH_RESPONSE: usize = 100 * 1024;
const EXPIRY_SKEW_SECS: i64 = 60;

pub fn default_scopes() -> Vec<String> {
    [SCOPE_OFFLINE_ACCESS, SCOPE_USER, SCOPE_USER_READ_BASIC_ALL]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub fn directory_scopes() -> Vec<String> {
    let mut scopes = default_scopes();
    scopes.extend([SCOPE_USER_READ_ALL, SCOPE_AUDIT_LOG_READ_ALL].map(str::to_owned));
    scopes
}

pub fn merge_scopes(base: Vec<String>, extras: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    base.into_iter()
        .chain(extras.iter().cloned())
        .filter_map(|scope| {
            let trimmed = scope.trim();
            if trimmed.is_empty() || !seen.insert(trimmed.to_ascii_lowercase()) {
                None
            } else {
                Some(trimmed.to_owned())
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub email: String,
    pub display_name: String,
    pub tenant_id: String,
    pub client_id: String,
    pub login_time: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenData {
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub email: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
}

impl TokenData {
    fn parsed_expiry(&self) -> Option<chrono::DateTime<chrono::FixedOffset>> {
        chrono::DateTime::parse_from_rfc3339(&self.expires_at).ok()
    }

    fn needs_refresh(&self) -> bool {
        if self.access_token.is_empty() {
            return true;
        }
        if self.expires_at.is_empty() {
            return false;
        }
        self.parsed_expiry().is_none_or(|expiry| {
            expiry <= chrono::Utc::now() + chrono::Duration::seconds(EXPIRY_SKEW_SECS)
        })
    }

    fn is_hard_expired(&self) -> bool {
        if self.access_token.is_empty() {
            return true;
        }
        if self.expires_at.is_empty() {
            return false;
        }
        self.parsed_expiry()
            .is_none_or(|expiry| expiry <= chrono::Utc::now())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default = "default_expires_in")]
    expires_in: u64,
    #[serde(default)]
    #[serde(rename = "token_type")]
    _token_type: String,
    #[serde(default)]
    scope: String,
}

fn default_expires_in() -> u64 {
    3600
}

fn safe_expires_in(value: u64) -> i64 {
    if value == 0 || value > 86_400 {
        3_600
    } else {
        value as i64
    }
}

fn refreshed_token_data(
    email: &str,
    previous: &TokenData,
    response: TokenResponse,
    requested_scope: Option<&str>,
) -> TokenData {
    TokenData {
        access_token: response.access_token,
        refresh_token: if response.refresh_token.is_empty() {
            previous.refresh_token.clone()
        } else {
            response.refresh_token
        },
        expires_at: (chrono::Utc::now()
            + chrono::Duration::seconds(safe_expires_in(response.expires_in)))
        .to_rfc3339(),
        email: email.to_owned(),
        scope: if response.scope.is_empty() {
            requested_scope.unwrap_or(&previous.scope).to_owned()
        } else {
            response.scope
        },
    }
}

#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
    #[serde(default)]
    error_description: String,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_device_expiry")]
    expires_in: u64,
    #[serde(default = "default_poll_interval")]
    interval: u64,
}

fn default_device_expiry() -> u64 {
    900
}

fn default_poll_interval() -> u64 {
    5
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MeResponse {
    #[serde(default)]
    mail: String,
    #[serde(default)]
    user_principal_name: String,
    #[serde(default)]
    display_name: String,
}

#[derive(Clone)]
pub struct Authenticator {
    store: Arc<dyn CredentialStore>,
    client_id: String,
    tenant_id: String,
    http: reqwest::Client,
    authority_base: Url,
    graph_me_url: Url,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authenticator")
            .field("client_id", &self.client_id)
            .field("tenant_id", &self.tenant_id)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    pub fn new(
        store: Arc<dyn CredentialStore>,
        client_id: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            store,
            client_id: client_id.into(),
            tenant_id: tenant_id.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            authority_base: Url::parse(AUTHORITY_BASE)?,
            graph_me_url: Url::parse(GRAPH_ME_URL)?,
        })
    }

    #[doc(hidden)]
    pub fn with_endpoints(mut self, authority_base: Url, graph_me_url: Url) -> Self {
        self.authority_base = authority_base;
        self.graph_me_url = graph_me_url;
        self
    }

    pub async fn login_device_code(&self, scopes: &[String], verbose: bool) -> Result<AccountInfo> {
        self.validate_ids()?;
        let (verifier, challenge) = generate_pkce()?;
        let response = self
            .http
            .post(self.endpoint("devicecode")?)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("scope", scopes.join(" ").as_str()),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ])
            .send()
            .await?;
        let status = response.status();
        let body = bounded_body(response, MAX_OAUTH_RESPONSE).await?;
        if status != StatusCode::OK {
            return Err(oauth_error("device code request failed", status, &body));
        }
        let mut code: DeviceCodeResponse = serde_json::from_slice(&body)?;
        if code.device_code.is_empty() {
            return Err(EntraError::message(
                "device code response contained empty device_code",
            ));
        }
        code.interval = code.interval.clamp(1, 120);
        code.expires_in = code.expires_in.clamp(1, 3600);
        if verbose {
            eprintln!(
                "[verbose] device code response: expires_in={} interval={} verification_uri={}",
                code.expires_in,
                code.interval,
                sanitize_multiline(&code.verification_uri)
            );
            eprintln!(
                "[verbose] client_id={} tenant={} scopes={}",
                self.client_id,
                self.tenant_id,
                scopes.join(" ")
            );
        }
        eprintln!(
            "\nTo sign in, open a browser to:\n  {}\n\nEnter the code: {}\n\nWaiting for authentication...",
            sanitize_multiline(&code.verification_uri),
            sanitize_multiline(&code.user_code)
        );
        let token = self
            .poll_for_token(&code, &verifier, verbose)
            .await
            .map_err(|error| error.context("polling for token"))?;
        eprint!("\r\x1b[K");
        self.finish_login(token, scopes).await
    }

    pub async fn login_browser(&self, scopes: &[String], verbose: bool) -> Result<AccountInfo> {
        self.validate_ids()?;
        let (verifier, challenge) = generate_pkce()?;
        let state = random_urlsafe(24)?;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| {
                EntraError::Io(error).context(
                    "starting loopback listener for browser login (rerun without --browser to use device code flow)",
                )
            })?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!("http://localhost:{port}/callback");
        let authorize = self.authorization_url(&redirect_uri, scopes, &state, &challenge)?;
        if verbose {
            eprintln!("[verbose] loopback listener on port {port}");
            eprintln!(
                "[verbose] client_id={} tenant={} scopes={}",
                self.client_id,
                self.tenant_id,
                scopes.join(" ")
            );
        }
        eprintln!(
            "\nOpening your browser to sign in. If it does not open, visit:\n  {authorize}\n\nWaiting for authentication..."
        );
        if webbrowser::open(authorize.as_str()).is_err() {
            eprintln!("warning: could not open the system browser");
        }
        let code = timeout(Duration::from_secs(900), receive_callback(listener, &state))
            .await
            .map_err(|_| {
                EntraError::message(
                    "timed out waiting for browser authentication; rerun without --browser to use device code flow",
                )
            })??;
        let token = self
            .exchange_code(&code, &redirect_uri, &verifier, scopes)
            .await?;
        self.finish_login(token, scopes).await
    }

    pub async fn access_token(&self, email: &str, verbose: bool) -> Result<String> {
        self.validate_ids()?;
        let data = self.load_token(email)?;
        if !data.needs_refresh() {
            return Ok(data.access_token);
        }
        let scope = (!data.scope.is_empty()).then_some(data.scope.as_str());
        match self
            .refresh_access_token(&data.refresh_token, scope, verbose)
            .await
        {
            Ok(response) => {
                let refreshed = refreshed_token_data(email, &data, response, scope);
                if let Err(error) = self.store_token(email, &refreshed) {
                    if verbose {
                        eprintln!(
                            "[verbose] refreshed token is usable but could not be persisted: {error}"
                        );
                    }
                }
                Ok(refreshed.access_token)
            }
            Err(error) if !data.is_hard_expired() => {
                if verbose {
                    eprintln!(
                        "[verbose] early token refresh failed; using the current token until its hard expiry: {error}"
                    );
                }
                Ok(data.access_token)
            }
            Err(error) => Err(error.context(format!("refreshing expired token for {email}"))),
        }
    }

    /// Force a non-interactive refresh. Unlike the background refresh path,
    /// persistence failure is fatal because updating the stored credential is
    /// the command's purpose.
    pub async fn refresh(
        &self,
        email: &str,
        scopes: Option<&[String]>,
        verbose: bool,
    ) -> Result<TokenData> {
        self.validate_ids()?;
        let data = self.load_token(email)?;
        let explicit_scope = scopes
            .filter(|values| !values.is_empty())
            .map(|values| values.join(" "));
        let scope = explicit_scope
            .as_deref()
            .or_else(|| (!data.scope.is_empty()).then_some(data.scope.as_str()));
        let response = self
            .refresh_access_token(&data.refresh_token, scope, verbose)
            .await?;
        let refreshed = refreshed_token_data(email, &data, response, scope);
        self.store_token(email, &refreshed)?;
        Ok(refreshed)
    }

    pub fn logout(&self, email: &str) -> Result<()> {
        delete_value(self.store.as_ref(), &token_key(email))
            .map_err(|error| error.context(format!("deleting token for {email}")))?;
        let path = account_file_path(email)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn list_accounts(&self) -> Result<Vec<AccountInfo>> {
        list_accounts()
    }

    async fn poll_for_token(
        &self,
        code: &DeviceCodeResponse,
        verifier: &str,
        verbose: bool,
    ) -> Result<TokenResponse> {
        let mut interval = code.interval;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(code.expires_in);
        loop {
            sleep(Duration::from_secs(interval)).await;
            if tokio::time::Instant::now() >= deadline {
                return Err(EntraError::message(
                    "device code expired before login completed",
                ));
            }
            let response = self
                .http
                .post(self.endpoint("token")?)
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", code.device_code.as_str()),
                    ("code_verifier", verifier),
                ])
                .send()
                .await?;
            let status = response.status();
            let body = bounded_body(response, MAX_OAUTH_RESPONSE).await?;
            if status == StatusCode::OK {
                let token: TokenResponse = serde_json::from_slice(&body)?;
                if token.access_token.is_empty() {
                    return Err(EntraError::message(
                        "token response contained empty access token",
                    ));
                }
                return Ok(token);
            }
            let parsed = serde_json::from_slice::<OAuthError>(&body).ok();
            if verbose {
                if let Some(error) = &parsed {
                    eprintln!(
                        "[verbose] poll response: status={} error={} description={}",
                        status,
                        sanitize_multiline(&error.error),
                        sanitize_multiline(&error.error_description)
                    );
                }
            }
            match parsed.as_ref().map(|error| error.error.as_str()) {
                Some("authorization_pending") => continue,
                Some("slow_down") => {
                    interval = (interval + 5).min(120);
                    continue;
                }
                Some("access_denied" | "invalid_grant") => {
                    let base = oauth_error("token request failed", status, &body);
                    return Err(EntraError::message(format!(
                        "{base} (if your organization blocks device code flow or requires a compliant device, retry with --browser)"
                    )));
                }
                _ => return Err(oauth_error("token request failed", status, &body)),
            }
        }
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
        scopes: &[String],
    ) -> Result<TokenResponse> {
        let response = self
            .http
            .post(self.endpoint("token")?)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
                ("scope", scopes.join(" ").as_str()),
            ])
            .send()
            .await?;
        let status = response.status();
        let body = bounded_body(response, MAX_OAUTH_RESPONSE).await?;
        if status != StatusCode::OK {
            return Err(oauth_error("code exchange failed", status, &body));
        }
        let token: TokenResponse = serde_json::from_slice(&body)?;
        if token.access_token.is_empty() {
            return Err(EntraError::message(
                "code exchange response contained empty access token",
            ));
        }
        Ok(token)
    }

    async fn refresh_access_token(
        &self,
        refresh_token: &str,
        scope: Option<&str>,
        verbose: bool,
    ) -> Result<TokenResponse> {
        let mut form = vec![
            ("client_id", self.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        if let Some(scope) = scope {
            form.push(("scope", scope));
        }
        let response = self
            .http
            .post(self.endpoint("token")?)
            .form(&form)
            .send()
            .await?;
        let status = response.status();
        let body = bounded_body(response, MAX_OAUTH_RESPONSE).await?;
        if status != StatusCode::OK {
            if verbose {
                eprintln!("[verbose] refresh failed: status={status}");
            }
            return Err(oauth_error("refresh token failed", status, &body));
        }
        if verbose {
            eprintln!("[verbose] token refresh successful");
        }
        let token: TokenResponse = serde_json::from_slice(&body)?;
        if token.access_token.is_empty() {
            return Err(EntraError::message(
                "refresh response contained empty access token",
            ));
        }
        Ok(token)
    }

    async fn finish_login(
        &self,
        token: TokenResponse,
        requested_scopes: &[String],
    ) -> Result<AccountInfo> {
        if token.refresh_token.is_empty() {
            return Err(EntraError::message(
                "no refresh token returned; ensure the offline_access scope was granted",
            ));
        }
        let response = self
            .http
            .get(self.graph_me_url.clone())
            .bearer_auth(&token.access_token)
            .send()
            .await?;
        let status = response.status();
        let body = bounded_body(response, MAX_OAUTH_RESPONSE).await?;
        if status != StatusCode::OK {
            return Err(EntraError::message(format!(
                "profile request failed with status {}",
                status.as_u16()
            )));
        }
        let me: MeResponse = serde_json::from_slice(&body)?;
        let email = if me.mail.is_empty() {
            me.user_principal_name
        } else {
            me.mail
        }
        .to_ascii_lowercase();
        if email.is_empty() {
            return Err(EntraError::message(
                "profile response contained no mail or userPrincipalName",
            ));
        }
        self.store_token(
            &email,
            &TokenData {
                access_token: token.access_token,
                refresh_token: token.refresh_token,
                expires_at: (chrono::Utc::now()
                    + chrono::Duration::seconds(safe_expires_in(token.expires_in)))
                .to_rfc3339(),
                email: email.clone(),
                scope: if token.scope.is_empty() {
                    requested_scopes.join(" ")
                } else {
                    token.scope
                },
            },
        )?;
        let info = AccountInfo {
            email,
            display_name: me.display_name,
            tenant_id: self.tenant_id.clone(),
            client_id: self.client_id.clone(),
            login_time: system_time_rfc3339(),
        };
        save_account(&info)?;
        Ok(info)
    }

    fn load_token(&self, email: &str) -> Result<TokenData> {
        let raw = get_value(self.store.as_ref(), &token_key(email))?;
        let data: TokenData = serde_json::from_str(&raw)?;
        if data.refresh_token.is_empty() {
            return Err(EntraError::message(
                "stored token data contains empty refresh token",
            ));
        }
        Ok(data)
    }

    fn store_token(&self, email: &str, data: &TokenData) -> Result<()> {
        store_value(
            self.store.as_ref(),
            &token_key(email),
            &serde_json::to_string(data)?,
        )
        .map_err(|error| error.context("storing token in keyring"))
    }

    fn endpoint(&self, leaf: &str) -> Result<Url> {
        let mut url = self.authority_base.clone();
        url.path_segments_mut()
            .map_err(|_| EntraError::message("authority URL cannot hold path segments"))?
            .pop_if_empty()
            .push(&self.tenant_id)
            .push("oauth2")
            .push("v2.0")
            .push(leaf);
        Ok(url)
    }

    fn authorization_url(
        &self,
        redirect_uri: &str,
        scopes: &[String],
        state: &str,
        challenge: &str,
    ) -> Result<Url> {
        let mut authorize = self.endpoint("authorize")?;
        authorize
            .query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_mode", "query")
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
        Ok(authorize)
    }

    fn validate_ids(&self) -> Result<()> {
        if Uuid::parse_str(&self.client_id).is_err() {
            return Err(EntraError::message(format!(
                "invalid client ID {:?}: must be a UUID",
                self.client_id
            )));
        }
        if !matches!(
            self.tenant_id.as_str(),
            "common" | "organizations" | "consumers"
        ) && Uuid::parse_str(&self.tenant_id).is_err()
        {
            return Err(EntraError::message(format!(
                "invalid tenant ID {:?}: must be a UUID or one of: common, organizations, consumers",
                self.tenant_id
            )));
        }
        Ok(())
    }
}

async fn receive_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
    let (mut stream, _) = listener.accept().await?;
    let mut buffer = vec![0_u8; 16 * 1024];
    let read = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| EntraError::message("browser callback was not a valid HTTP request"))?;
    let callback = Url::parse(&format!("http://localhost{target}"))?;
    let query: std::collections::HashMap<_, _> = callback.query_pairs().into_owned().collect();
    let result = match (query.get("state"), query.get("code"), query.get("error")) {
        (Some(state), Some(code), _) if state == expected_state => Ok(code.clone()),
        (Some(_), _, _) => Err(EntraError::message(
            "browser callback state did not match; refusing the authorization response",
        )),
        (_, _, Some(error)) => Err(EntraError::message(format!(
            "browser authentication failed: {error}: {}",
            query.get("error_description").cloned().unwrap_or_default()
        ))),
        _ => Err(EntraError::message(
            "browser callback did not contain an authorization code",
        )),
    };
    let (status, body) = if result.is_ok() {
        (
            "200 OK",
            "Authentication complete. You can close this window.",
        )
    } else {
        (
            "400 Bad Request",
            "Authentication failed. Return to the terminal.",
        )
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    result
}

fn generate_pkce() -> Result<(String, String)> {
    let verifier = random_urlsafe(32)?;
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    Ok((verifier, challenge))
}

fn random_urlsafe(length: usize) -> Result<String> {
    let mut bytes = vec![0_u8; length];
    getrandom::fill(&mut bytes)
        .map_err(|error| EntraError::message(format!("generating secure random value: {error}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

async fn bounded_body(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(EntraError::message(format!(
            "response exceeds the {maximum}-byte limit"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(EntraError::message(format!(
                "response exceeds the {maximum}-byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn oauth_error(context: &str, status: StatusCode, body: &[u8]) -> EntraError {
    if let Ok(error) = serde_json::from_slice::<OAuthError>(body) {
        return EntraError::OAuth {
            status: status.as_u16(),
            operation: context.to_owned(),
            code: sanitize_multiline(&error.error),
            description: sanitize_multiline(&error.error_description),
        };
    }
    EntraError::message(format!("{context} with status {}", status.as_u16()))
}

fn sanitize_multiline(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect()
}

fn account_file_path(email: &str) -> Result<PathBuf> {
    let lowered = email.to_ascii_lowercase().replace("..", "_");
    let safe = Path::new(&lowered)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| EntraError::message("account address is not a safe file name"))?;
    Ok(config::accounts_dir()?.join(format!("{safe}.json")))
}

fn save_account(info: &AccountInfo) -> Result<()> {
    config::ensure_config_dirs()?;
    atomic_write(
        &account_file_path(&info.email)?,
        &serde_json::to_vec_pretty(info)?,
    )
}

pub fn list_accounts() -> Result<Vec<AccountInfo>> {
    let directory = config::accounts_dir()?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut accounts: Vec<AccountInfo> = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        match fs::read(entry.path())
            .map_err(EntraError::from)
            .and_then(|data| serde_json::from_slice(&data).map_err(Into::into))
        {
            Ok(info) => accounts.push(info),
            Err(error) => eprintln!(
                "warning: skipping account file {:?}: {error}",
                entry.file_name()
            ),
        }
    }
    accounts.sort_by(|left, right| left.email.cmp(&right.email));
    Ok(accounts)
}

fn system_time_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::secrets::test_support::MemoryStore;

    use super::*;

    struct FailingWriteStore {
        value: String,
    }

    impl CredentialStore for FailingWriteStore {
        fn get_password(&self, _key: &str) -> Result<Option<String>> {
            Ok(Some(self.value.clone()))
        }

        fn set_password(&self, _key: &str, _value: &str) -> Result<()> {
            Err(EntraError::message("simulated keyring write failure"))
        }

        fn get_secret(&self, _key: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn set_secret(&self, _key: &str, _value: &[u8]) -> Result<()> {
            Err(EntraError::message("simulated keyring write failure"))
        }

        fn delete(&self, _key: &str) -> Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn scope_merge_is_ordered_trimmed_and_case_insensitive() {
        let scopes = merge_scopes(
            default_scopes(),
            &[" user.read ".into(), "AuditLog.Read.All".into()],
        );
        assert_eq!(
            scopes,
            vec![
                "offline_access",
                "User.Read",
                "User.ReadBasic.All",
                "AuditLog.Read.All"
            ]
        );
    }

    #[test]
    fn directory_scopes_include_full_profiles_and_sign_in_activity() {
        assert_eq!(
            directory_scopes(),
            vec![
                "offline_access",
                "User.Read",
                "User.ReadBasic.All",
                "User.Read.All",
                "AuditLog.Read.All"
            ]
        );
    }

    #[test]
    fn token_data_accepts_the_existing_go_keyring_json() {
        let token: TokenData = serde_json::from_str(
            r#"{"access_token":"","refresh_token":"secret","expires_at":"0001-01-01T00:00:00Z","email":"person@example.test"}"#,
        )
        .unwrap();
        assert_eq!(token.refresh_token, "secret");
    }

    #[test]
    fn token_without_expiry_is_assumed_valid_but_malformed_expiry_is_not() {
        let mut token = TokenData {
            access_token: "opaque-access".into(),
            refresh_token: "refresh".into(),
            ..TokenData::default()
        };
        assert!(!token.needs_refresh());
        assert!(!token.is_hard_expired());
        token.expires_at = "not-a-timestamp".into();
        assert!(token.needs_refresh());
        assert!(token.is_hard_expired());
    }

    #[test]
    fn account_info_accepts_the_existing_go_json() {
        let account: AccountInfo = serde_json::from_str(
            r#"{"email":"person@example.test","display_name":"Test Person","tenant_id":"tenant","client_id":"client","login_time":"2026-01-02T03:04:05Z"}"#,
        )
        .unwrap();
        assert_eq!(account.display_name, "Test Person");
        assert_eq!(account.login_time, "2026-01-02T03:04:05Z");
    }

    #[tokio::test]
    async fn reuses_a_still_valid_access_token_from_the_go_keyring_shape() {
        let account = "person@example.test";
        let store = Arc::new(MemoryStore::default());
        store
            .set_password(
                &token_key(account),
                &serde_json::json!({
                    "access_token": "cached-access",
                    "refresh_token": "refresh",
                    "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                    "email": account
                })
                .to_string(),
            )
            .unwrap();
        let auth =
            Authenticator::new(store, "00000000-0000-4000-8000-000000000001", "common").unwrap();

        assert_eq!(
            auth.access_token(account, false).await.unwrap(),
            "cached-access"
        );
    }

    #[test]
    fn pkce_values_have_the_required_shape() {
        let (verifier, challenge) = generate_pkce().unwrap();
        assert!(verifier.len() >= 43);
        assert!(!challenge.contains('='));
    }

    #[test]
    fn browser_login_forces_the_account_picker() {
        let auth = Authenticator::new(
            Arc::new(MemoryStore::default()),
            "00000000-0000-4000-8000-000000000001",
            "common",
        )
        .unwrap();
        let url = auth
            .authorization_url(
                "http://localhost:1234/callback",
                &default_scopes(),
                "state",
                "challenge",
            )
            .unwrap();
        assert!(url
            .query_pairs()
            .any(|(key, value)| key == "prompt" && value == "select_account"));
    }

    #[tokio::test]
    async fn refreshes_the_existing_token_shape_and_persists_rotation() {
        let server = MockServer::start().await;
        let account = "person@example.test";
        let client_id = "00000000-0000-4000-8000-000000000001";
        let store = Arc::new(MemoryStore::default());
        store
            .set_password(
                &token_key(account),
                r#"{"access_token":"","refresh_token":"old-refresh","expires_at":"0001-01-01T00:00:00Z","email":"person@example.test"}"#,
            )
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=old-refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Authenticator::new(store.clone(), client_id, "common")
            .unwrap()
            .with_endpoints(base.clone(), base);

        assert_eq!(
            auth.access_token(account, false).await.unwrap(),
            "new-access"
        );
        let stored: TokenData =
            serde_json::from_str(&get_value(store.as_ref(), &token_key(account)).unwrap()).unwrap();
        assert_eq!(stored.refresh_token, "new-refresh");
        assert_eq!(stored.access_token, "new-access");
        assert!(chrono::DateTime::parse_from_rfc3339(&stored.expires_at).is_ok());
    }

    #[tokio::test]
    async fn early_refresh_failure_keeps_a_not_yet_expired_token() {
        let server = MockServer::start().await;
        let account = "person@example.test";
        let store = Arc::new(MemoryStore::default());
        store
            .set_password(
                &token_key(account),
                &serde_json::json!({
                    "access_token": "still-usable",
                    "refresh_token": "old-refresh",
                    "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc3339(),
                    "email": account,
                    "scope": "User.Read offline_access"
                })
                .to_string(),
            )
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(503).set_body_string("temporarily unavailable"))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Authenticator::new(store, "00000000-0000-4000-8000-000000000001", "common")
            .unwrap()
            .with_endpoints(base.clone(), base);

        assert_eq!(
            auth.access_token(account, false).await.unwrap(),
            "still-usable"
        );
    }

    #[tokio::test]
    async fn refresh_failure_does_not_reuse_a_hard_expired_token() {
        let server = MockServer::start().await;
        let account = "person@example.test";
        let store = Arc::new(MemoryStore::default());
        store
            .set_password(
                &token_key(account),
                r#"{"access_token":"expired","refresh_token":"old-refresh","expires_at":"2020-01-01T00:00:00Z","email":"person@example.test"}"#,
            )
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "refresh token revoked"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Authenticator::new(store, "00000000-0000-4000-8000-000000000001", "common")
            .unwrap()
            .with_endpoints(base.clone(), base);

        let error = auth.access_token(account, false).await.unwrap_err();
        assert!(error.to_string().contains("refreshing expired token"));
        assert!(error.to_string().contains("invalid_grant"));
    }

    #[tokio::test]
    async fn refresh_preserves_scope_and_refresh_token_when_response_omits_them() {
        let server = MockServer::start().await;
        let account = "person@example.test";
        let store = Arc::new(MemoryStore::default());
        store
            .set_password(
                &token_key(account),
                &serde_json::json!({
                    "access_token": "expired",
                    "refresh_token": "old-refresh",
                    "expires_at": "2020-01-01T00:00:00Z",
                    "email": account,
                    "scope": "User.Read.All offline_access"
                })
                .to_string(),
            )
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .and(body_string_contains("scope=User.Read.All+offline_access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Authenticator::new(
            store.clone(),
            "00000000-0000-4000-8000-000000000001",
            "common",
        )
        .unwrap()
        .with_endpoints(base.clone(), base);

        assert_eq!(
            auth.access_token(account, false).await.unwrap(),
            "new-access"
        );
        let stored: TokenData =
            serde_json::from_str(&get_value(store.as_ref(), &token_key(account)).unwrap()).unwrap();
        assert_eq!(stored.refresh_token, "old-refresh");
        assert_eq!(stored.scope, "User.Read.All offline_access");
    }

    #[tokio::test]
    async fn explicit_refresh_requests_the_override_and_persists_granted_scope() {
        let server = MockServer::start().await;
        let account = "person@example.test";
        let store = Arc::new(MemoryStore::default());
        store
            .set_password(
                &token_key(account),
                r#"{"access_token":"old","refresh_token":"old-refresh","expires_at":"2030-01-01T00:00:00Z","email":"person@example.test","scope":"User.Read offline_access"}"#,
            )
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .and(body_string_contains(
                "scope=offline_access+User.Read+User.ReadBasic.All+User.Read.All+AuditLog.Read.All",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "upgraded-access",
                "refresh_token": "rotated-refresh",
                "expires_in": 3600,
                "scope": "User.Read User.ReadBasic.All User.Read.All AuditLog.Read.All offline_access"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Authenticator::new(
            store.clone(),
            "00000000-0000-4000-8000-000000000001",
            "common",
        )
        .unwrap()
        .with_endpoints(base.clone(), base);

        let refreshed = auth
            .refresh(account, Some(&directory_scopes()), false)
            .await
            .unwrap();
        assert_eq!(refreshed.access_token, "upgraded-access");
        assert_eq!(refreshed.refresh_token, "rotated-refresh");
        assert!(refreshed.scope.contains("User.Read.All"));
        assert!(refreshed.scope.contains("AuditLog.Read.All"));
    }

    #[tokio::test]
    async fn background_refresh_uses_the_new_token_when_persistence_fails() {
        let server = MockServer::start().await;
        let account = "person@example.test";
        let store = Arc::new(FailingWriteStore {
            value: serde_json::json!({
                "access_token": "expired",
                "refresh_token": "old-refresh",
                "expires_at": "2020-01-01T00:00:00Z",
                "email": account,
                "scope": "User.Read offline_access"
            })
            .to_string(),
        });
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access",
                "refresh_token": "rotated-refresh",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Authenticator::new(store, "00000000-0000-4000-8000-000000000001", "common")
            .unwrap()
            .with_endpoints(base.clone(), base);

        assert_eq!(
            auth.access_token(account, false).await.unwrap(),
            "new-access"
        );
    }

    #[tokio::test]
    async fn explicit_refresh_reports_a_persistence_failure() {
        let server = MockServer::start().await;
        let account = "person@example.test";
        let store = Arc::new(FailingWriteStore {
            value: serde_json::json!({
                "access_token": "old",
                "refresh_token": "old-refresh",
                "expires_at": "2030-01-01T00:00:00Z",
                "email": account,
                "scope": "User.Read offline_access"
            })
            .to_string(),
        });
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Authenticator::new(store, "00000000-0000-4000-8000-000000000001", "common")
            .unwrap()
            .with_endpoints(base.clone(), base);

        let error = auth.refresh(account, None, false).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("simulated keyring write failure"));
    }
}
