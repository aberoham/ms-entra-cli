use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntraError {
    #[error("{0}")]
    Message(String),

    #[error("no directory user matches {key:?} by sign-in name, object id, primary mail, proxy address or name")]
    UserNotFound { key: String },

    #[error(
        "{key:?} matches more than one directory user: {}. Find the person with 'entra user search' (raise -n for more results), then pass their full address or object id",
        .candidates.join("; ")
    )]
    AmbiguousUser {
        key: String,
        candidates: Vec<String>,
    },

    #[error(
        "{key:?} is not an exact display name or surname; the only person whose name starts with it is {candidate}. JSON and plain output accept only an exact name, so a near match cannot be mistaken for the person you meant. Pass that person's full address or object id, or their exact display name"
    )]
    InexactName { key: String, candidate: String },

    #[error("graph returned {status} {code}: {message}")]
    Graph {
        status: u16,
        code: String,
        message: String,
    },

    #[error("{operation}: {code}: {description}")]
    OAuth {
        status: u16,
        operation: String,
        code: String,
        description: String,
    },

    #[error(
        "not permitted to {action}: the token lacks delegated {required_scope}, which needs administrator consent. {remedy} (underlying error: {source})"
    )]
    Permission {
        action: String,
        required_scope: String,
        remedy: String,
        #[source]
        source: Box<EntraError>,
    },

    #[error(
        "not permitted to read sign-in activity: the signed-in account needs a supported Microsoft Entra role; Reports Reader is the least-privileged built-in choice. Ask an Entra administrator to assign that role, then refresh or sign in again (underlying error: {source})"
    )]
    SignInActivityRole {
        #[source]
        source: Box<EntraError>,
    },

    #[error(
        "not permitted to read the tenant's licences: the token lacks delegated LicenseAssignment.Read.All, or the signed-in account lacks a role that may read licences, such as Directory Readers or Global Reader; Graph refuses both the same way. Have an administrator grant the permission, then run 'entra auth refresh --licences', and check the account's roles. Passing a SKU id to 'licences holders --sku' skips this read (underlying error: {source})"
    )]
    LicenceAccess {
        #[source]
        source: Box<EntraError>,
    },

    #[error(
        "not permitted to read Microsoft 365 usage reports: the token lacks delegated Reports.Read.All (or ReportSettings.Read.All for the report settings), or the signed-in account lacks a role that may read usage reports, such as Reports Reader, AI Administrator or Global Reader. Have an administrator grant the permission, then run 'entra auth refresh --reports', and check the account's roles (underlying error: {source})"
    )]
    ReportsAccess {
        #[source]
        source: Box<EntraError>,
    },

    #[error(
        "another entra process kept the credential lock {path} busy for over {seconds} seconds; wait for it to finish and try again"
    )]
    CredentialLockBusy { path: String, seconds: u64 },

    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source: Box<EntraError>,
    },

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL operation failed: {0}")]
    Url(#[from] url::ParseError),

    #[error("keyring operation failed: {0}")]
    Keyring(#[from] keyring::Error),
}

impl EntraError {
    pub fn message(value: impl Into<String>) -> Self {
        Self::Message(value.into())
    }

    pub fn context(self, context: impl Into<String>) -> Self {
        Self::Context {
            context: context.into(),
            source: Box::new(self),
        }
    }

    pub fn permission(self, action: impl Into<String>) -> Self {
        self.permission_with_scope(
            action,
            "User.Read.All",
            "Have an administrator grant it, then run 'entra auth refresh --directory' (or sign in again with 'entra auth login --directory')",
        )
    }

    pub fn permission_with_scope(
        self,
        action: impl Into<String>,
        required_scope: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self::Permission {
            action: action.into(),
            required_scope: required_scope.into(),
            remedy: remedy.into(),
            source: Box::new(self),
        }
    }

    pub fn licence_access(self) -> Self {
        Self::LicenceAccess {
            source: Box::new(self),
        }
    }

    pub fn reports_access(self) -> Self {
        Self::ReportsAccess {
            source: Box::new(self),
        }
    }

    pub fn sign_in_activity_role(self) -> Self {
        Self::SignInActivityRole {
            source: Box::new(self),
        }
    }

    pub fn is_not_found(&self) -> bool {
        match self {
            Self::UserNotFound { .. } => true,
            Self::Graph { status, code, .. } => {
                *status == 404
                    || code.eq_ignore_ascii_case("Request_ResourceNotFound")
                    || code.eq_ignore_ascii_case("ResourceNotFound")
            }
            Self::Context { source, .. }
            | Self::Permission { source, .. }
            | Self::SignInActivityRole { source }
            | Self::LicenceAccess { source }
            | Self::ReportsAccess { source } => source.is_not_found(),
            _ => false,
        }
    }

    pub fn is_permission(&self) -> bool {
        match self {
            Self::Permission { .. } | Self::ReportsAccess { .. } => true,
            Self::Graph { code, .. } => code.eq_ignore_ascii_case("Authorization_RequestDenied"),
            Self::Context { source, .. }
            | Self::SignInActivityRole { source }
            | Self::LicenceAccess { source } => source.is_permission(),
            _ => false,
        }
    }

    pub fn is_sign_in_activity_role_refusal(&self) -> bool {
        match self {
            Self::Graph { code, .. } => {
                code.eq_ignore_ascii_case("Authentication_RequestFromUnsupportedUserRole")
            }
            Self::Context { source, .. }
            | Self::Permission { source, .. }
            | Self::SignInActivityRole { source }
            | Self::LicenceAccess { source }
            | Self::ReportsAccess { source } => source.is_sign_in_activity_role_refusal(),
            _ => false,
        }
    }

    pub fn is_credential_lock_busy(&self) -> bool {
        match self {
            Self::CredentialLockBusy { .. } => true,
            Self::Context { source, .. } => source.is_credential_lock_busy(),
            _ => false,
        }
    }

    pub fn is_authorization_failure(&self) -> bool {
        self.is_permission() || self.is_sign_in_activity_role_refusal()
    }

    pub fn is_consent_required(&self) -> bool {
        match self {
            Self::OAuth {
                code, description, ..
            } => {
                code.eq_ignore_ascii_case("consent_required") || description.contains("AADSTS65001")
            }
            Self::Context { source, .. } => source.is_consent_required(),
            _ => false,
        }
    }

    pub fn metadata(&self) -> (&str, u16) {
        match self {
            Self::UserNotFound { .. } => ("ResourceNotFound", 404),
            Self::AmbiguousUser { .. } => ("AmbiguousUser", 0),
            Self::InexactName { .. } => ("InexactNameMatch", 0),
            Self::CredentialLockBusy { .. } => ("CredentialLockBusy", 0),
            Self::Graph { status, code, .. } => {
                if code.eq_ignore_ascii_case("Request_ResourceNotFound") {
                    ("ResourceNotFound", *status)
                } else {
                    (code.as_str(), *status)
                }
            }
            Self::OAuth { status, code, .. } => (code.as_str(), *status),
            Self::Permission { .. } => ("Authorization_RequestDenied", 403),
            Self::SignInActivityRole { source }
            | Self::LicenceAccess { source }
            | Self::ReportsAccess { source } => source.metadata(),
            Self::Context { source, .. } => source.metadata(),
            _ => ("CommandFailed", 0),
        }
    }

    pub fn from_graph(status: u16, body: &[u8]) -> Self {
        #[derive(Deserialize)]
        struct Envelope {
            error: GraphBody,
        }
        #[derive(Deserialize)]
        struct GraphBody {
            code: String,
            #[serde(default)]
            message: String,
        }

        if let Ok(parsed) = serde_json::from_slice::<Envelope>(body) {
            return Self::Graph {
                status,
                code: parsed.error.code,
                message: parsed.error.message,
            };
        }
        let text = String::from_utf8_lossy(body).trim().to_owned();
        Self::Graph {
            status,
            code: format!("HTTP_{status}"),
            message: text,
        }
    }
}

impl From<&str> for EntraError {
    fn from(value: &str) -> Self {
        Self::Message(value.to_owned())
    }
}

impl From<String> for EntraError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

pub type Result<T> = std::result::Result<T, EntraError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_not_found_has_stable_machine_metadata() {
        let error = EntraError::from_graph(
            404,
            br#"{"error":{"code":"Request_ResourceNotFound","message":"ambiguous prose"}}"#,
        );
        assert!(error.is_not_found());
        assert_eq!(error.metadata(), ("ResourceNotFound", 404));
    }

    #[test]
    fn ambiguous_user_has_its_own_code_and_is_not_a_miss() {
        let error = EntraError::AmbiguousUser {
            key: "Smith".into(),
            candidates: vec![
                "A Smith <a@example.test>".into(),
                "B Smith <b@example.test>".into(),
            ],
        };
        assert!(!error.is_not_found());
        assert!(!error.is_authorization_failure());
        assert_eq!(error.metadata(), ("AmbiguousUser", 0));
        let message = error.to_string();
        assert!(
            message.contains("A Smith <a@example.test>; B Smith"),
            "{message}"
        );
    }

    #[test]
    fn a_busy_credential_lock_is_recognised_through_context() {
        let error = EntraError::CredentialLockBusy {
            path: "credentials.lock".into(),
            seconds: 10,
        }
        .context("loading the stored token");
        assert!(error.is_credential_lock_busy());
        assert!(!error.is_authorization_failure());
        assert_eq!(error.metadata(), ("CredentialLockBusy", 0));
        assert!(!EntraError::message("credential lock").is_credential_lock_busy());
    }

    #[test]
    fn inexact_name_has_its_own_code_and_is_not_a_miss() {
        let error = EntraError::InexactName {
            key: "Sam".into(),
            candidate: "Samantha Jones <sj@example.test>".into(),
        };
        assert!(!error.is_not_found());
        assert!(!error.is_authorization_failure());
        assert_eq!(error.metadata(), ("InexactNameMatch", 0));
    }

    #[test]
    fn permission_classification_does_not_parse_unrelated_messages() {
        let error = EntraError::Graph {
            status: 403,
            code: "Authorization_RequestDenied".into(),
            message: String::new(),
        };
        assert!(error.is_permission());
        assert!(!EntraError::message("connection refused").is_permission());
    }

    // Account fallback switches identity on a permission refusal, so only the
    // typed Graph code may trigger it, never Microsoft's wording.
    #[test]
    fn permission_classification_ignores_graph_prose() {
        let error = EntraError::Graph {
            status: 403,
            code: "Forbidden".into(),
            message: "Insufficient privileges to complete the operation.".into(),
        };
        assert!(!error.is_permission());
    }

    #[test]
    fn unsupported_sign_in_role_is_classified_by_graph_code() {
        let error = EntraError::Graph {
            status: 403,
            code: "Authentication_RequestFromUnsupportedUserRole".into(),
            message: "localized or changing prose".into(),
        };
        assert!(error.is_sign_in_activity_role_refusal());
        assert!(error.is_authorization_failure());
        let explained = error.sign_in_activity_role();
        assert!(explained.to_string().contains("Reports Reader"));
        assert_eq!(
            explained.metadata(),
            ("Authentication_RequestFromUnsupportedUserRole", 403)
        );
    }
}
