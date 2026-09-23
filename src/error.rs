use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EntraError {
    #[error("{0}")]
    Message(String),

    #[error("no directory user matches {key:?} by sign-in name, object id, primary mail or proxy address")]
    UserNotFound { key: String },

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
            | Self::SignInActivityRole { source } => source.is_not_found(),
            _ => false,
        }
    }

    pub fn is_permission(&self) -> bool {
        match self {
            Self::Permission { .. } => true,
            Self::Graph { code, .. } => code.eq_ignore_ascii_case("Authorization_RequestDenied"),
            Self::Context { source, .. } | Self::SignInActivityRole { source } => {
                source.is_permission()
            }
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
            | Self::SignInActivityRole { source } => source.is_sign_in_activity_role_refusal(),
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
            Self::Graph { status, code, .. } => {
                if code.eq_ignore_ascii_case("Request_ResourceNotFound") {
                    ("ResourceNotFound", *status)
                } else {
                    (code.as_str(), *status)
                }
            }
            Self::OAuth { status, code, .. } => (code.as_str(), *status),
            Self::Permission { .. } => ("Authorization_RequestDenied", 403),
            Self::SignInActivityRole { source } => source.metadata(),
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
