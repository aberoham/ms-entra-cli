use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::time::sleep;

use crate::error::{EntraError, Result};
use crate::model::{Page, User};

pub const GRAPH_V1: &str = "https://graph.microsoft.com/v1.0/";
const MAX_QUERY_LENGTH: usize = 256;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 3;
const MAX_PAGES: usize = 1_000;

const PROFILE_FIELDS: &[&str] = &[
    "id",
    "displayName",
    "givenName",
    "surname",
    "mail",
    "userPrincipalName",
    "jobTitle",
    "department",
    "companyName",
    "officeLocation",
    "employeeId",
    "employeeType",
    "accountEnabled",
    "createdDateTime",
    "proxyAddresses",
    "otherMails",
    "mailNickname",
    "onPremisesSamAccountName",
    "usageLocation",
];

#[derive(Debug, Clone)]
pub struct GraphClient {
    http: reqwest::Client,
    access_token: String,
    base_url: Url,
    verbose: bool,
}

impl GraphClient {
    pub fn new(access_token: impl Into<String>, timeout: Duration, verbose: bool) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            access_token: access_token.into(),
            base_url: Url::parse(GRAPH_V1)?,
            verbose,
        })
    }

    #[doc(hidden)]
    pub fn with_base_url(mut self, base_url: Url) -> Self {
        self.base_url = base_url;
        self
    }

    pub async fn get_user(&self, key: &str) -> Result<User> {
        match self.get_user_direct(key).await {
            Ok(user) => Ok(user),
            Err(error) if error.is_permission() => Err(error.permission("read user profiles")),
            Err(error) if !error.is_not_found() => {
                Err(error.context(format!("reading user profile for {key:?}")))
            }
            Err(_) => match self.find_by_address(key).await {
                Ok(user) => Ok(user),
                Err(error) if error.is_permission() => {
                    Err(error.permission("search user email addresses"))
                }
                Err(error) if error.is_not_found() => Err(EntraError::UserNotFound {
                    key: key.to_owned(),
                }),
                Err(error) => Err(error.context(format!(
                    "searching for {key:?} after the direct lookup missed"
                ))),
            },
        }
    }

    pub async fn get_user_attributes(
        &self,
        key: &str,
        properties: &[&str],
    ) -> Result<BTreeMap<String, Value>> {
        if properties.is_empty() {
            return Err(EntraError::message("no properties requested"));
        }
        odata_literal(key)?;
        if key.contains('@') {
            let resolved = match self.resolve_key(key).await {
                Ok(value) => value,
                Err(error) if error.is_not_found() => {
                    return Err(EntraError::UserNotFound {
                        key: key.to_owned(),
                    });
                }
                Err(error) if error.is_permission() => {
                    return Err(error.permission("resolve the user's email address"));
                }
                Err(error) => {
                    return Err(error.context(format!(
                        "resolving {key:?} to an object id before reading requested attributes"
                    )));
                }
            };
            return match self.get_attributes_direct(&resolved, properties).await {
                Ok(record) => Ok(record),
                Err(error)
                    if error.is_permission()
                        || error.is_sign_in_activity_role_refusal() =>
                {
                    Err(attribute_permission(error, properties))
                }
                Err(error) => Err(error.context(format!(
                    "found directory user {key:?} as object {resolved:?}, but reading the requested attributes failed"
                ))),
            };
        }
        match self.get_attributes_direct(key, properties).await {
            Ok(record) => Ok(record),
            Err(error) if error.is_permission() || error.is_sign_in_activity_role_refusal() => {
                Err(attribute_permission(error, properties))
            }
            Err(error) if !error.is_not_found() => {
                Err(error.context(format!("reading requested attributes for {key:?}")))
            }
            Err(_) => {
                let resolved = match self.resolve_key(key).await {
                    Ok(value) => value,
                    Err(error) if error.is_not_found() => {
                        return Err(EntraError::UserNotFound {
                            key: key.to_owned(),
                        });
                    }
                    Err(error) if error.is_permission() => {
                        return Err(error.permission("resolve the user's email address"));
                    }
                    Err(error) => {
                        return Err(error
                            .context(format!("resolving {key:?} after the direct lookup missed")));
                    }
                };
                match self.get_attributes_direct(&resolved, properties).await {
                    Ok(record) => Ok(record),
                    Err(error)
                        if error.is_permission()
                            || error.is_sign_in_activity_role_refusal() =>
                    {
                        Err(attribute_permission(error, properties))
                    }
                    Err(error) => Err(error.context(format!(
                        "found directory user {key:?} as object {resolved:?}, but reading the requested attributes failed"
                    ))),
                }
            }
        }
    }

    pub async fn get_manager(&self, key: &str) -> Result<Option<User>> {
        match self.manager_direct(key).await {
            Ok(manager) => Ok(Some(manager)),
            Err(error) if error.is_permission() => {
                Err(error.permission("read the manager relationship"))
            }
            Err(error) if !error.is_not_found() => {
                Err(error.context(format!("getting manager for {key:?}")))
            }
            Err(_) => {
                let id = match self.resolve_key(key).await {
                    Ok(value) => value,
                    Err(error) if error.is_permission() => {
                        return Err(error.permission("resolve the user's email address"));
                    }
                    Err(error) if error.is_not_found() => {
                        return Err(EntraError::UserNotFound {
                            key: key.to_owned(),
                        });
                    }
                    Err(error) => {
                        return Err(error.context(format!(
                            "resolving {key:?} after the manager lookup missed"
                        )));
                    }
                };
                match self.manager_direct(&id).await {
                    Ok(manager) => Ok(Some(manager)),
                    Err(error) if error.is_not_found() => Ok(None),
                    Err(error) if error.is_permission() => {
                        Err(error.permission("read the manager relationship"))
                    }
                    Err(error) => Err(error.context(format!("getting manager for {key:?}"))),
                }
            }
        }
    }

    pub async fn get_direct_reports(&self, key: &str) -> Result<Vec<User>> {
        match self.direct_reports_direct(key).await {
            Ok(reports) => Ok(reports),
            Err(error) if error.is_permission() => Err(error.permission("read direct reports")),
            Err(error) if !error.is_not_found() => {
                Err(error.context(format!("getting direct reports for {key:?}")))
            }
            Err(_) => {
                let id = match self.resolve_key(key).await {
                    Ok(value) => value,
                    Err(error) if error.is_permission() => {
                        return Err(error.permission("resolve the user's email address"));
                    }
                    Err(error) if error.is_not_found() => {
                        return Err(EntraError::UserNotFound {
                            key: key.to_owned(),
                        });
                    }
                    Err(error) => {
                        return Err(error.context(format!(
                            "resolving {key:?} after the direct-reports lookup missed"
                        )));
                    }
                };
                self.direct_reports_direct(&id).await.map_err(|error| {
                    if error.is_permission() {
                        error.permission("read direct reports")
                    } else {
                        error.context(format!("getting direct reports for {key:?}"))
                    }
                })
            }
        }
    }

    pub async fn get_chain(&self, key: &str, max_depth: usize) -> Result<Vec<User>> {
        let maximum = if max_depth == 0 { 10 } else { max_depth };
        let start = self.get_user(key).await?;
        let mut seen = std::collections::HashSet::from([start.id.clone()]);
        let mut chain = vec![start];
        while chain.len() < maximum {
            let current_id = chain
                .last()
                .map(|user| user.id.as_str())
                .unwrap_or_default();
            let Some(manager) = self.get_manager(current_id).await? else {
                break;
            };
            if !seen.insert(manager.id.clone()) {
                break;
            }
            chain.push(manager);
        }
        Ok(chain)
    }

    pub async fn search_users(&self, query: &str, top: usize) -> Result<Vec<User>> {
        let escaped = odata_literal(query)?;
        let filter = format!(
            "startswith(displayName,'{escaped}') or startswith(mail,'{escaped}') or startswith(userPrincipalName,'{escaped}') or startswith(surname,'{escaped}')"
        );
        let mut url = self.collection_url("users")?;
        url.query_pairs_mut()
            .append_pair("$select", &PROFILE_FIELDS.join(","))
            .append_pair("$filter", &filter)
            .append_pair("$top", &top.max(1).to_string());
        self.get_all_pages(url, Some(top.max(1)))
            .await
            .map_err(|error| {
                if error.is_permission() {
                    error.permission("search the directory")
                } else {
                    error.context(format!("searching for {query:?}"))
                }
            })
    }

    pub async fn me(&self) -> Result<User> {
        let mut url = self.collection_url("me")?;
        url.query_pairs_mut()
            .append_pair("$select", &PROFILE_FIELDS.join(","));
        self.get_json(url)
            .await
            .map_err(|error| error.context("getting own profile"))
    }

    async fn get_user_direct(&self, key: &str) -> Result<User> {
        let mut url = self.user_url(key)?;
        url.query_pairs_mut()
            .append_pair("$select", &PROFILE_FIELDS.join(","));
        self.get_json(url).await
    }

    async fn find_by_address(&self, address: &str) -> Result<User> {
        if !address.contains('@') {
            return Err(EntraError::UserNotFound {
                key: address.to_owned(),
            });
        }
        let escaped = odata_literal(address)?;
        let filter = format!(
            "mail eq '{escaped}' or userPrincipalName eq '{escaped}' or proxyAddresses/any(p:p eq 'smtp:{}')",
            escaped.to_ascii_lowercase()
        );
        let mut url = self.collection_url("users")?;
        url.query_pairs_mut()
            .append_pair("$select", &PROFILE_FIELDS.join(","))
            .append_pair("$filter", &filter)
            .append_pair("$top", "2");
        let page: Page<User> = self.get_json(url).await?;
        page.value
            .into_iter()
            .next()
            .ok_or_else(|| EntraError::UserNotFound {
                key: address.to_owned(),
            })
    }

    async fn resolve_key(&self, key: &str) -> Result<String> {
        let user = if key.contains('@') {
            self.find_by_address(key).await?
        } else {
            self.get_user_direct(key).await?
        };
        if user.id.is_empty() {
            return Err(EntraError::UserNotFound {
                key: key.to_owned(),
            });
        }
        Ok(user.id)
    }

    async fn get_attributes_direct(
        &self,
        key: &str,
        properties: &[&str],
    ) -> Result<BTreeMap<String, Value>> {
        let mut url = self.user_url(key)?;
        url.query_pairs_mut()
            .append_pair("$select", &properties.join(","));
        let mut record: BTreeMap<String, Value> = self.get_json(url).await?;
        record.remove("@odata.context");
        Ok(record)
    }

    async fn manager_direct(&self, key: &str) -> Result<User> {
        let mut url = self.user_relation_url(key, "manager")?;
        url.query_pairs_mut()
            .append_pair("$select", &PROFILE_FIELDS.join(","));
        self.get_json(url).await
    }

    async fn direct_reports_direct(&self, key: &str) -> Result<Vec<User>> {
        let mut url = self.user_relation_url(key, "directReports")?;
        url.query_pairs_mut()
            .append_pair("$select", &PROFILE_FIELDS.join(","));
        self.get_all_pages(url, None).await
    }

    async fn get_all_pages<T: DeserializeOwned>(
        &self,
        mut url: Url,
        maximum_items: Option<usize>,
    ) -> Result<Vec<T>> {
        let mut values = Vec::new();
        let mut visited = std::collections::HashSet::new();
        for _ in 0..MAX_PAGES {
            if !visited.insert(url.as_str().to_owned()) {
                return Err(EntraError::message(
                    "Graph pagination repeated a URL; refusing an infinite loop",
                ));
            }
            let page: Page<T> = self.get_json(url).await?;
            values.extend(page.value);
            if let Some(maximum) = maximum_items {
                if values.len() >= maximum {
                    values.truncate(maximum);
                    return Ok(values);
                }
            }
            let Some(next) = page.next_link else {
                return Ok(values);
            };
            url = self.validated_next_link(&next)?;
        }
        Err(EntraError::message(format!(
            "Graph pagination exceeded the safety limit of {MAX_PAGES} pages"
        )))
    }

    fn validated_next_link(&self, next: &str) -> Result<Url> {
        let url = Url::parse(next)?;
        let same_origin = url.scheme() == self.base_url.scheme()
            && url.host_str() == self.base_url.host_str()
            && url.port_or_known_default() == self.base_url.port_or_known_default();
        if !same_origin {
            return Err(EntraError::message(format!(
                "Graph returned an unsafe cross-origin pagination URL for {:?}",
                url.origin().ascii_serialization()
            )));
        }
        Ok(url)
    }

    fn collection_url(&self, segment: &str) -> Result<Url> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| EntraError::message("Graph base URL cannot hold path segments"))?
            .pop_if_empty()
            .push(segment);
        Ok(url)
    }

    fn user_url(&self, key: &str) -> Result<Url> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| EntraError::message("Graph base URL cannot hold path segments"))?
            .pop_if_empty()
            .push("users")
            .push(key);
        Ok(url)
    }

    fn user_relation_url(&self, key: &str, relation: &str) -> Result<Url> {
        let mut url = self.user_url(key)?;
        url.path_segments_mut()
            .map_err(|_| EntraError::message("Graph base URL cannot hold path segments"))?
            .push(relation);
        Ok(url)
    }

    async fn get_json<T: DeserializeOwned>(&self, url: Url) -> Result<T> {
        let body = self.request_bytes(Method::GET, url).await?;
        serde_json::from_slice(&body)
            .map_err(|error| EntraError::message(format!("decoding Graph response: {error}")))
    }

    async fn request_bytes(&self, method: Method, url: Url) -> Result<Vec<u8>> {
        for attempt in 1..=MAX_ATTEMPTS {
            if self.verbose {
                eprintln!("[verbose] {} {}", method, url);
            }
            let response = match self
                .http
                .request(method.clone(), url.clone())
                .bearer_auth(&self.access_token)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
            {
                Ok(response) => response,
                Err(error)
                    if attempt < MAX_ATTEMPTS && (error.is_connect() || error.is_timeout()) =>
                {
                    sleep(Duration::from_millis(250 << (attempt - 1))).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let status = response.status();
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(Duration::from_secs);
            if let Some(length) = response.content_length() {
                if length > MAX_RESPONSE_BYTES as u64 {
                    return Err(EntraError::message(format!(
                        "Graph response is too large ({length} bytes, maximum {MAX_RESPONSE_BYTES})"
                    )));
                }
            }
            let mut response = response;
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err(EntraError::message(format!(
                        "Graph response is too large (more than {MAX_RESPONSE_BYTES} bytes)"
                    )));
                }
                body.extend_from_slice(&chunk);
            }
            if status.is_success() {
                return Ok(body);
            }
            let retryable = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if retryable && attempt < MAX_ATTEMPTS {
                let delay =
                    retry_after.unwrap_or_else(|| Duration::from_millis(250 << (attempt - 1)));
                sleep(delay.min(Duration::from_secs(30))).await;
                continue;
            }
            return Err(EntraError::from_graph(status.as_u16(), &body));
        }
        Err(EntraError::message("Graph request exhausted its retries"))
    }
}

fn attribute_permission(error: EntraError, properties: &[&str]) -> EntraError {
    if properties.contains(&"signInActivity") && error.is_sign_in_activity_role_refusal() {
        return error.sign_in_activity_role();
    }
    if properties.contains(&"signInActivity") {
        error.permission_with_scope(
            "read sign-in activity",
            "AuditLog.Read.All",
            "add AuditLog.Read.All to the app registration, grant administrator consent, then run 'entra auth refresh --directory' (or sign in again with 'entra auth login --directory')",
        )
    } else {
        error.permission("read the requested user attributes")
    }
}

pub fn odata_literal(value: &str) -> Result<String> {
    if value.len() > MAX_QUERY_LENGTH {
        return Err(EntraError::message(format!(
            "query is too long ({} characters, maximum {MAX_QUERY_LENGTH})",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(EntraError::message("query contains a control character"));
    }
    Ok(value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use wiremock::matchers::{header, method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    async fn client(server: &MockServer) -> GraphClient {
        GraphClient::new("test-token", Duration::from_secs(2), false)
            .unwrap()
            .with_base_url(Url::parse(&format!("{}/v1.0/", server.uri())).unwrap())
    }

    #[test]
    fn odata_literals_double_quotes_and_reject_controls() {
        assert_eq!(odata_literal("o'brien").unwrap(), "o''brien");
        assert!(odata_literal("bad\0value").is_err());
        assert!(odata_literal(&"a".repeat(MAX_QUERY_LENGTH + 1)).is_err());
    }

    #[test]
    fn sign_in_activity_permission_names_its_distinct_scope() {
        let error = attribute_permission(
            EntraError::Graph {
                status: 403,
                code: "Authorization_RequestDenied".into(),
                message: "Insufficient privileges".into(),
            },
            &["id", "signInActivity"],
        );
        assert!(error.to_string().contains("AuditLog.Read.All"));
        assert!(!error.to_string().contains("lacks delegated User.Read.All"));
    }

    #[tokio::test]
    async fn deep_lookup_resolves_address_before_reading_attributes() {
        let server = MockServer::start().await;
        let address = "alex.smyth19@example.test";
        let object_id = "00000000-0000-4000-8000-000000000019";
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{address}")))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {
                    "code": "BadRequest",
                    "message": "Get By Key only supports UserId and the key has to be a valid Guid"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(header("authorization", "Bearer test-token"))
            .and(query_param("$top", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": object_id, "mail": address, "userPrincipalName": "alex.smith19@example.test"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": object_id,
                "mail": address,
                "department": "Engineering",
                "signInActivity": {"lastSuccessfulSignInDateTime": "2026-08-30T00:00:00Z"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let record = client(&server)
            .await
            .get_user_attributes(address, &["id", "mail", "department", "signInActivity"])
            .await
            .unwrap();
        assert_eq!(record["id"], object_id);
    }

    #[tokio::test]
    async fn sign_in_activity_role_refusal_keeps_code_and_names_required_role() {
        let server = MockServer::start().await;
        let address = "alex@example.test";
        let object_id = "00000000-0000-4000-8000-000000000043";
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": object_id, "userPrincipalName": address}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}")))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {
                    "code": "Authentication_RequestFromUnsupportedUserRole",
                    "message": "User is not in the allowed roles"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .get_user_attributes(address, &["id", "signInActivity"])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Reports Reader"));
        assert!(error.to_string().contains("signed-in account"));
        assert_eq!(
            error.metadata(),
            ("Authentication_RequestFromUnsupportedUserRole", 403)
        );
    }

    #[tokio::test]
    async fn real_miss_replaces_graphs_ambiguous_message() {
        let server = MockServer::start().await;
        let address = "missing@example.test";
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{address}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "Request_ResourceNotFound", "message": "or one of its queried reference-property objects are not present"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": []})))
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .get_user_attributes(address, &["id"])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no directory user matches"));
        assert!(!error.to_string().contains("reference-property"));
        assert_eq!(error.metadata(), ("ResourceNotFound", 404));
    }

    #[tokio::test]
    async fn unrelated_direct_failure_is_not_misreported_as_a_miss() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users/someone@example.test"))
            .respond_with(ResponseTemplate::new(502).set_body_json(json!({
                "error": {"code": "ServiceUnavailable", "message": "try later"}
            })))
            .expect(3)
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .get_user("someone@example.test")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reading user profile"));
        assert!(error.to_string().contains("ServiceUnavailable"));
    }

    #[tokio::test]
    async fn guest_upn_is_encoded_as_one_path_segment() {
        let server = MockServer::start().await;
        let guest = "person_example.com#EXT#@tenant.onmicrosoft.com";
        Mock::given(method("GET"))
            .and(path_regex(
                r"^/v1\.0/users/person_example\.com%23EXT%23@tenant\.onmicrosoft\.com$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "object-id", "userPrincipalName": guest
            })))
            .expect(1)
            .mount(&server)
            .await;
        let result = client(&server).await.get_user(guest).await;
        let requests = server.received_requests().await.unwrap_or_default();
        let user = result.unwrap_or_else(|error| panic!("{error}; requests: {requests:#?}"));
        assert_eq!(user.user_principal_name, guest);
    }

    #[tokio::test]
    async fn refuses_cross_host_pagination_links() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users/person/directReports"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [], "@odata.nextLink": "https://attacker.example/steal"
            })))
            .mount(&server)
            .await;
        let error = client(&server)
            .await
            .get_direct_reports("person")
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsafe cross-origin pagination URL"));
    }

    #[tokio::test]
    async fn refuses_same_host_pagination_links_on_another_port() {
        let server = MockServer::start().await;
        let other_port = server.address().port().saturating_add(1);
        Mock::given(method("GET"))
            .and(path("/v1.0/users/person/directReports"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [],
                "@odata.nextLink": format!("http://127.0.0.1:{other_port}/steal")
            })))
            .mount(&server)
            .await;
        let error = client(&server)
            .await
            .get_direct_reports("person")
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unsafe cross-origin pagination URL"));
    }

    #[tokio::test]
    async fn existing_object_id_with_no_manager_is_not_reported_missing() {
        let server = MockServer::start().await;
        let object_id = "00000000-0000-4000-8000-000000000042";
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}/manager")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "Request_ResourceNotFound", "message": "not found"}
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": object_id
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert!(client(&server)
            .await
            .get_manager(object_id)
            .await
            .unwrap()
            .is_none());
    }
}
