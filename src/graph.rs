use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::time::sleep;
use uuid::Uuid;

use crate::error::{EntraError, Result};
use crate::model::{Group, ManagedUser, Page, ReportSettings, SubscribedSku, User};
use crate::output::sanitize;

pub const GRAPH_V1: &str = "https://graph.microsoft.com/v1.0/";
const MAX_QUERY_LENGTH: usize = 256;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ATTEMPTS: usize = 3;
const MAX_PAGES: usize = 1_000;
// Graph's page ceilings for a user collection, which is lower when the query
// selects signInActivity. An expanded relationship draws smaller pages still,
// which Graph imposes on its own.
const LIST_PAGE_SIZE: &str = "999";
const SIGN_IN_ACTIVITY_PAGE_SIZE: &str = "500";
const MANAGER_EXPANSION: &str = "manager($select=id,displayName,userPrincipalName,accountEnabled)";
const SKU_FIELDS: &str = "skuId,skuPartNumber,consumedUnits,prepaidUnits";
const BETA_FROM_V1: &str = "../beta/";
const COMPANY_FIELDS: &[&str] = &[
    "id",
    "displayName",
    "userPrincipalName",
    "companyName",
    "department",
];
// How many matches a name lookup fetches, so an ambiguous name can be
// reported with some of the people it matches.
const NAME_MATCH_LIMIT: usize = 5;

/// Whether `key` can only be a person's name. Graph's `/users/{key}` route
/// accepts an object id or a sign-in name, and every sign-in name contains
/// `@`, so any other key would always miss there.
pub fn is_name_key(key: &str) -> bool {
    !key.contains('@') && Uuid::parse_str(key).is_err()
}

/// How a name lookup matched its one person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameMatch {
    /// The key equals the person's display name or surname, ignoring case.
    Exact,
    /// The person's display name or surname only starts with the key.
    Prefix,
}

/// The one person a name lookup found, and how the name matched them.
#[derive(Debug, Clone)]
pub struct NamedUser {
    pub user: User,
    pub matched: NameMatch,
}

/// A person as `Name <sign-in name>`, sanitised because it ends up in error
/// messages that reach both the terminal and JSON.
pub fn person_label(user: &User) -> String {
    format!(
        "{} <{}>",
        sanitize(&user.display_name),
        sanitize(&user.user_principal_name)
    )
}

fn name_match(key: &str, user: &User) -> NameMatch {
    let key = key.trim().to_lowercase();
    let exact = [&user.display_name, &user.surname]
        .iter()
        .any(|name| name.trim().to_lowercase() == key);
    if exact {
        NameMatch::Exact
    } else {
        NameMatch::Prefix
    }
}

pub const PROFILE_FIELDS: &[&str] = &[
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

const GROUP_FIELDS: &[&str] = &[
    "id",
    "displayName",
    "mail",
    "mailEnabled",
    "securityEnabled",
    "groupTypes",
    "onPremisesSyncEnabled",
];

fn group_permission(error: EntraError) -> EntraError {
    error.permission_with_scope(
        "read group memberships",
        "GroupMember.Read.All",
        "Have an administrator grant it, then run 'entra auth refresh --groups' (or sign in again with 'entra auth login --directory --groups')",
    )
}

fn membership_error(error: EntraError, key: &str) -> EntraError {
    if error.is_permission() {
        group_permission(error)
    } else if error.is_not_found() {
        EntraError::UserNotFound {
            key: key.to_owned(),
        }
    } else {
        error.context(format!("reading group memberships for {key:?}"))
    }
}

#[derive(Clone)]
pub struct GraphClient {
    http: reqwest::Client,
    access_token: String,
    base_url: Url,
    verbose: bool,
    progress: Option<ProgressSink>,
}

/// Receives the number of items read so far while a read spans several
/// pages, and `None` once that read ends, whether it succeeded or failed.
/// A read that fits in one page reports nothing.
pub type ProgressSink = Arc<dyn Fn(Option<usize>) + Send + Sync>;

/// Reports a paged read's progress and, when dropped, its end, so the sink
/// hears the end on every return path, including errors.
struct PageProgress<'a> {
    sink: Option<&'a ProgressSink>,
    reported: bool,
}

impl PageProgress<'_> {
    fn report(&mut self, count: usize) {
        if let Some(sink) = self.sink {
            sink(Some(count));
            self.reported = true;
        }
    }
}

impl Drop for PageProgress<'_> {
    fn drop(&mut self) {
        if let (Some(sink), true) = (self.sink, self.reported) {
            sink(None);
        }
    }
}

/// Leaves the bearer token out, so a debug print can never leak it.
impl std::fmt::Debug for GraphClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GraphClient")
            .field("base_url", &self.base_url.as_str())
            .field("verbose", &self.verbose)
            .finish_non_exhaustive()
    }
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
            progress: None,
        })
    }

    /// Sends the progress of every read that spans several pages to `sink`,
    /// unless the client is verbose.
    pub fn with_progress(mut self, sink: ProgressSink) -> Self {
        self.progress = Some(sink);
        self
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

    /// Reads the manager of the user whose object id Graph itself returned,
    /// `None` when the directory records no manager. Because the id came from
    /// Graph, a typed not-found answer means no manager, and no address
    /// fallback is tried: one request per person.
    pub async fn manager_of_object(&self, id: &str) -> Result<Option<User>> {
        match self.manager_direct(id).await {
            Ok(manager) => Ok(Some(manager)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) if error.is_permission() => {
                Err(error.permission("read the manager relationship"))
            }
            Err(error) => Err(error.context(format!("getting manager for {id:?}"))),
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

    /// Returns the groups a person belongs to, transitively and directly, as
    /// two lists. An address is resolved to an object id first so that both
    /// reads name the same person. Graph answers a token without a group-read
    /// permission with groups stripped to their ids rather than with an error,
    /// so a group without a display name is reported as a permission failure.
    pub async fn get_group_memberships(&self, key: &str) -> Result<(Vec<Group>, Vec<Group>)> {
        odata_literal(key)?;
        let id = if key.contains('@') {
            match self.resolve_key(key).await {
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
                        "resolving {key:?} to an object id before reading group memberships"
                    )));
                }
            }
        } else {
            key.to_owned()
        };
        let transitive = self.groups_direct(&id, "transitiveMemberOf").await;
        let transitive = transitive.map_err(|error| membership_error(error, key))?;
        let direct = self.groups_direct(&id, "memberOf").await;
        let direct = direct.map_err(|error| membership_error(error, key))?;
        if transitive
            .iter()
            .chain(&direct)
            .any(|group| group.display_name.is_empty())
        {
            return Err(group_permission(EntraError::message(
                "Graph returned groups without their names",
            )));
        }
        Ok((transitive, direct))
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
            if manager.id.is_empty() {
                return Err(EntraError::message(
                    "Graph returned a manager without an object id, so the chain cannot continue",
                ));
            }
            if !seen.insert(manager.id.clone()) {
                break;
            }
            chain.push(manager);
        }
        Ok(chain)
    }

    /// Finds the one person a name refers to, by a prefix match on display
    /// name and surname only: a mail or sign-in prefix such as `ann` for
    /// `announcements@` could otherwise single out someone the caller never
    /// named. More than one match is an error that lists the candidates,
    /// because every caller acts on exactly one person and must not guess.
    pub async fn resolve_by_name(&self, key: &str) -> Result<NamedUser> {
        let key = key.trim();
        let escaped = odata_literal(key)?;
        let filter =
            format!("startswith(displayName,'{escaped}') or startswith(surname,'{escaped}')");
        let mut found = self.find_users(&filter, NAME_MATCH_LIMIT, key).await?;
        if found.iter().any(|user| user.id.is_empty()) {
            return Err(EntraError::message(format!(
                "Graph returned a match for {key:?} without an object id, so the name cannot be resolved safely; pass a full address instead"
            )));
        }
        match found.len() {
            0 => Err(EntraError::UserNotFound {
                key: key.to_owned(),
            }),
            1 => {
                let user = found.remove(0);
                let matched = name_match(key, &user);
                Ok(NamedUser { user, matched })
            }
            _ => Err(EntraError::AmbiguousUser {
                key: key.to_owned(),
                candidates: found.iter().map(person_label).collect(),
            }),
        }
    }

    pub async fn search_users(&self, query: &str, top: usize) -> Result<Vec<User>> {
        let escaped = odata_literal(query)?;
        let filter = format!(
            "startswith(displayName,'{escaped}') or startswith(mail,'{escaped}') or startswith(userPrincipalName,'{escaped}') or startswith(surname,'{escaped}')"
        );
        self.find_users(&filter, top, query).await
    }

    async fn find_users(&self, filter: &str, top: usize, query: &str) -> Result<Vec<User>> {
        let mut url = self.collection_url("users")?;
        url.query_pairs_mut()
            .append_pair("$select", &PROFILE_FIELDS.join(","))
            .append_pair("$filter", filter)
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

    /// Lists every user in the directory with the summary profile fields.
    pub async fn list_users(&self) -> Result<Vec<User>> {
        let url = self.list_url(PROFILE_FIELDS, None)?;
        self.get_all_pages(url, None).await.map_err(|error| {
            if error.is_permission() {
                error.permission("list directory users")
            } else {
                error.context("listing directory users")
            }
        })
    }

    /// Lists every user's summary profile with their manager expanded, in
    /// one paged read. With `enabled_only`, Graph returns only accounts whose
    /// `accountEnabled` is `true`. Graph pages expanded reads in far smaller
    /// pages than plain ones, so leaving out disabled accounts on the server
    /// saves many sequential requests.
    pub async fn list_users_with_managers(&self, enabled_only: bool) -> Result<Vec<ManagedUser>> {
        let mut url = self.list_url(PROFILE_FIELDS, Some(MANAGER_EXPANSION))?;
        if enabled_only {
            url.query_pairs_mut()
                .append_pair("$filter", "accountEnabled eq true");
        }
        self.get_all_pages(url, None).await.map_err(|error| {
            if error.is_permission() {
                error.permission("list directory users and their managers")
            } else {
                error.context("listing directory users and their managers")
            }
        })
    }

    /// Lists every user as an unmapped record holding `properties`.
    ///
    /// Every record carries every requested property, as `null` where Graph
    /// left it out (it omits `signInActivity` for anyone with no recorded
    /// sign-in), so all records share one set of keys. With `manager`, each
    /// record also carries a `manager` key: `null` when the directory holds no
    /// manager, otherwise the manager's id, display name, sign-in name and
    /// enabled state.
    pub async fn list_user_records(
        &self,
        properties: &[&str],
        manager: bool,
    ) -> Result<Vec<BTreeMap<String, Value>>> {
        if properties.is_empty() {
            return Err(EntraError::message("no properties requested"));
        }
        let expand = manager.then_some(MANAGER_EXPANSION);
        let url = self.list_url(properties, expand)?;
        let mut records: Vec<BTreeMap<String, Value>> =
            self.get_all_pages(url, None).await.map_err(|error| {
                if error.is_authorization_failure() {
                    attribute_permission(error, properties)
                } else {
                    error.context("listing directory users")
                }
            })?;
        for record in &mut records {
            record.remove("@odata.context");
            for property in properties {
                record.entry((*property).to_owned()).or_insert(Value::Null);
            }
            if manager {
                normalise_manager(record);
            }
        }
        Ok(records)
    }

    /// Lists the licences the tenant subscribes to. The route accepts only
    /// `$select`, so matching by name happens locally.
    pub async fn list_subscribed_skus(&self) -> Result<Vec<SubscribedSku>> {
        let mut url = self.collection_url("subscribedSkus")?;
        url.query_pairs_mut().append_pair("$select", SKU_FIELDS);
        self.get_all_pages(url, None).await.map_err(|error| {
            if error.is_permission() {
                error.licence_access()
            } else {
                error.context("listing the tenant's licences")
            }
        })
    }

    /// Lists every user holding the licence `sku_id`, disabled accounts and
    /// guests included. The filter is built from a parsed id, so no caller
    /// text reaches OData, and Graph serves it without advanced-query headers.
    pub async fn list_licence_holders(&self, sku_id: Uuid) -> Result<Vec<User>> {
        let mut url = self.list_url(PROFILE_FIELDS, None)?;
        url.query_pairs_mut().append_pair(
            "$filter",
            &format!("assignedLicenses/any(x:x/skuId eq {})", sku_id.hyphenated()),
        );
        self.get_all_pages(url, None).await.map_err(|error| {
            if error.is_permission() {
                error.permission("list licence holders")
            } else {
                error.context("listing licence holders")
            }
        })
    }

    /// Reads one Microsoft 365 Copilot usage report function, such as
    /// `getMicrosoft365CopilotUsageUserDetail`, for a period such as `D28`.
    /// Both values come from fixed lists in the caller. The beta endpoint is
    /// used because v1.0 serves these reports only as CSV and answers a JSON
    /// request with 400 "JSON format is not supported"; beta returns paged
    /// JSON from the same host, so pagination checks still apply.
    pub async fn copilot_report(&self, function: &str, period: &str) -> Result<Vec<Value>> {
        let mut url = self.base_url.join(BETA_FROM_V1)?;
        url.path_segments_mut()
            .map_err(|_| EntraError::message("Graph base URL cannot hold path segments"))?
            .pop_if_empty()
            .push("copilot")
            .push("reports")
            .push(&format!("{function}(period='{period}')"));
        self.get_all_pages(url, None)
            .await
            .map_err(|error| report_refusal(error, "reading the Copilot usage report"))
    }

    /// Reads the tenant's report settings. `displayConcealedNames` is true
    /// when usage reports replace names and addresses with opaque codes.
    pub async fn report_settings(&self) -> Result<ReportSettings> {
        let mut url = self.collection_url("admin")?;
        url.path_segments_mut()
            .map_err(|_| EntraError::message("Graph base URL cannot hold path segments"))?
            .push("reportSettings");
        let mut body: Value = self
            .get_json(url)
            .await
            .map_err(|error| report_refusal(error, "reading the report settings"))?;
        if body["value"].is_object() {
            body = body["value"].take();
        }
        Ok(serde_json::from_value(body)?)
    }

    /// Lists every user's sign-in name, company and department, for joining
    /// usage report rows to the directory.
    pub async fn list_user_companies(&self) -> Result<Vec<User>> {
        let url = self.list_url(COMPANY_FIELDS, None)?;
        self.get_all_pages(url, None).await.map_err(|error| {
            if error.is_permission() {
                error.permission("list users' companies")
            } else {
                error.context("listing users' companies")
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
        // Graph may split even two results across pages, so read until two
        // are found or the pages run out.
        let found: Vec<User> = self.get_all_pages(url, Some(2)).await?;
        // Two objects can hold one address, such as a guest whose mail
        // matches a member's alias; pick neither.
        if found.len() > 1 {
            return Err(EntraError::AmbiguousUser {
                key: address.to_owned(),
                candidates: found.iter().map(person_label).collect(),
            });
        }
        found
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

    /// Reads one membership relationship and keeps only the groups. The
    /// relationship also returns directory roles and administrative units;
    /// they are filtered here rather than with an OData cast, because Graph
    /// documents a cast on these routes as an advanced query that needs
    /// `$count` and a `ConsistencyLevel` header on every page.
    async fn groups_direct(&self, key: &str, relation: &str) -> Result<Vec<Group>> {
        let mut url = self.user_relation_url(key, relation)?;
        url.query_pairs_mut()
            .append_pair("$select", &GROUP_FIELDS.join(","));
        let objects: Vec<Group> = self.get_all_pages(url, None).await?;
        Ok(objects.into_iter().filter(Group::is_group).collect())
    }

    async fn get_all_pages<T: DeserializeOwned>(
        &self,
        mut url: Url,
        maximum_items: Option<usize>,
    ) -> Result<Vec<T>> {
        let mut values = Vec::new();
        let mut visited = std::collections::HashSet::new();
        // Verbose request lines would land in the middle of the progress
        // line, so a verbose client shows only the request lines.
        let mut progress = PageProgress {
            sink: self.progress.as_ref().filter(|_| !self.verbose),
            reported: false,
        };
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
            progress.report(values.len());
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

    fn list_url(&self, properties: &[&str], expand: Option<&str>) -> Result<Url> {
        let page_size = if properties.contains(&"signInActivity") {
            SIGN_IN_ACTIVITY_PAGE_SIZE
        } else {
            LIST_PAGE_SIZE
        };
        let mut url = self.collection_url("users")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("$select", &properties.join(","));
            if let Some(expand) = expand {
                query.append_pair("$expand", expand);
            }
            query.append_pair("$top", page_size);
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
        // A URL path treats these as navigation, not as a segment, so they
        // would address the collection or its parent instead of a person.
        if matches!(key.trim(), "" | "." | "..") {
            return Err(EntraError::UserNotFound {
                key: key.to_owned(),
            });
        }
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
            let body = match read_bounded_body(response).await {
                Ok(body) => body,
                // A connection that drops part way through a body is as
                // transient as one that fails before the headers.
                Err(EntraError::Http(error))
                    if attempt < MAX_ATTEMPTS
                        && (error.is_timeout() || error.is_body() || error.is_decode()) =>
                {
                    sleep(retry_delay(retry_after, attempt)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if status.is_success() {
                return Ok(body);
            }
            let retryable = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if retryable && attempt < MAX_ATTEMPTS {
                sleep(retry_delay(retry_after, attempt)).await;
                continue;
            }
            return Err(EntraError::from_graph(status.as_u16(), &body));
        }
        Err(EntraError::message("Graph request exhausted its retries"))
    }
}

/// How long to wait before another attempt: Graph's numeric `Retry-After`
/// when it sent one, otherwise an exponential backoff, never above 30 seconds.
fn retry_delay(retry_after: Option<Duration>, attempt: usize) -> Duration {
    retry_after
        .unwrap_or_else(|| Duration::from_millis(250 << (attempt - 1)))
        .min(Duration::from_secs(30))
}

/// Reads a response body, refusing one larger than `MAX_RESPONSE_BYTES`.
async fn read_bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(EntraError::message(format!(
                "Graph response is too large (more than {MAX_RESPONSE_BYTES} bytes)"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Gives every listed record an explicit `manager` value. Graph omits the key
/// or sends null when nobody is recorded, and tags an expanded manager with
/// an `@odata.type` that says nothing a caller needs.
fn normalise_manager(record: &mut BTreeMap<String, Value>) {
    let mut manager = record.remove("manager").unwrap_or(Value::Null);
    if let Value::Object(fields) = &mut manager {
        fields.remove("@odata.type");
    }
    record.insert("manager".into(), manager);
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
            "query is too long ({} bytes of UTF-8, maximum {MAX_QUERY_LENGTH})",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(EntraError::message("query contains a control character"));
    }
    Ok(value.replace('\'', "''"))
}

/// Usage-report routes refuse a missing scope or role with 403 and codes
/// such as `S2SUnauthorized` or `UnknownError` rather than
/// `Authorization_RequestDenied`, so the status decides.
fn report_refusal(error: EntraError, operation: &str) -> EntraError {
    if error.is_permission() || error.metadata().1 == 403 {
        error.reports_access()
    } else {
        error.context(operation)
    }
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

    #[tokio::test]
    async fn dot_and_empty_keys_never_reach_a_url() {
        let server = MockServer::start().await;
        let graph = client(&server).await;
        for key in ["", " ", ".", ".."] {
            let error = graph.get_direct_reports(key).await.unwrap_err();
            assert!(error.is_not_found(), "{key:?}: {error}");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_chain_stops_at_a_manager_without_an_object_id() {
        let server = MockServer::start().await;
        let start = "00000000-0000-4000-8000-000000000061";
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{start}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(person(start, "Al")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{start}/manager")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"displayName": "No Id"})))
            .mount(&server)
            .await;
        let error = client(&server).await.get_chain(start, 5).await.unwrap_err();
        assert!(
            error.to_string().contains("without an object id"),
            "{error}"
        );
    }

    /// Serves two responses on a raw socket: the first cut off half way
    /// through its body with the given status line and extra headers, the
    /// second complete. Returns the client's base address.
    async fn cut_off_then_complete(
        first_status: &'static str,
        first_headers: &'static str,
        body: String,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for complete in [false, true] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0_u8; 4096];
                let _ = stream.read(&mut request).await.unwrap();
                let (status, headers, sent) = if complete {
                    ("200 OK", "", body.len())
                } else {
                    (first_status, first_headers, body.len() / 2)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    &body[..sent]
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (address, server)
    }

    fn raw_client(address: std::net::SocketAddr) -> GraphClient {
        GraphClient::new("test-token", Duration::from_secs(5), false)
            .unwrap()
            .with_base_url(Url::parse(&format!("http://{address}/v1.0/")).unwrap())
    }

    #[tokio::test]
    async fn a_body_cut_off_part_way_is_retried() {
        let body =
            json!({"id": "00000000-0000-4000-8000-000000000051", "displayName": "Al"}).to_string();
        let (address, server) = cut_off_then_complete("200 OK", "", body).await;
        let user = raw_client(address)
            .get_user("00000000-0000-4000-8000-000000000051")
            .await
            .unwrap();
        assert_eq!(user.display_name, "Al");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_cut_off_throttling_response_still_waits_for_retry_after() {
        let body =
            json!({"id": "00000000-0000-4000-8000-000000000052", "displayName": "Bo"}).to_string();
        let (address, server) =
            cut_off_then_complete("429 Too Many Requests", "Retry-After: 1\r\n", body).await;
        let started = std::time::Instant::now();
        let user = raw_client(address)
            .get_user("00000000-0000-4000-8000-000000000052")
            .await
            .unwrap();
        assert_eq!(user.display_name, "Bo");
        assert!(
            started.elapsed() >= Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        server.await.unwrap();
    }

    fn person(id: &str, name: &str) -> Value {
        json!({
            "id": id,
            "displayName": name,
            "userPrincipalName": format!("{}@example.test", name.to_ascii_lowercase().replace(' ', ".")),
        })
    }

    async fn mount_name_search(server: &MockServer, people: Vec<Value>) {
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", NAME_MATCH_LIMIT.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": people })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn only_keys_without_an_at_sign_or_object_id_shape_are_names() {
        assert!(is_name_key("Smith"));
        assert!(is_name_key("Alex Smith"));
        assert!(!is_name_key("alex@example.test"));
        assert!(!is_name_key("00000000-0000-4000-8000-000000000041"));
    }

    #[tokio::test]
    async fn a_name_with_one_match_resolves_to_that_person() {
        let server = MockServer::start().await;
        let id = "00000000-0000-4000-8000-000000000042";
        mount_name_search(&server, vec![person(id, "Alex Smith")]).await;

        let user = client(&server)
            .await
            .resolve_by_name("Smith")
            .await
            .unwrap();
        assert_eq!(user.user.id, id);
        assert_eq!(user.matched, NameMatch::Prefix);
    }

    #[tokio::test]
    async fn a_name_with_several_matches_lists_them_and_picks_none() {
        let server = MockServer::start().await;
        mount_name_search(
            &server,
            vec![
                person("00000000-0000-4000-8000-000000000043", "Alex Smith"),
                person("00000000-0000-4000-8000-000000000044", "Sam Smith"),
            ],
        )
        .await;

        let error = client(&server)
            .await
            .resolve_by_name("Smith")
            .await
            .unwrap_err();
        let EntraError::AmbiguousUser { candidates, .. } = &error else {
            panic!("expected an ambiguous user, got {error:?}");
        };
        assert_eq!(
            candidates,
            &[
                "Alex Smith <alex.smith@example.test>",
                "Sam Smith <sam.smith@example.test>"
            ]
        );
        assert!(!error.is_not_found());
    }

    #[tokio::test]
    async fn a_name_matches_display_name_and_surname_only() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param(
                "$filter",
                "startswith(displayName,'ann') or startswith(surname,'ann')",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .expect(1)
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .resolve_by_name("ann")
            .await
            .unwrap_err();
        assert!(matches!(error, EntraError::UserNotFound { .. }));
    }

    #[tokio::test]
    async fn a_match_without_an_object_id_is_refused_not_skipped() {
        let server = MockServer::start().await;
        mount_name_search(
            &server,
            vec![
                person("00000000-0000-4000-8000-000000000045", "Alex Smith"),
                json!({"displayName": "No Id Smith"}),
            ],
        )
        .await;

        let error = client(&server)
            .await
            .resolve_by_name("Smith")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("without an object id"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn an_apostrophe_in_a_name_is_doubled_in_the_filter() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param(
                "$filter",
                "startswith(displayName,'O''Brien') or startswith(surname,'O''Brien')",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "00000000-0000-4000-8000-000000000046", "displayName": "Pat O'Brien", "surname": "O'Brien"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let named = client(&server)
            .await
            .resolve_by_name("O'Brien")
            .await
            .unwrap();
        assert_eq!(named.matched, NameMatch::Exact);
    }

    #[tokio::test]
    async fn ambiguous_candidates_are_sanitised() {
        let server = MockServer::start().await;
        mount_name_search(
            &server,
            vec![
                json!({"id": "00000000-0000-4000-8000-000000000047", "displayName": "Alex\nError: forged\u{202e}", "userPrincipalName": "a\tb@example.test"}),
                person("00000000-0000-4000-8000-000000000048", "Sam Smith"),
            ],
        )
        .await;

        let error = client(&server)
            .await
            .resolve_by_name("Smith")
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("Alex Error: forged <a b@example.test>"),
            "{message:?}"
        );
        assert!(!message.contains(['\n', '\t', '\u{202e}']), "{message:?}");
    }

    #[tokio::test]
    async fn surrounding_spaces_are_trimmed_before_the_search() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param(
                "$filter",
                "startswith(displayName,'Smith') or startswith(surname,'Smith')",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "00000000-0000-4000-8000-000000000049", "displayName": "Alex Smith", "surname": "Smith"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let named = client(&server)
            .await
            .resolve_by_name("  Smith ")
            .await
            .unwrap();
        assert_eq!(named.matched, NameMatch::Exact);
    }

    #[tokio::test]
    async fn a_name_with_no_match_is_a_missing_user() {
        let server = MockServer::start().await;
        mount_name_search(&server, vec![]).await;

        let error = client(&server)
            .await
            .resolve_by_name("Nobody")
            .await
            .unwrap_err();
        assert!(matches!(error, EntraError::UserNotFound { .. }));
    }

    #[tokio::test]
    async fn a_refused_name_search_stays_a_permission_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}
            })))
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .resolve_by_name("Smith")
            .await
            .unwrap_err();
        assert!(error.is_authorization_failure());
    }

    #[test]
    fn odata_literals_double_quotes_and_reject_controls() {
        assert_eq!(odata_literal("o'brien").unwrap(), "o''brien");
        assert!(odata_literal("bad\0value").is_err());
        assert!(odata_literal(&"a".repeat(MAX_QUERY_LENGTH + 1)).is_err());
        // The bound is in bytes: 129 two-byte letters are 258 bytes.
        let error = odata_literal(&"é".repeat(129)).unwrap_err().to_string();
        assert!(error.contains("258 bytes of UTF-8, maximum 256"), "{error}");
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
    async fn an_address_match_on_a_later_page_still_makes_it_ambiguous() {
        let server = MockServer::start().await;
        let address = "shared@example.test";
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{address}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "Request_ResourceNotFound", "message": "not found"}
            })))
            .mount(&server)
            .await;
        let next = format!("{}/v1.0/users?page=2", server.uri());
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [person("00000000-0000-4000-8000-000000000033", "First")],
                "@odata.nextLink": next,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [person("00000000-0000-4000-8000-000000000034", "Second")],
            })))
            .mount(&server)
            .await;
        let error = client(&server).await.get_user(address).await.unwrap_err();
        assert_eq!(error.metadata().0, "AmbiguousUser", "{error}");
    }

    #[tokio::test]
    async fn an_address_held_by_two_objects_is_ambiguous() {
        let server = MockServer::start().await;
        let address = "shared@example.test";
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{address}")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "Request_ResourceNotFound", "message": "not found"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": [
                {"id": "00000000-0000-4000-8000-000000000031", "displayName": "Member",
                 "userPrincipalName": "member@example.test"},
                {"id": "00000000-0000-4000-8000-000000000032", "displayName": "Guest",
                 "userPrincipalName": "guest#EXT#@example.test"},
            ]})))
            .mount(&server)
            .await;
        let error = client(&server).await.get_user(address).await.unwrap_err();
        assert_eq!(error.metadata().0, "AmbiguousUser", "{error}");
        let message = error.to_string();
        assert!(message.contains("member@example.test"), "{message}");
        assert!(message.contains("guest#EXT#@example.test"), "{message}");
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

    #[tokio::test]
    async fn list_follows_next_links_and_requests_full_pages() {
        let server = MockServer::start().await;
        let second_page = format!("{}/v1.0/users?page=2", server.uri());
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", "999"))
            .and(query_param("$select", "id,mail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "one", "mail": "one@example.test"}],
                "@odata.nextLink": second_page
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "two", "mail": "two@example.test"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let records = client(&server)
            .await
            .list_user_records(&["id", "mail"], false)
            .await
            .unwrap();
        let ids: Vec<_> = records.iter().map(|record| record["id"].clone()).collect();
        assert_eq!(ids, [json!("one"), json!("two")]);
        assert!(records.iter().all(|record| !record.contains_key("manager")));
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| !request
            .url
            .query()
            .unwrap_or("")
            .contains("expand")));
    }

    #[tokio::test]
    async fn listed_managers_are_expanded_and_normalised() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$expand", MANAGER_EXPANSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    {"id": "absent"},
                    {"id": "null", "manager": null},
                    {"id": "set", "manager": {
                        "@odata.type": "#microsoft.graph.user",
                        "id": "boss",
                        "accountEnabled": false
                    }}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let records = client(&server)
            .await
            .list_user_records(&["id"], true)
            .await
            .unwrap();
        assert_eq!(records[0]["manager"], Value::Null);
        assert_eq!(records[1]["manager"], Value::Null);
        assert_eq!(
            records[2]["manager"],
            json!({"id": "boss", "accountEnabled": false})
        );
    }

    #[tokio::test]
    async fn list_refusal_on_a_later_page_is_an_authorization_failure() {
        let server = MockServer::start().await;
        let second_page = format!("{}/v1.0/users?page=2", server.uri());
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", "999"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "one"}],
                "@odata.nextLink": second_page
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}
            })))
            .mount(&server)
            .await;

        let error = client(&server).await.list_users().await.unwrap_err();
        assert!(error.is_authorization_failure());
        assert_eq!(error.metadata(), ("Authorization_RequestDenied", 403));
    }

    #[tokio::test]
    async fn managed_listing_asks_graph_for_enabled_accounts_only_when_told() {
        use wiremock::matchers::query_param_is_missing;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$expand", MANAGER_EXPANSION))
            .and(query_param("$filter", "accountEnabled eq true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "enabled-only"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$expand", MANAGER_EXPANSION))
            .and(query_param_is_missing("$filter"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "everyone"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let graph = client(&server).await;
        let enabled = graph.list_users_with_managers(true).await.unwrap();
        let everyone = graph.list_users_with_managers(false).await.unwrap();
        assert_eq!(enabled[0].user.id, "enabled-only");
        assert_eq!(everyone[0].user.id, "everyone");
    }

    /// Serves `/v1.0/users` as two pages of one record each, the second
    /// answered with `second_status`.
    async fn two_page_server(second_status: u16) -> MockServer {
        let server = MockServer::start().await;
        let second_page = format!("{}/v1.0/users?page=2", server.uri());
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", "999"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "one"}],
                "@odata.nextLink": second_page
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(second_status).set_body_json(json!({
                "value": [{"id": "two"}],
                "error": {"code": "Authorization_RequestDenied", "message": "denied"}
            })))
            .mount(&server)
            .await;
        server
    }

    fn recording_sink() -> (ProgressSink, Arc<std::sync::Mutex<Vec<Option<usize>>>>) {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&events);
        let sink: ProgressSink = Arc::new(move |count| recorded.lock().unwrap().push(count));
        (sink, events)
    }

    #[tokio::test]
    async fn a_paged_read_reports_its_count_and_then_its_end() {
        let server = two_page_server(200).await;
        let (sink, events) = recording_sink();
        let graph = client(&server).await.with_progress(sink);
        assert_eq!(graph.list_users().await.unwrap().len(), 2);
        assert_eq!(*events.lock().unwrap(), vec![Some(1), None]);
    }

    #[tokio::test]
    async fn a_paged_read_that_fails_still_reports_its_end() {
        let server = two_page_server(403).await;
        let (sink, events) = recording_sink();
        let graph = client(&server).await.with_progress(sink);
        assert!(graph.list_users().await.is_err());
        assert_eq!(*events.lock().unwrap(), vec![Some(1), None]);
    }

    #[tokio::test]
    async fn a_verbose_client_reports_no_progress() {
        let server = two_page_server(200).await;
        let (sink, events) = recording_sink();
        let graph = GraphClient::new("test-token", Duration::from_secs(2), true)
            .unwrap()
            .with_base_url(Url::parse(&format!("{}/v1.0/", server.uri())).unwrap())
            .with_progress(sink);
        assert_eq!(graph.list_users().await.unwrap().len(), 2);
        assert!(events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_one_page_read_reports_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": "only"}]
            })))
            .mount(&server)
            .await;
        let (sink, events) = recording_sink();
        let graph = client(&server).await.with_progress(sink);
        assert_eq!(graph.list_users().await.unwrap().len(), 1);
        assert!(events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn listing_sign_in_activity_without_a_role_names_the_role() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", "500"))
            .and(query_param("$expand", MANAGER_EXPANSION))
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
            .list_user_records(&["id", "signInActivity"], true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Reports Reader"));
        assert_eq!(
            error.metadata(),
            ("Authentication_RequestFromUnsupportedUserRole", 403)
        );
    }

    #[tokio::test]
    async fn list_query_and_decoding_failures_do_not_become_permission_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$select", "id"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": {"code": "Request_UnsupportedQuery", "message": "Unsupported query."}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$select", "mail"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let graph = client(&server).await;
        let unsupported = graph.list_user_records(&["id"], false).await.unwrap_err();
        assert!(!unsupported.is_authorization_failure());
        assert_eq!(unsupported.metadata(), ("Request_UnsupportedQuery", 400));
        let malformed = graph.list_user_records(&["mail"], false).await.unwrap_err();
        assert!(!malformed.is_authorization_failure());
        assert!(malformed.to_string().contains("listing directory users"));
    }

    #[tokio::test]
    async fn every_listed_record_carries_every_requested_property() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    {"id": "active", "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}},
                    {"id": "never"}
                ]
            })))
            .mount(&server)
            .await;

        let records = client(&server)
            .await
            .list_user_records(&["id", "mail", "signInActivity"], false)
            .await
            .unwrap();
        for record in &records {
            let keys: Vec<_> = record.keys().map(String::as_str).collect();
            assert_eq!(keys, ["id", "mail", "signInActivity"]);
        }
        assert_eq!(records[1]["signInActivity"], Value::Null);
        assert!(records[0]["signInActivity"].is_object());
    }

    #[tokio::test]
    async fn empty_directory_lists_no_users() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": []})))
            .mount(&server)
            .await;

        assert!(client(&server).await.list_users().await.unwrap().is_empty());
    }

    fn group_json(id: &str, name: &str, mail_enabled: bool, security_enabled: bool) -> Value {
        json!({
            "@odata.type": "#microsoft.graph.group",
            "id": id,
            "displayName": name,
            "mail": null,
            "mailEnabled": mail_enabled,
            "securityEnabled": security_enabled,
            "groupTypes": [],
            "onPremisesSyncEnabled": null
        })
    }

    #[tokio::test]
    async fn group_memberships_resolve_an_address_and_read_both_relationships() {
        let server = MockServer::start().await;
        let address = "sam.jones@example.test";
        let object_id = "00000000-0000-4000-8000-000000000031";
        let list = "00000000-0000-4000-8000-0000000000a1";
        let nested = "00000000-0000-4000-8000-0000000000a2";
        Mock::given(method("GET"))
            .and(path("/v1.0/users"))
            .and(query_param("$top", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{"id": object_id, "mail": address}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}/transitiveMemberOf")))
            .and(query_param("$select", GROUP_FIELDS.join(",")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    group_json(list, "Example List", true, false),
                    group_json(nested, "Example Nested", false, true),
                    {
                        "@odata.type": "#microsoft.graph.directoryRole",
                        "id": "00000000-0000-4000-8000-0000000000a3",
                        "displayName": "Example Role"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}/memberOf")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [group_json(list, "Example List", true, false)]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (transitive, direct) = client(&server)
            .await
            .get_group_memberships(address)
            .await
            .unwrap();
        let ids: Vec<_> = transitive.iter().map(|group| group.id.as_str()).collect();
        assert_eq!(ids, [list, nested]);
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].id, list);
    }

    #[tokio::test]
    async fn groups_stripped_of_names_are_reported_as_a_missing_group_scope() {
        let server = MockServer::start().await;
        let object_id = "00000000-0000-4000-8000-000000000032";
        Mock::given(method("GET"))
            .and(path_regex(format!(
                r"^/v1\.0/users/{object_id}/(transitiveMemberOf|memberOf)$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "@odata.type": "#microsoft.graph.group",
                    "id": "00000000-0000-4000-8000-0000000000b1",
                    "displayName": null
                }]
            })))
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .get_group_memberships(object_id)
            .await
            .unwrap_err();
        assert!(error.is_permission());
        assert!(error.to_string().contains("GroupMember.Read.All"));
    }

    #[tokio::test]
    async fn refused_group_read_names_the_group_scope() {
        let server = MockServer::start().await;
        let object_id = "00000000-0000-4000-8000-000000000033";
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1.0/users/{object_id}/transitiveMemberOf"
            )))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}
            })))
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .get_group_memberships(object_id)
            .await
            .unwrap_err();
        assert!(error.is_permission());
        assert!(error.to_string().contains("GroupMember.Read.All"));
        assert!(!error.to_string().contains("lacks delegated User.Read.All"));
    }

    #[tokio::test]
    async fn unknown_object_id_for_group_memberships_is_a_missing_user() {
        let server = MockServer::start().await;
        let object_id = "00000000-0000-4000-8000-000000000034";
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}/transitiveMemberOf")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "error": {"code": "Request_ResourceNotFound", "message": "not found"}
            })))
            .mount(&server)
            .await;

        let error = client(&server)
            .await
            .get_group_memberships(object_id)
            .await
            .unwrap_err();
        assert!(matches!(error, EntraError::UserNotFound { .. }));
    }

    #[tokio::test]
    async fn group_memberships_follow_next_links() {
        let server = MockServer::start().await;
        let object_id = "00000000-0000-4000-8000-000000000035";
        let first = "00000000-0000-4000-8000-0000000000c1";
        let second = "00000000-0000-4000-8000-0000000000c2";
        let transitive = format!("/v1.0/users/{object_id}/transitiveMemberOf");
        Mock::given(method("GET"))
            .and(path(transitive.clone()))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [group_json(second, "Second", true, false)]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(transitive.clone()))
            .and(query_param("$select", GROUP_FIELDS.join(",")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [group_json(first, "First", true, false)],
                "@odata.nextLink": format!("{}{transitive}?page=2", server.uri())
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/users/{object_id}/memberOf")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": []})))
            .mount(&server)
            .await;

        let (transitive, _) = client(&server)
            .await
            .get_group_memberships(object_id)
            .await
            .unwrap();
        let ids: Vec<_> = transitive.iter().map(|group| group.id.as_str()).collect();
        assert_eq!(ids, [first, second]);
    }
}
