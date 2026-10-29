use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub display_name: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub given_name: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub surname: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub mail: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub user_principal_name: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub job_title: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub department: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub company_name: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub office_location: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub employee_id: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub employee_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub created_date_time: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub proxy_addresses: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub other_mails: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub mail_nickname: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub on_premises_sam_account_name: String,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub usage_location: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A group as Graph returns it from a user's `memberOf` relationship, holding
/// only the properties that decide what kind of group it is and where it is
/// administered.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    #[serde(rename = "@odata.type", default, deserialize_with = "null_to_default")]
    pub odata_type: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub display_name: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub mail: String,
    #[serde(default)]
    pub mail_enabled: Option<bool>,
    #[serde(default)]
    pub security_enabled: Option<bool>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub group_types: Vec<String>,
    #[serde(default)]
    pub on_premises_sync_enabled: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum GroupKind {
    Distribution,
    MailSecurity,
    M365,
    Security,
    Other,
}

impl GroupKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Distribution => "distribution",
            Self::MailSecurity => "mail-security",
            Self::M365 => "m365",
            Self::Security => "security",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupSource {
    OnPremises,
    Cloud,
}

impl GroupSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::OnPremises => "on-premises",
            Self::Cloud => "cloud",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Membership {
    Direct,
    Nested,
}

impl Membership {
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Nested => "nested",
        }
    }
}

impl Group {
    pub fn is_group(&self) -> bool {
        self.odata_type == "#microsoft.graph.group"
    }

    /// Classifies the group the way Exchange and Entra administrators name
    /// them. A `Unified` group type marks a Microsoft 365 group whatever its
    /// flags say; the remaining kinds follow from the two enabled flags.
    pub fn kind(&self) -> GroupKind {
        if self
            .group_types
            .iter()
            .any(|kind| kind.eq_ignore_ascii_case("Unified"))
        {
            return GroupKind::M365;
        }
        match (self.mail_enabled, self.security_enabled) {
            (Some(true), Some(false)) => GroupKind::Distribution,
            (Some(true), Some(true)) => GroupKind::MailSecurity,
            (Some(false), Some(true)) => GroupKind::Security,
            _ => GroupKind::Other,
        }
    }

    /// A group synchronised from on-premises Active Directory is read-only in
    /// the cloud: its membership is changed in the on-premises directory.
    pub fn source(&self) -> GroupSource {
        if self.on_premises_sync_enabled == Some(true) {
            GroupSource::OnPremises
        } else {
            GroupSource::Cloud
        }
    }
}

/// One row of `user groups`: a group the person belongs to, how it was
/// classified, and whether the membership is direct or arrives through
/// another group.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMembership {
    pub id: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mail: String,
    pub kind: GroupKind,
    pub source: GroupSource,
    pub membership: Membership,
}

impl GroupMembership {
    /// Joins the transitive and direct membership lists into one row per
    /// group, direct memberships first and each half ordered by name.
    pub fn from_lists(transitive: Vec<Group>, direct: &[Group]) -> Vec<Self> {
        let direct_ids: std::collections::HashSet<&str> =
            direct.iter().map(|group| group.id.as_str()).collect();
        let mut seen = std::collections::HashSet::new();
        let mut rows: Vec<Self> = transitive
            .into_iter()
            .chain(direct.iter().cloned())
            .filter(|group| seen.insert(group.id.clone()))
            .map(|group| {
                let membership = if direct_ids.contains(group.id.as_str()) {
                    Membership::Direct
                } else {
                    Membership::Nested
                };
                Self {
                    kind: group.kind(),
                    source: group.source(),
                    membership,
                    id: group.id,
                    display_name: group.display_name,
                    mail: group.mail,
                }
            })
            .collect();
        rows.sort_by(|left, right| {
            left.membership.cmp(&right.membership).then_with(|| {
                left.display_name
                    .to_lowercase()
                    .cmp(&right.display_name.to_lowercase())
            })
        });
        rows
    }

    pub fn wrap_untrusted(&self, id: &str) -> Self {
        let mut out = self.clone();
        if !out.display_name.is_empty() {
            out.display_name = format!("[UNTRUSTED:{id}]{}[/UNTRUSTED:{id}]", out.display_name);
        }
        out
    }
}

/// A licence the tenant subscribes to, as `/subscribedSkus` reports it.
/// `skuPartNumber` is the name people type; `skuId` is the product id that
/// user licence assignments carry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SubscribedSku {
    #[serde(default, deserialize_with = "null_to_default")]
    pub sku_id: String,
    #[serde(default, deserialize_with = "null_to_default")]
    pub sku_part_number: String,
    #[serde(default)]
    pub consumed_units: u64,
    #[serde(default, deserialize_with = "null_to_default")]
    pub prepaid_units: PrepaidUnits,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PrepaidUnits {
    #[serde(default)]
    pub enabled: u64,
}

/// One row of `licences holders --by-company`: a company name as the
/// directory records it, or `None` for holders with no company, and how many
/// holders carry it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompanyCount {
    pub company: Option<String>,
    pub holders: usize,
}

impl CompanyCount {
    /// Counts holders per company, largest first and ties by name, with the
    /// unnamed group after every named one of the same size. Names that differ
    /// only in surrounding whitespace are one company; case is kept as
    /// recorded, so differently cased names stay apart.
    pub fn tally(users: &[User]) -> Vec<Self> {
        let mut counts: BTreeMap<Option<String>, usize> = BTreeMap::new();
        for user in users {
            let name = user.company_name.trim();
            let key = (!name.is_empty()).then(|| name.to_owned());
            *counts.entry(key).or_default() += 1;
        }
        let mut rows: Vec<Self> = counts
            .into_iter()
            .map(|(company, holders)| Self { company, holders })
            .collect();
        rows.sort_by(|left, right| {
            right
                .holders
                .cmp(&left.holders)
                .then_with(|| left.company.is_none().cmp(&right.company.is_none()))
                .then_with(|| left.company.cmp(&right.company))
        });
        rows
    }

    pub fn wrap_untrusted(&self, id: &str) -> Self {
        Self {
            company: self
                .company
                .as_ref()
                .map(|name| format!("[UNTRUSTED:{id}]{name}[/UNTRUSTED:{id}]")),
            holders: self.holders,
        }
    }
}

/// The tenant's report settings. When `display_concealed_names` is true,
/// usage reports carry opaque codes instead of names and addresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReportSettings {
    #[serde(default)]
    pub display_concealed_names: bool,
}

const LAST_ACTIVITY_SUFFIX: &str = "LastActivityDate";

/// One person's row of the Microsoft 365 Copilot usage report, joined to the
/// directory for company and department. Counts are for the report period;
/// `last_activity_by_app` keeps every per-app date Graph reports, keyed by
/// the property name without its `LastActivityDate` suffix, so apps Microsoft
/// adds later still appear.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CopilotUsage {
    pub display_name: String,
    pub user_principal_name: String,
    pub company_name: Option<String>,
    pub department: Option<String>,
    pub last_activity_date: Option<String>,
    pub active_days: u64,
    pub prompts: u64,
    pub prompts_chat_work: u64,
    pub prompts_chat_web: u64,
    pub last_activity_by_app: BTreeMap<String, String>,
    pub report_refresh_date: String,
}

impl CopilotUsage {
    /// Reads one report record. The period detail is chosen by its length in
    /// days; a record without one has zero counts.
    pub fn from_report(record: &Value, period_days: u64) -> Self {
        let text = |key: &str| record[key].as_str().unwrap_or_default().to_owned();
        let detail = record["copilotActivityUserDetailsByPeriod"]
            .as_array()
            .and_then(|periods| {
                periods
                    .iter()
                    .find(|period| period["reportPeriod"].as_u64() == Some(period_days))
            })
            .cloned()
            .unwrap_or(Value::Null);
        let count = |key: &str| detail[key].as_u64().unwrap_or_default();
        let last_activity_by_app = record
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(key, value)| {
                let app = key.strip_suffix(LAST_ACTIVITY_SUFFIX)?;
                let date = value.as_str()?;
                (!app.is_empty() && !date.is_empty()).then(|| (app.to_owned(), date.to_owned()))
            })
            .collect();
        let last_activity = text("lastActivityDate");
        Self {
            display_name: text("displayName"),
            user_principal_name: text("userPrincipalName"),
            company_name: None,
            department: None,
            last_activity_date: (!last_activity.is_empty()).then_some(last_activity),
            active_days: count("activeUsageDaysAllApps"),
            prompts: count("promptsSubmittedAllApps"),
            prompts_chat_work: count("promptsSubmittedBusinessChatWork"),
            prompts_chat_web: count("promptsSubmittedBusinessChatWeb"),
            last_activity_by_app,
            report_refresh_date: text("reportRefreshDate"),
        }
    }

    /// A concealed report replaces each address with an opaque code, so an
    /// address without `@` cannot be matched to the directory.
    pub fn is_concealed(&self) -> bool {
        !self.user_principal_name.contains('@')
    }

    pub fn wrap_untrusted(&self, id: &str) -> Self {
        let wrap = |value: &str| format!("[UNTRUSTED:{id}]{value}[/UNTRUSTED:{id}]");
        Self {
            display_name: wrap(&self.display_name),
            company_name: self.company_name.as_deref().map(wrap),
            department: self.department.as_deref().map(wrap),
            ..self.clone()
        }
    }
}

/// One row of `reports copilot-usage --by-company`: how many people in the
/// report belong to a company, how many were active in the period, and their
/// prompts and active days.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompanyUsage {
    pub company: Option<String>,
    pub users: usize,
    pub active_users: usize,
    pub prompts: u64,
    pub active_days: u64,
}

impl CompanyUsage {
    /// Totals per company, most users first and ties by name, with the
    /// unnamed group after every named one of the same size. A person is
    /// active when they used Copilot on at least one day in the period.
    pub fn tally(rows: &[CopilotUsage]) -> Vec<Self> {
        let mut totals: BTreeMap<Option<String>, Self> = BTreeMap::new();
        for row in rows {
            let company = row
                .company_name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            let total = totals.entry(company.clone()).or_insert(Self {
                company,
                users: 0,
                active_users: 0,
                prompts: 0,
                active_days: 0,
            });
            total.users += 1;
            total.active_users += usize::from(row.active_days > 0);
            total.prompts += row.prompts;
            total.active_days += row.active_days;
        }
        let mut rows: Vec<Self> = totals.into_values().collect();
        rows.sort_by(|left, right| {
            right
                .users
                .cmp(&left.users)
                .then_with(|| left.company.is_none().cmp(&right.company.is_none()))
                .then_with(|| left.company.cmp(&right.company))
        });
        rows
    }

    pub fn wrap_untrusted(&self, id: &str) -> Self {
        Self {
            company: self
                .company
                .as_ref()
                .map(|name| format!("[UNTRUSTED:{id}]{name}[/UNTRUSTED:{id}]")),
            ..self.clone()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Page<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

impl User {
    pub fn created_date(&self) -> &str {
        self.created_date_time
            .get(..10)
            .unwrap_or(&self.created_date_time)
    }

    pub fn wrap_untrusted(&self, id: &str) -> Self {
        let mut out = self.clone();
        for value in [
            &mut out.display_name,
            &mut out.given_name,
            &mut out.surname,
            &mut out.job_title,
            &mut out.department,
            &mut out.company_name,
            &mut out.office_location,
        ] {
            if !value.is_empty() {
                *value = format!("[UNTRUSTED:{id}]{value}[/UNTRUSTED:{id}]");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_null_user_fields_deserialize_to_defaults() {
        let json = r#"{
            "id": null,
            "displayName": null,
            "givenName": null,
            "surname": null,
            "mail": null,
            "userPrincipalName": null,
            "jobTitle": null,
            "department": null,
            "companyName": null,
            "officeLocation": null,
            "employeeId": null,
            "employeeType": null,
            "accountEnabled": null,
            "createdDateTime": null,
            "proxyAddresses": null,
            "otherMails": null,
            "mailNickname": null,
            "onPremisesSamAccountName": null,
            "usageLocation": null
        }"#;

        let user: User = serde_json::from_str(json).unwrap();

        assert_eq!(user, User::default());
    }

    fn group(id: &str, name: &str, mail: Option<bool>, security: Option<bool>) -> Group {
        Group {
            id: id.into(),
            display_name: name.into(),
            mail_enabled: mail,
            security_enabled: security,
            ..Group::default()
        }
    }

    #[test]
    fn groups_are_classified_by_type_and_enabled_flags() {
        let cases = [
            (Some(true), Some(false), GroupKind::Distribution),
            (Some(true), Some(true), GroupKind::MailSecurity),
            (Some(false), Some(true), GroupKind::Security),
            (Some(false), Some(false), GroupKind::Other),
            (None, None, GroupKind::Other),
        ];
        for (mail, security, expected) in cases {
            assert_eq!(group("g", "G", mail, security).kind(), expected);
        }
        let unified = Group {
            group_types: vec!["unified".into()],
            ..group("g", "G", Some(true), Some(false))
        };
        assert_eq!(unified.kind(), GroupKind::M365);
    }

    #[test]
    fn only_a_synchronised_group_is_reported_as_on_premises() {
        let mut synced = group("g", "G", Some(true), Some(false));
        assert_eq!(synced.source(), GroupSource::Cloud);
        synced.on_premises_sync_enabled = Some(false);
        assert_eq!(synced.source(), GroupSource::Cloud);
        synced.on_premises_sync_enabled = Some(true);
        assert_eq!(synced.source(), GroupSource::OnPremises);
    }

    #[test]
    fn memberships_mark_direct_groups_and_list_them_first() {
        let transitive = vec![
            group("a", "alpha nested", Some(true), Some(false)),
            group("b", "Beta direct", Some(true), Some(false)),
            group("c", "charlie direct", Some(false), Some(true)),
        ];
        let direct = vec![
            group("c", "charlie direct", Some(false), Some(true)),
            group("b", "Beta direct", Some(true), Some(false)),
        ];
        let rows = GroupMembership::from_lists(transitive, &direct);
        let summary: Vec<_> = rows
            .iter()
            .map(|row| (row.id.as_str(), row.membership))
            .collect();
        assert_eq!(
            summary,
            [
                ("b", Membership::Direct),
                ("c", Membership::Direct),
                ("a", Membership::Nested),
            ]
        );
    }

    #[test]
    fn a_direct_group_missing_from_the_transitive_list_is_still_shown_once() {
        let direct = vec![group("d", "Direct only", Some(true), Some(false))];
        let rows = GroupMembership::from_lists(Vec::new(), &direct);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].membership, Membership::Direct);
    }

    fn employee(company: &str) -> User {
        User {
            company_name: company.into(),
            ..User::default()
        }
    }

    #[test]
    fn copilot_usage_reads_the_requested_period_only() {
        let record = serde_json::json!({
            "userPrincipalName": "a@example.test",
            "lastActivityDate": "",
            "copilotActivityUserDetailsByPeriod": [
                {"reportPeriod": 7, "promptsSubmittedAllApps": 3, "activeUsageDaysAllApps": 1},
                {"reportPeriod": 28, "promptsSubmittedAllApps": 9, "activeUsageDaysAllApps": 4}
            ]
        });
        let row = CopilotUsage::from_report(&record, 28);
        assert_eq!((row.prompts, row.active_days), (9, 4));
        assert_eq!(row.last_activity_date, None);
        let missing = CopilotUsage::from_report(&record, 90);
        assert_eq!((missing.prompts, missing.active_days), (0, 0));
    }

    #[test]
    fn company_tally_merges_blank_names_and_keeps_case_apart() {
        let users = [
            employee("Example"),
            employee(" Example "),
            employee("example"),
            employee(""),
            employee("   "),
            employee("Other"),
        ];
        let rows: Vec<_> = CompanyCount::tally(&users)
            .into_iter()
            .map(|row| (row.company, row.holders))
            .collect();
        assert_eq!(
            rows,
            [
                (Some("Example".to_owned()), 2),
                (None, 2),
                (Some("Other".to_owned()), 1),
                (Some("example".to_owned()), 1),
            ]
        );
        assert!(CompanyCount::tally(&[]).is_empty());
    }

    #[test]
    fn membership_json_uses_kebab_case_labels() {
        let rows =
            GroupMembership::from_lists(vec![group("e", "Example", Some(true), Some(true))], &[]);
        let value = serde_json::to_value(&rows[0]).unwrap();
        assert_eq!(value["kind"], "mail-security");
        assert_eq!(value["source"], "cloud");
        assert_eq!(value["membership"], "nested");
        assert!(value.get("mail").is_none());
    }
}
