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
