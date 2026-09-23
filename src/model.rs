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
}
