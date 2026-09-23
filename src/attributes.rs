use crate::error::{EntraError, Result};

#[derive(Debug, Clone, Copy)]
pub struct AttributeGroup {
    pub name: &'static str,
    pub description: &'static str,
    pub properties: &'static [&'static str],
}

pub const SIGN_IN_ACTIVITY_GROUP: AttributeGroup = AttributeGroup {
    name: "signinactivity",
    description: "Last sign-in, requiring AuditLog.Read.All and a P1/P2 licence",
    properties: &["signInActivity"],
};

pub const ATTRIBUTE_GROUPS: &[AttributeGroup] = &[
    AttributeGroup {
        name: "identity",
        description: "Who the account is and how it is named",
        properties: &[
            "id", "displayName", "givenName", "surname", "mailNickname",
            "userPrincipalName", "userType", "preferredLanguage", "securityIdentifier",
        ],
    },
    AttributeGroup {
        name: "addresses",
        description: "Every email address and telephone number on the record",
        properties: &[
            "mail", "otherMails", "proxyAddresses", "imAddresses", "businessPhones",
            "mobilePhone", "faxNumber",
        ],
    },
    AttributeGroup {
        name: "organisation",
        description: "Where the person sits in the business",
        properties: &[
            "jobTitle", "department", "companyName", "employeeId", "employeeType",
            "employeeHireDate", "employeeLeaveDateTime", "employeeOrgData", "officeLocation",
        ],
    },
    AttributeGroup {
        name: "location",
        description: "Physical and licensing location",
        properties: &[
            "streetAddress", "city", "state", "postalCode", "country", "usageLocation",
            "preferredDataLocation",
        ],
    },
    AttributeGroup {
        name: "account",
        description: "Account lifecycle and state",
        properties: &[
            "accountEnabled", "createdDateTime", "deletedDateTime", "creationType",
            "externalUserState", "externalUserStateChangeDateTime", "isResourceAccount",
            "showInAddressList", "ageGroup", "consentProvidedForMinor",
            "legalAgeGroupClassification",
        ],
    },
    AttributeGroup {
        name: "credentials",
        description: "Password and session state, useful for offboarding checks",
        properties: &[
            "lastPasswordChangeDateTime", "passwordPolicies",
            "refreshTokensValidFromDateTime", "signInSessionsValidFromDateTime",
        ],
    },
    AttributeGroup {
        name: "onpremises",
        description: "Values synchronised from on-premises Active Directory, which is where the manager data is supposed to originate",
        properties: &[
            "onPremisesSamAccountName", "onPremisesUserPrincipalName",
            "onPremisesDomainName", "onPremisesDistinguishedName",
            "onPremisesSecurityIdentifier", "onPremisesSyncEnabled",
            "onPremisesLastSyncDateTime", "onPremisesImmutableId",
            "onPremisesExtensionAttributes", "onPremisesProvisioningErrors",
        ],
    },
];

pub fn all_properties() -> Vec<&'static str> {
    ATTRIBUTE_GROUPS
        .iter()
        .flat_map(|group| group.properties.iter().copied())
        .collect()
}

pub fn group_properties(names: &[String]) -> Result<Vec<&'static str>> {
    let mut properties = Vec::new();
    let mut unknown = Vec::new();
    for raw in names {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let found = ATTRIBUTE_GROUPS
            .iter()
            .chain(std::iter::once(&SIGN_IN_ACTIVITY_GROUP))
            .find(|group| group.name == name);
        if let Some(group) = found {
            properties.extend_from_slice(group.properties);
        } else {
            unknown.push(raw.as_str());
        }
    }
    if unknown.is_empty() {
        return Ok(properties);
    }
    let mut valid: Vec<_> = ATTRIBUTE_GROUPS.iter().map(|group| group.name).collect();
    valid.push(SIGN_IN_ACTIVITY_GROUP.name);
    valid.sort_unstable();
    Err(EntraError::message(format!(
        "unknown attribute group(s): {} (available: {})",
        unknown.join(", "),
        valid.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_properties_excludes_navigation_properties() {
        let properties = all_properties();
        assert!(properties.contains(&"proxyAddresses"));
        for navigation in ["manager", "directReports", "memberOf"] {
            assert!(!properties.contains(&navigation));
        }
    }

    #[test]
    fn unknown_groups_name_the_valid_choices() {
        let error = group_properties(&["identitty".into()]).unwrap_err();
        assert!(error.to_string().contains("identity"));
        assert!(error.to_string().contains("identitty"));
    }
}
