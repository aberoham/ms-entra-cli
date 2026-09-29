#!/usr/bin/env bash
set -euo pipefail

# Creates a single-tenant public-client app registration for entra, named
# "Entra CLI (read-only directory lookups)" unless APP_NAME says otherwise,
# with its service principal. It adds the delegated Graph permissions, grants
# admin consent and restricts who may sign in through it.
#
# The permission that matters here is delegated User.Read.All. It is what makes
# a manager lookup possible and it covers the whole directory, so this script
# refuses to run without an assignment unless ALLOW_ALL_TENANT_USERS=1 is set
# deliberately. Consent granted for "all users in your organisation" on an app
# nobody is assigned to is a far wider grant than the task needs.
# See docs/auth.md for the walkthrough.
#
# Usage:
#   TENANT_ID=<tenant-guid> ./contrib/create-entra-app.sh
#
# TENANT_ID and CLIENT_ID fall back to ENTRA_TENANT_ID and ENTRA_CLIENT_ID,
# then to the registration saved by the last `entra auth login` (for
# ENTRA_ACCOUNT, else the default account; reading it needs jq). A known
# CLIENT_ID updates that registration in place rather than looking one up by
# display name, so re-running to add a permission never creates a second app.
# Re-running against an app that already requires assignment needs no new
# assignment variables.
#
# Optional environment overrides:
#   CLIENT_ID        application (client) ID of an existing registration to update
#   APP_NAME         display name             (default: "Entra CLI (read-only directory lookups)")
#   SCOPES           space-separated scopes   (default includes AuditLog.Read.All and
#                    User-LifeCycleInfo.Read.All; see docs/auth.md)
#   GROUP_OBJECT_ID  group object ID to assign
#   ASSIGN_USERS     space-separated user UPNs (or object IDs) to assign
#   ALLOW_ALL_TENANT_USERS=1 to intentionally allow any tenant user to sign in
# Providing either assignment variable also sets appRoleAssignmentRequired=true,
# so ONLY the assigned principals can sign in through the app. Without an
# assignment, ALLOW_ALL_TENANT_USERS=1 is required as an explicit opt-in.
#
# Finding IDs:
#   your own UPN:      az ad signed-in-user show --query userPrincipalName -o tsv
#   a group's ID:      az ad group show --group "<display name>" --query id -o tsv
#   browse groups:     az ad group list --query "[].{name:displayName,id:id}" -o table
#
# Requires: az CLI, logged in (az login --tenant $TENANT_ID) as a user who can
# create applications; admin consent additionally needs Cloud
# Application Administrator, Application Administrator or a higher role.

# saved_registration prints the client_id or tenant_id that `entra auth login`
# saved for ENTRA_ACCOUNT, else for the default account, or nothing.
saved_registration() {
  local dir file
  if [ -n "${ENTRA_CONFIG_DIR:-}" ]; then
    dir="$ENTRA_CONFIG_DIR"
  elif [ "$(uname -s)" = Darwin ]; then
    dir="$HOME/Library/Application Support/entra"
  else
    dir="${XDG_CONFIG_HOME:-$HOME/.config}/entra"
  fi
  file="$dir/config.json"
  [ -f "$file" ] && command -v jq >/dev/null 2>&1 || return 0
  jq -r --arg field "$1" --arg account "${ENTRA_ACCOUNT:-}" '
    (if $account != "" then $account else (.default_account // "") end) as $who
    | [(.clients // {}) | to_entries[]
       | select((.key | ascii_downcase) == ($who | ascii_downcase))
       | .value[$field] // empty][0] // empty' "$file"
}

TENANT_ID="${TENANT_ID:-${ENTRA_TENANT_ID:-$(saved_registration tenant_id)}}"
if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" = common ]; then
  echo "error: no directory (tenant) ID." >&2
  echo "Set TENANT_ID or ENTRA_TENANT_ID, or sign in once with entra auth login --tenant-id." >&2
  exit 1
fi
CLIENT_ID="${CLIENT_ID:-${ENTRA_CLIENT_ID:-$(saved_registration client_id)}}"
APP_NAME="${APP_NAME:-Entra CLI (read-only directory lookups)}"
SCOPES="${SCOPES:-offline_access User.Read User.ReadBasic.All User.Read.All AuditLog.Read.All User-LifeCycleInfo.Read.All}"
GRAPH_SP="00000003-0000-0000-c000-000000000000"
echo "==> Tenant: $TENANT_ID"

current_tenant=$(az account show --query tenantId -o tsv 2>/dev/null || true)
if [ "$current_tenant" != "$TENANT_ID" ]; then
  echo "error: az is logged into tenant '${current_tenant:-none}', expected '$TENANT_ID'." >&2
  echo "Run: az login --tenant $TENANT_ID" >&2
  exit 1
fi

# An existing registration that already requires assignment is restricted, so
# a re-run that only adds permissions needs no new assignment.
already_restricted=false
if [ -n "$CLIENT_ID" ]; then
  if ! az ad app show --id "$CLIENT_ID" --query appId -o tsv >/dev/null 2>&1; then
    echo "error: no app registration '$CLIENT_ID' in tenant $TENANT_ID." >&2
    echo "Check CLIENT_ID / ENTRA_CLIENT_ID, or unset both to create a new registration." >&2
    exit 1
  fi
  required=$(az ad sp show --id "$CLIENT_ID" --query appRoleAssignmentRequired -o tsv 2>/dev/null || true)
  [ "$required" = true ] && already_restricted=true
fi

if [ -z "${GROUP_OBJECT_ID:-}" ] &&
  [ -z "${ASSIGN_USERS:-}" ] &&
  [ "$already_restricted" != true ] &&
  [ "${ALLOW_ALL_TENANT_USERS:-}" != "1" ]; then
  echo "error: no user or group assignment configured." >&2
  echo "Set GROUP_OBJECT_ID or ASSIGN_USERS to restrict access." >&2
  echo "To intentionally allow every tenant user, set ALLOW_ALL_TENANT_USERS=1." >&2
  exit 1
fi

if [ -n "$CLIENT_ID" ]; then
  echo "==> Updating existing app registration $CLIENT_ID"
  APP_ID="$CLIENT_ID"
else
  echo "==> Creating app registration '$APP_NAME' (single-tenant public client)"
  APP_ID=$(az ad app create \
    --display-name "$APP_NAME" \
    --sign-in-audience AzureADMyOrg \
    --public-client-redirect-uris "http://localhost/callback" \
    --is-fallback-public-client true \
    --query appId -o tsv)
fi
echo "    appId: $APP_ID"

# `az ad app permission add` appends without checking for duplicates, so a
# re-run adds only the delegated permissions the registration does not hold.
existing=$(az ad app show --id "$APP_ID" \
  --query "requiredResourceAccess[?resourceAppId=='$GRAPH_SP'].resourceAccess[] | [?type=='Scope'].id" \
  -o tsv 2>/dev/null || true)

echo "==> Resolving Graph delegated-permission IDs for: $SCOPES"
perms=()
for scope in $SCOPES; do
  perm_id=$(az ad sp show --id "$GRAPH_SP" \
    --query "oauth2PermissionScopes[?value=='$scope'].id | [0]" -o tsv)
  if [ -z "$perm_id" ] || [ "$perm_id" = "None" ]; then
    echo "error: could not resolve Graph delegated scope '$scope'" >&2
    exit 1
  fi
  if printf '%s\n' "$existing" | grep -qixF -- "$perm_id"; then
    echo "    $scope = $perm_id (already present)"
    continue
  fi
  echo "    $scope = $perm_id"
  perms+=("$perm_id=Scope")
done

if [ "${#perms[@]}" -gt 0 ]; then
  echo "==> Adding ${#perms[@]} API permission(s) to the app registration"
  az ad app permission add --id "$APP_ID" --api "$GRAPH_SP" --api-permissions "${perms[@]}" \
    --only-show-errors
else
  echo "==> Every requested API permission is already present"
fi

echo "==> Creating service principal (Enterprise application)"
# Re-running this script is a normal thing to do; adding a second person to
# the assignment list is the obvious reason. Every step here therefore has to
# tolerate the object already existing, and `az ad sp create` fails outright
# when the service principal is already there.
SP_ID=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv 2>/dev/null || true)
if [ -n "$SP_ID" ] && [ "$SP_ID" != "None" ]; then
  echo "    already exists, reusing"
else
  SP_ID=$(az ad sp create --id "$APP_ID" --query id -o tsv)
fi
echo "    servicePrincipal objectId: $SP_ID"

restrict=false
if [ -n "${GROUP_OBJECT_ID:-}" ] || [ -n "${ASSIGN_USERS:-}" ]; then
  restrict=true
fi

# Require assignment before granting consent, so that an interrupted run can
# never leave a consented app that every tenant user may sign in to.
if [ "$restrict" = true ]; then
  echo "==> Requiring assignment (only assigned principals may use the app)"
  az ad sp update --id "$APP_ID" --set appRoleAssignmentRequired=true
fi

echo "==> Granting admin consent (requires Cloud Application Administrator or higher)"
# Directory writes propagate asynchronously; retry briefly before failing.
for attempt in 1 2 3 4 5; do
  if az ad app permission admin-consent --id "$APP_ID" --only-show-errors; then
    break
  fi
  if [ "$attempt" = 5 ]; then
    echo "error: admin consent failed after $attempt attempts." >&2
    echo "Retry manually: az ad app permission admin-consent --id $APP_ID" >&2
    exit 1
  fi
  echo "    not ready yet (attempt $attempt), retrying in 10s..."
  sleep 10
done

# assign_principal grants a user or group the default access role on the app.
# An already-assigned principal is reported and skipped rather than treated as
# a failure, so the script stays safe to re-run.
assign_principal() {
  local out
  if out=$(az rest --method POST \
    --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" \
    --body "{\"principalId\":\"$1\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"00000000-0000-0000-0000-000000000000\"}" \
    --only-show-errors 2>&1); then
    return 0
  fi
  if printf '%s' "$out" | grep -qiE "already exists|Permission being assigned already exists"; then
    echo "      already assigned, skipping"
    return 0
  fi
  echo "$out" >&2
  return 1
}

assign_failures=0

if [ "$restrict" = true ]; then
  echo "==> Assigning principals"
  if [ -n "${GROUP_OBJECT_ID:-}" ]; then
    echo "    assigning group $GROUP_OBJECT_ID"
    assign_principal "$GROUP_OBJECT_ID"
  fi
  for upn in ${ASSIGN_USERS:-}; do
    # A mistyped address must not take the whole run down with it, and under
    # `set -e` an unresolvable user would. Many directories give people a
    # sign-in name on one domain and mail on another, so getting this wrong is
    # easy; say which name failed and carry on with the rest.
    user_id=$(az ad user show --id "$upn" --query id -o tsv 2>/dev/null || true)
    if [ -z "$user_id" ] || [ "$user_id" = "None" ]; then
      echo "    WARNING: no directory user matches '$upn'; not assigned" >&2
      echo "             check the sign-in name, which may differ from their email" >&2
      assign_failures=$((assign_failures + 1))
      continue
    fi
    echo "    assigning user $upn ($user_id)"
    assign_principal "$user_id"
  done
elif [ "$already_restricted" = true ]; then
  echo "==> No new assignment given; existing assignments are unchanged and still required."
else
  echo "==> No assignment given; 'Assignment required' was left unchanged."
  echo "    On a new app that means any tenant user may sign in through it."
  echo "    Restrict later with GROUP_OBJECT_ID=<guid> or ASSIGN_USERS=\"a@x.com b@x.com\","
  echo "    or in one line per user:"
  echo "    az ad sp update --id $APP_ID --set appRoleAssignmentRequired=true"
fi

if [ "$assign_failures" -gt 0 ]; then
  echo
  echo "WARNING: $assign_failures principal(s) could not be assigned; see above." >&2
  echo "         Re-run with a corrected ASSIGN_USERS; this script is safe to repeat." >&2
fi

echo
echo "==> Done. Verify consent:"
echo "    az ad app permission list-grants --id $APP_ID --show-resource-name -o table"
echo
echo "==> Log in with:"
echo "    entra auth login --browser --directory --client-id $APP_ID --tenant-id $TENANT_ID"
