#!/bin/bash
# Copyright (c) 2026 GitOps Manager, S.L. All rights reserved.
# =============================================================================
# create-headlamp-app.sh
#
# Creates the two Entra applications Headlamp needs and puts their credentials
# in whichever secret stores this installation uses:
#
#   headlamp                          the OIDC client that signs users in
#   gitopsmanager-headlamp-patch-url  owns the above; patches its redirect URIs
#
# Talks to Entra, Key Vault and Secrets Manager directly. The server is told
# only metadata -- application IDs and credential expiry dates -- so no customer
# secret ever reaches the EKS Manager database.
#
# Safe to re-run. See "Secret resolution" below for why, and for the one case
# where it deliberately refuses.
# =============================================================================

set -euo pipefail

# --- Arguments ---------------------------------------------------------------
KEY_VAULT_NAME=""
ENABLE_AWS="false"
HEADLAMP_APP_ID_OVERRIDE=""
TRUST=""

usage() {
  cat <<'USAGE'
Usage:
  create-headlamp-app.sh --key-vault <name>                # Azure
  create-headlamp-app.sh --enable-aws                      # AWS
  create-headlamp-app.sh --key-vault <name> --enable-aws   # both

  --key-vault <name>    Store the credentials in this Key Vault.
  --enable-aws          Store them in AWS Secrets Manager.

  --headlamp-id <appId> Name the Headlamp application directly instead of
                        searching by display name. Use when more than one
                        application shares the name.
  --trust azure|aws     Resolve a disagreement between the two stores that
                        cannot be settled from credential hints.

At least one store is required. The Entra work happens either way -- `az login`
needs only a tenant, so an EKS-only installation does not need an Azure
subscription.

Everything else comes from the environment supplied by Settings -> Terraform
tile -> Pipeline credentials.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key-vault)
      KEY_VAULT_NAME="${2:-}"
      if [[ -z "$KEY_VAULT_NAME" ]]; then echo "ERROR: --key-vault needs a value." >&2; exit 1; fi
      shift 2 ;;
    --enable-aws) ENABLE_AWS="true"; shift ;;
    --headlamp-id)
      HEADLAMP_APP_ID_OVERRIDE="${2:-}"
      if [[ -z "$HEADLAMP_APP_ID_OVERRIDE" ]]; then echo "ERROR: --headlamp-id needs a value." >&2; exit 1; fi
      shift 2 ;;
    --trust)
      TRUST="${2:-}"
      case "$TRUST" in azure|aws) ;; *) echo "ERROR: --trust must be azure or aws." >&2; exit 1 ;; esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "$KEY_VAULT_NAME" && "$ENABLE_AWS" != "true" ]]; then
  echo "ERROR: nothing to do -- pass --key-vault, --enable-aws, or both." >&2
  usage >&2
  exit 1
fi

# --- Config ------------------------------------------------------------------
APP_NAME="headlamp"
PATCH_APP_NAME="gitopsmanager-headlamp-patch-url"

KV_OIDC_NAME="global-headlamp-oidc"
KV_PATCH_NAME="global-headlamp-patch-url"

SM_OIDC_NAME="/EKSManagerBootstrap/headlamp-oidc"
SM_PATCH_NAME="/EKSManagerBootstrap/headlamp-patch-url"

K8S_SECRET_NAME="headlamp-oidc"
K8S_NAMESPACE="headlamp"
SECRET_YEARS_VALID=2

# Fixed Microsoft identifier used as the access-token audience. Not tenant
# specific and not a secret.
VALIDATOR_CLIENT_ID="6dae42f8-4368-4678-94ff-3960e28e3630"

# Two names, because the stores disagree about what a name may contain and
# because the AWS one has to sit where a scoped policy can see it. A probe
# outside /EKSManagerBootstrap/headlamp-* would fail preflight on an operator
# whose permissions are correct -- reporting a write problem that is really a
# naming one.
KV_PROBE_NAME="gitopsmanager-preflight-probe"
SM_PROBE_NAME="/EKSManagerBootstrap/headlamp-preflight-probe"

# --- Helpers -----------------------------------------------------------------
info()    { echo -e "\n\033[1;34m[INFO]\033[0m $*"; }
success() { echo -e "\033[1;32m[OK]\033[0m $*"; }
warn()    { echo -e "\033[1;33m[WARN]\033[0m $*"; }
error()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

# =============================================================================
# PREFLIGHT
#
# All of this runs before anything is created. The ordering is the point, not
# politeness: Entra reveals a client secret exactly once, so minting one and
# then failing to store it leaves an application holding a credential nobody
# has. That is the only unrecoverable failure here, and proving the writes
# first avoids it entirely.
# =============================================================================

# -----------------------------------------------------------------------------
# Sign-in gate
#
# Every cloud this run touches is proven here, and all failures are reported in
# one message. Checking each where it is first needed meant an operator signed
# in to neither fixed Azure, re-ran, sat through the Entra and API preflights,
# and only then learned AWS was missing too -- two round trips for one setup
# problem. --key-vault needs Azure; --enable-aws needs AWS; Entra is always
# needed.
# -----------------------------------------------------------------------------
info "Preflight: sign-in"

SIGNIN_ERRORS=""
add_signin_error() { SIGNIN_ERRORS="${SIGNIN_ERRORS}${SIGNIN_ERRORS:+

}$1"; }

TENANT_ID=$(az account show --query "tenantId" -o tsv 2>/dev/null || true)
if [[ -n "$TENANT_ID" ]]; then
  success "Azure: tenant $TENANT_ID."
else
  add_signin_error "Azure -- not signed in. The Entra applications live here, so this is
       always required, with or without --enable-aws.

           az login
           az login --allow-no-subscriptions    # tenant with no subscription"
fi

if [[ "$ENABLE_AWS" == "true" ]]; then
  # REGION and SHARED_SERVICES_ACCOUNT_ID come from the same Settings ->
  # Terraform environment block as the EKSMANAGER_* credentials, so both are
  # required rather than best-effort. This writes to Secrets Manager and uses
  # EKSManagerCMK, both of which live in the SHARED SERVICES account, and
  # nothing here assumes a role to get there -- the session has to be the right
  # one to begin with. Treating the expected account as optional made the check
  # skip itself in exactly the case it exists to catch.
  AWS_REGION_RESOLVED="${REGION:-}"
  EXPECTED_ACCOUNT="${SHARED_SERVICES_ACCOUNT_ID:-}"

  UNSET_VARS=""
  [[ -z "$AWS_REGION_RESOLVED" ]] && UNSET_VARS="REGION"
  [[ -z "$EXPECTED_ACCOUNT"    ]] && UNSET_VARS="${UNSET_VARS}${UNSET_VARS:+, }SHARED_SERVICES_ACCOUNT_ID"

  if [[ -n "$UNSET_VARS" ]]; then
    add_signin_error "AWS -- not set: ${UNSET_VARS}.

           Paste the environment block from Settings -> Terraform tile."
  else
    # Every aws call passes --region explicitly; this covers the CLI's own need
    # for one on calls that do not, sts included.
    export AWS_REGION="$AWS_REGION_RESOLVED"

    AWS_ACCOUNT=$(aws sts get-caller-identity --query "Account" -o text 2>/dev/null || true)
    if [[ -z "$AWS_ACCOUNT" ]]; then
      # On a machine with named profiles this is a selection problem, not a
      # sign-in problem, and "sign in and retry" sends the operator looking in
      # the wrong place. Name what is configured.
      AWS_PROFILES=$(aws configure list-profiles 2>/dev/null | paste -sd', ' - || true)
      if [[ -n "$AWS_PROFILES" ]]; then
        PROFILE_HINT="           Configured profiles: ${AWS_PROFILES}

           export AWS_PROFILE=<profile>
           aws sso login --profile <profile>    # if the session has lapsed"
      else
        PROFILE_HINT="           No named profiles are configured."
      fi
      add_signin_error "AWS -- no usable credentials. --enable-aws was passed, so shared
       services account ${EXPECTED_ACCOUNT} is required.

${PROFILE_HINT}"
    elif [[ "$EXPECTED_ACCOUNT" != "$AWS_ACCOUNT" ]]; then
      add_signin_error "AWS -- wrong account.

           Signed in to : ${AWS_ACCOUNT}
           Expected     : ${EXPECTED_ACCOUNT}  (shared services)

           This script does not assume a role to get there. Worth knowing:
           setup-pipeline.sh runs from the MANAGEMENT account and this one
           does not, which is an easy thing to carry over out of habit."
    else
      success "AWS: shared services account $AWS_ACCOUNT in $AWS_REGION_RESOLVED."
    fi
  fi
fi

if [[ -n "$SIGNIN_ERRORS" ]]; then
  error "Not signed in to everything this run needs.

${SIGNIN_ERRORS}

       Fix all of the above, then re-run."
fi

info "Preflight: Entra"
# 'az ad app list' has no --top. A filter that cannot match anything is the
# cheapest call that still exercises the /applications read the rest of this
# script depends on, and it returns an empty list rather than the whole
# directory.
az ad app list --filter "appId eq '00000000-0000-0000-0000-000000000000'" \
  --query "[0].appId" -o tsv >/dev/null 2>&1 \
  || error "Cannot read applications in tenant $TENANT_ID. Check your directory role."
success "Tenant $TENANT_ID, directory readable."

# Create rights cannot be proven without creating something. Left to fail
# clearly at the point of use.

info "Preflight: EKS Manager API"
for v in EKSMANAGER_API_URL EKSMANAGER_COGNITO_URL EKSMANAGER_CLIENT_ID EKSMANAGER_CLIENT_SECRET; do
  if [[ -z "${!v:-}" ]]; then
    error "$v is not set. Paste the credentials block from Settings -> Terraform tile."
  fi
done
API_TOKEN=$(curl -fsSL -X POST "${EKSMANAGER_COGNITO_URL}/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${EKSMANAGER_CLIENT_ID}&client_secret=${EKSMANAGER_CLIENT_SECRET}" \
  2>/dev/null | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4 || true)
if [[ -z "$API_TOKEN" ]]; then
  error "Could not obtain an M2M token. Check the pipeline credentials and that this host is allowlisted."
fi
success "API reachable, token obtained."

if [[ -n "$KEY_VAULT_NAME" ]]; then
  info "Preflight: Key Vault '$KEY_VAULT_NAME'"
  az keyvault show --name "$KEY_VAULT_NAME" --query "name" -o tsv >/dev/null 2>&1 \
    || error "Key Vault '$KEY_VAULT_NAME' not found or not accessible."

  # Prove write, do not assume it.
  az keyvault secret set --vault-name "$KEY_VAULT_NAME" --name "$KV_PROBE_NAME" \
    --value "probe" --output none 2>/dev/null \
    || error "Cannot write to Key Vault '$KEY_VAULT_NAME'. Grant Key Vault Secrets Officer and retry."
  az keyvault secret delete --vault-name "$KEY_VAULT_NAME" --name "$KV_PROBE_NAME" --output none 2>/dev/null || true
  success "Key Vault writable."
fi

if [[ "$ENABLE_AWS" == "true" ]]; then
  info "Preflight: AWS Secrets Manager"

  # Credentials, region, and the account match are all settled by the sign-in
  # gate above. What is left is the one thing a successful sts call does not
  # prove: that this identity can actually write.
  #
  # Proves the write path and kms:GenerateDataKey on EKSManagerCMK end to end.
  aws secretsmanager create-secret --name "$SM_PROBE_NAME" --secret-string "probe" \
    --region "$AWS_REGION_RESOLVED" >/dev/null 2>&1 \
    || aws secretsmanager put-secret-value --secret-id "$SM_PROBE_NAME" --secret-string "probe" \
         --region "$AWS_REGION_RESOLVED" >/dev/null 2>&1 \
    || error "Cannot write to Secrets Manager in $AWS_ACCOUNT / $AWS_REGION_RESOLVED (check secretsmanager and kms permissions)."
  aws secretsmanager delete-secret --secret-id "$SM_PROBE_NAME" --force-delete-without-recovery \
    --region "$AWS_REGION_RESOLVED" >/dev/null 2>&1 || true
  success "Secrets Manager writable in $AWS_ACCOUNT / $AWS_REGION_RESOLVED."
fi

# =============================================================================
# APPLICATIONS
# =============================================================================

# Entra does not enforce unique display names. Configuring the wrong application
# -- disabling assignment-required on something unrelated, granting it a Graph
# role -- is far worse than refusing, so ambiguity stops.
resolve_app() {
  local display_name="$1" override="$2" __out="$3"
  local ids count

  if [[ -n "$override" ]]; then
    ids=$(az ad app list --filter "appId eq '$override'" --query "[].appId" -o tsv 2>/dev/null || true)
    if [[ -z "$ids" ]]; then error "No application found with appId $override."; fi
    printf -v "$__out" '%s' "$override"
    return
  fi

  ids=$(az ad app list --display-name "$display_name" --query "[].appId" -o tsv 2>/dev/null || true)
  count=$(printf '%s' "$ids" | grep -c . || true)

  if [[ "$count" -gt 1 ]]; then
    error "More than one application is named '$display_name':
$(printf '%s' "$ids" | sed 's/^/         /')
       Re-run with --headlamp-id <appId> naming the one you mean."
  fi
  printf -v "$__out" '%s' "$ids"
}

ensure_app() {
  local display_name="$1" __out="$2" app_id="${3:-}"
  if [[ -n "$app_id" ]]; then
    warn "Application '$display_name' exists ($app_id). Reusing it."
  else
    info "Creating application '$display_name'..."
    app_id=$(az ad app create --display-name "$display_name" --query "appId" -o tsv)
    success "Created. App ID: $app_id"
  fi
  printf -v "$__out" '%s' "$app_id"
}

# The Entra portal's "Enterprise applications" list defaults to Application
# type = Enterprise Applications, which shows only service principals carrying
# this tag. One created by the CLI has no tags, so it is invisible there -- the
# administrator sees the app registration, finds nothing under Enterprise
# applications, and concludes the enterprise application was never created. It
# was; the list is filtered.
#
# Applied in ensure_sp so both service principals get it. The patcher is not a
# sign-in app and might look like it does not belong in that list, but it holds
# Application.ReadWrite.OwnedBy, and Enterprise applications -> Permissions is
# the only place that grant can be reviewed or revoked.
PORTAL_TAG="WindowsAzureActiveDirectoryIntegratedApp"

tag_sp_for_portal() {
  local sp_id="$1" existing_tags all_tags

  existing_tags=$(az ad sp show --id "$sp_id" \
    --query "join(',', not_null(tags, \`[]\`))" -o tsv 2>/dev/null || true)

  case ",${existing_tags}," in
    *",${PORTAL_TAG},"*) return 0 ;;   # already tagged, leave it alone
  esac

  # PATCH replaces tags wholesale, so carry forward any already present rather
  # than overwriting them.
  if [[ -n "$existing_tags" ]]; then
    all_tags="${existing_tags},${PORTAL_TAG}"
  else
    all_tags="${PORTAL_TAG}"
  fi

  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$sp_id" \
    --body "{\"tags\": [\"$(echo "$all_tags" | sed 's/,/","/g')\"]}"
  success "Tagged as an enterprise application so it appears in the portal list."
}

ensure_sp() {
  local app_id="$1" __out="$2" sp_id
  sp_id=$(az ad sp list --filter "appId eq '$app_id'" --query "[0].id" -o tsv 2>/dev/null || true)
  if [[ -z "$sp_id" || "$sp_id" == "None" ]]; then
    sp_id=$(az ad sp create --id "$app_id" --query "id" -o tsv)
    success "Service principal created: $sp_id"
  fi
  tag_sp_for_portal "$sp_id"
  printf -v "$__out" '%s' "$sp_id"
}

info "Resolving '$APP_NAME'"
resolve_app "$APP_NAME" "$HEADLAMP_APP_ID_OVERRIDE" FOUND_ID
ensure_app  "$APP_NAME" APP_ID "$FOUND_ID"
ensure_sp   "$APP_ID" SP_OBJECT_ID
APP_OBJECT_ID=$(az ad app show --id "$APP_ID" --query "id" -o tsv)

# --- Sign-in configuration, each check-then-set ------------------------------
info "Asserting sign-in configuration on '$APP_NAME'"

if [[ "$(az ad sp show --id "$SP_OBJECT_ID" --query "appRoleAssignmentRequired" -o tsv 2>/dev/null || echo true)" != "false" ]]; then
  az ad sp update --id "$SP_OBJECT_ID" --set "appRoleAssignmentRequired=false"
  success "Assignment required disabled."
fi

if [[ "$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" \
        --query "api.requestedAccessTokenVersion" -o tsv 2>/dev/null || true)" != "2" ]]; then
  az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" \
    --body '{"api": {"requestedAccessTokenVersion": 2}}'
  success "Access token version set to v2.0."
fi

if [[ "$(az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" \
        --query "groupMembershipClaims" -o tsv 2>/dev/null || true)" != "SecurityGroup" ]]; then
  az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID" \
    --body '{"groupMembershipClaims": "SecurityGroup"}'
  success "groupMembershipClaims set to SecurityGroup."
fi

# --- The patcher -------------------------------------------------------------
# Separate from the Headlamp application deliberately. Adding a redirect URI IS
# the sensitive operation -- a callback pointing at someone else's
# infrastructure harvests authorization codes for every user who signs in. If
# Headlamp owned itself, one leaked secret would buy both.
info "Resolving '$PATCH_APP_NAME'"
resolve_app "$PATCH_APP_NAME" "" FOUND_PATCH
ensure_app  "$PATCH_APP_NAME" PATCH_APP_ID "$FOUND_PATCH"
ensure_sp   "$PATCH_APP_ID" PATCH_SP_ID

if [[ -z "$(az ad app owner list --id "$APP_ID" --query "[?id=='$PATCH_SP_ID'].id" -o tsv 2>/dev/null || true)" ]]; then
  az ad app owner add --id "$APP_ID" --owner-object-id "$PATCH_SP_ID"
  success "'$PATCH_APP_NAME' added as owner of '$APP_NAME'."
fi

# Application.ReadWrite.OwnedBy is the narrowest permission Graph offers -- there
# is no scope for "manage redirect URIs only". It confines the caller to
# applications it owns, plus any it creates.
GRAPH_SP=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "id" -o tsv)
OWNED_BY_ROLE_ID=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 \
  --query "appRoles[?value=='Application.ReadWrite.OwnedBy'].id" -o tsv)

if [[ -z "$(az rest --method GET \
      --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PATCH_SP_ID/appRoleAssignments" \
      --query "value[?appRoleId=='$OWNED_BY_ROLE_ID'].id" -o tsv 2>/dev/null || true)" ]]; then
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PATCH_SP_ID/appRoleAssignments" \
    --body "{\"principalId\":\"$PATCH_SP_ID\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$OWNED_BY_ROLE_ID\"}"
  success "Application.ReadWrite.OwnedBy granted."
fi

# =============================================================================
# SECRET RESOLUTION
#
#   1. Key Vault, if enabled and present
#   2. Secrets Manager, if enabled and present
#   3. Mint -- only if the application has no credentials at all
#   4. Otherwise stop
#
# Steps 1 and 2 do double duty: they make re-runs safe, and they copy an
# existing value from one cloud to the other.
# =============================================================================

kv_get()  { az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name "$1" --query "value" -o tsv 2>/dev/null || true; }
sm_get()  { aws secretsmanager get-secret-value --secret-id "$1" --region "$AWS_REGION_RESOLVED" --query "SecretString" --output text 2>/dev/null || true; }

json_field() { printf '%s' "$1" | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('$2',''))
except Exception: pass
"; }

manifest_secret() { printf '%s' "$1" | python3 -c "
import base64,json,sys
try: print(base64.b64decode(json.load(sys.stdin)['data']['clientSecret']).decode())
except Exception: pass
"; }

# Entra returns a hint -- the first characters -- for every credential on an
# application. The values themselves are never returned, but the hint is enough
# to tell a live credential from a stale stored copy.
secret_is_live() {
  local app_id="$1" value="$2"
  [[ -z "$value" ]] && return 1
  az ad app credential list --id "$app_id" --query "[].hint" -o tsv 2>/dev/null \
    | grep -qx "${value:0:3}"
}

# Resolves one application's secret across both stores. Sets RESOLVED_SECRET and
# RESOLVED_ORIGIN.
resolve_secret() {
  local app_id="$1" label="$2" azure_value="$3" aws_value="$4"
  RESOLVED_SECRET=""; RESOLVED_ORIGIN=""

  if [[ -n "$azure_value" && -n "$aws_value" && "$azure_value" != "$aws_value" ]]; then
    local az_live="no" aws_live="no"
    secret_is_live "$app_id" "$azure_value" && az_live="yes"
    secret_is_live "$app_id" "$aws_value"   && aws_live="yes"

    if [[ "$az_live" == "yes" && "$aws_live" == "no" ]]; then
      warn "$label: the Secrets Manager copy is no longer a live credential. Using Key Vault."
      RESOLVED_SECRET="$azure_value"; RESOLVED_ORIGIN="key vault"; return
    fi
    if [[ "$aws_live" == "yes" && "$az_live" == "no" ]]; then
      warn "$label: the Key Vault copy is no longer a live credential. Using Secrets Manager."
      RESOLVED_SECRET="$aws_value"; RESOLVED_ORIGIN="secrets manager"; return
    fi
    if [[ "$az_live" == "no" && "$aws_live" == "no" ]]; then
      error "$label: neither stored secret matches a live credential on the application.
       Both are stale. This needs a deliberate rotation."
    fi

    # Both live. Someone added a secret without updating both sides; nothing is
    # broken, but only the operator can say which should win.
    case "$TRUST" in
      azure) RESOLVED_SECRET="$azure_value"; RESOLVED_ORIGIN="key vault (--trust azure)" ;;
      aws)   RESOLVED_SECRET="$aws_value";   RESOLVED_ORIGIN="secrets manager (--trust aws)" ;;
      *) error "$label: Key Vault and Secrets Manager hold different secrets and both are live.
       Re-run with --trust azure or --trust aws, then remove the losing
       credential from the application so this does not recur." ;;
    esac
    return
  fi

  if [[ -n "$azure_value" ]]; then RESOLVED_SECRET="$azure_value"; RESOLVED_ORIGIN="key vault"; return; fi
  if [[ -n "$aws_value"   ]]; then RESOLVED_SECRET="$aws_value";   RESOLVED_ORIGIN="secrets manager"; return; fi

  # Fail closed. The 'credential reset' below is the one destructive call in
  # this script -- it removes every credential the application already has --
  # and this count is the only thing standing between it and a live app. A
  # trailing "|| echo 0" here turned a failed query (expired login, throttling,
  # a directory role that cannot read credentials) into "no credentials", which
  # would mint straight over the secret every running Headlamp is using.
  local cred_count
  if ! cred_count=$(az ad app credential list --id "$app_id" --query "length(@)" -o tsv 2>/dev/null) \
     || [[ -z "$cred_count" ]]; then
    error "$label: could not read the existing credentials from Entra, so minting
       is not safe -- it would remove any secret this application already holds.
       Resolve the access problem and re-run."
  fi

  if [[ "$cred_count" -gt 0 ]]; then
    error "$label already has ${cred_count} client secret(s), and Entra does not return one
       after creation. No enabled store holds it, so it cannot be recovered.

       Re-run including the store that does hold it, or rotate deliberately --
       a rotation invalidates the credential every running Headlamp is using
       and needs every cluster refreshed."
  fi

  info "Minting a client secret for $label (valid ${SECRET_YEARS_VALID} years)..."
  local end_date
  end_date=$(date -u -d "+${SECRET_YEARS_VALID} years" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
    || date -u -v+${SECRET_YEARS_VALID}y '+%Y-%m-%dT%H:%M:%SZ')
  RESOLVED_SECRET=$(az ad app credential reset --id "$app_id" \
    --display-name "$label" --end-date "$end_date" --query "password" -o tsv)
  RESOLVED_ORIGIN="minted"
  success "Created."
}

info "Resolving credentials"

KV_OIDC_DOC="";  KV_PATCH_DOC=""
SM_OIDC_DOC="";  SM_PATCH_DOC=""
if [[ -n "$KEY_VAULT_NAME" ]]; then KV_OIDC_DOC=$(kv_get "$KV_OIDC_NAME"); KV_PATCH_DOC=$(kv_get "$KV_PATCH_NAME"); fi
if [[ "$ENABLE_AWS" == "true" ]]; then SM_OIDC_DOC=$(sm_get "$SM_OIDC_NAME"); SM_PATCH_DOC=$(sm_get "$SM_PATCH_NAME"); fi

resolve_secret "$APP_ID" "$APP_NAME" \
  "$( [[ -n "$KV_OIDC_DOC" ]] && manifest_secret "$KV_OIDC_DOC" )" \
  "$( [[ -n "$SM_OIDC_DOC" ]] && manifest_secret "$SM_OIDC_DOC" )"
HEADLAMP_SECRET="$RESOLVED_SECRET"; HEADLAMP_ORIGIN="$RESOLVED_ORIGIN"

resolve_secret "$PATCH_APP_ID" "$PATCH_APP_NAME" \
  "$( [[ -n "$KV_PATCH_DOC" ]] && json_field "$KV_PATCH_DOC" clientSecret )" \
  "$( [[ -n "$SM_PATCH_DOC" ]] && json_field "$SM_PATCH_DOC" clientSecret )"
PATCH_SECRET="$RESOLVED_SECRET"; PATCH_ORIGIN="$RESOLVED_ORIGIN"

# =============================================================================
# WRITE TO STORES
# =============================================================================

# All seven keys are always present, even when empty. The deployment reads them
# with secretKeyRef and no `optional: true`, so a missing key does not fall back
# to a default -- the pod fails with CreateContainerConfigError.
build_manifest() {
  local use_access_token="$1"
  APP_ID="$APP_ID" HEADLAMP_SECRET="$HEADLAMP_SECRET" TENANT_ID="$TENANT_ID" \
  K8S_SECRET_NAME="$K8S_SECRET_NAME" K8S_NAMESPACE="$K8S_NAMESPACE" \
  VALIDATOR_CLIENT_ID="$VALIDATOR_CLIENT_ID" USE_ACCESS_TOKEN="$use_access_token" python3 -c "
import base64, json, os
def b64(s): return base64.b64encode(s.encode()).decode()
uat = os.environ['USE_ACCESS_TOKEN']
azure = uat == 'true'
tenant = os.environ['TENANT_ID']
print(json.dumps({
  'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
  'metadata': {'name': os.environ['K8S_SECRET_NAME'], 'namespace': os.environ['K8S_NAMESPACE']},
  'data': {
    'clientID':           b64(os.environ['APP_ID']),
    'clientSecret':       b64(os.environ['HEADLAMP_SECRET']),
    'issuerURL':          b64('https://login.microsoftonline.com/%s/v2.0' % tenant),
    'scopes':             b64('%s/user.read,openid,email,profile' % os.environ['VALIDATOR_CLIENT_ID'] if azure else 'openid,email,profile'),
    'validatorClientID':  b64(os.environ['VALIDATOR_CLIENT_ID'] if azure else ''),
    'validatorIssuerURL': b64('https://sts.windows.net/%s/' % tenant if azure else ''),
    'useAccessToken':     b64(uat),
  },
}))
"
}

build_patch_doc() {
  PATCH_APP_ID="$PATCH_APP_ID" PATCH_SECRET="$PATCH_SECRET" TENANT_ID="$TENANT_ID" python3 -c "
import json, os
print(json.dumps({
  'clientId':     os.environ['PATCH_APP_ID'],
  'clientSecret': os.environ['PATCH_SECRET'],
  'tenantId':     os.environ['TENANT_ID'],
}))
"
}

STORES_WRITTEN=""

if [[ -n "$KEY_VAULT_NAME" ]]; then
  info "Key Vault"
  WANT_OIDC=$(build_manifest true)
  WANT_PATCH=$(build_patch_doc)
  if [[ "$WANT_OIDC" != "$KV_OIDC_DOC" ]]; then
    az keyvault secret set --vault-name "$KEY_VAULT_NAME" --name "$KV_OIDC_NAME" --value "$WANT_OIDC" --output none
    success "$KV_OIDC_NAME written."
  else
    success "$KV_OIDC_NAME already current."
  fi
  if [[ "$WANT_PATCH" != "$KV_PATCH_DOC" ]]; then
    az keyvault secret set --vault-name "$KEY_VAULT_NAME" --name "$KV_PATCH_NAME" --value "$WANT_PATCH" --output none
    success "$KV_PATCH_NAME written."
  else
    success "$KV_PATCH_NAME already current."
  fi
  STORES_WRITTEN="azure"
fi

if [[ "$ENABLE_AWS" == "true" ]]; then
  info "Secrets Manager"
  # useAccessToken is false on AWS: the EKS API server requires an aud claim
  # that Entra access tokens do not carry in the form it expects. The ID token
  # does, which makes the validator pair unnecessary -- but the keys stay.
  WANT_OIDC=$(build_manifest false)
  WANT_PATCH=$(build_patch_doc)
  sm_put() {
    local name="$1" value="$2"
    aws secretsmanager put-secret-value --secret-id "$name" --secret-string "$value" \
      --region "$AWS_REGION_RESOLVED" >/dev/null 2>&1 \
      || aws secretsmanager create-secret --name "$name" --secret-string "$value" \
           --region "$AWS_REGION_RESOLVED" >/dev/null
  }
  if [[ "$WANT_OIDC" != "$SM_OIDC_DOC" ]]; then
    sm_put "$SM_OIDC_NAME" "$WANT_OIDC";  success "$SM_OIDC_NAME written."
  else
    success "$SM_OIDC_NAME already current."
  fi
  if [[ "$WANT_PATCH" != "$SM_PATCH_DOC" ]]; then
    sm_put "$SM_PATCH_NAME" "$WANT_PATCH"; success "$SM_PATCH_NAME written."
  else
    success "$SM_PATCH_NAME already current."
  fi
  STORES_WRITTEN="${STORES_WRITTEN:+$STORES_WRITTEN,}aws"
fi

# =============================================================================
# REPORT METADATA
#
# No secrets. Application IDs and expiry dates only -- enough for the credential
# dashboard, and nothing that would matter if it were logged. Entra sends no
# notification before an application client secret expires, so these dates are
# the only warning that will exist.
# =============================================================================

info "Reporting to EKS Manager"

app_expiry() { az ad app credential list --id "$1" --query "[0].endDateTime" -o tsv 2>/dev/null || true; }

PAYLOAD=$(APP_ID="$APP_ID" PATCH_APP_ID="$PATCH_APP_ID" TENANT_ID="$TENANT_ID" \
  HEADLAMP_EXPIRY="$(app_expiry "$APP_ID")" PATCH_EXPIRY="$(app_expiry "$PATCH_APP_ID")" \
  STORES_WRITTEN="$STORES_WRITTEN" python3 -c "
import json, os
print(json.dumps({
  'headlampAppId':        os.environ['APP_ID'],
  'patchUrlAppId':        os.environ['PATCH_APP_ID'],
  'tenantId':             os.environ['TENANT_ID'],
  'issuerURL':            'https://login.microsoftonline.com/%s/v2.0' % os.environ['TENANT_ID'],
  'headlampSecretExpiry': os.environ['HEADLAMP_EXPIRY'],
  'patchUrlSecretExpiry': os.environ['PATCH_EXPIRY'],
  'storesWritten':        os.environ['STORES_WRITTEN'],
}))
")

HTTP_STATUS=$(curl -sS -o /tmp/headlamp-status-response.json -w '%{http_code}' \
  -X POST "${EKSMANAGER_API_URL}/config/headlamp/status" \
  -H "Authorization: Bearer ${API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" || echo "000")

case "$HTTP_STATUS" in
  2*) success "Reported (HTTP $HTTP_STATUS)." ;;
  *)  warn "Could not report to EKS Manager (HTTP $HTTP_STATUS). The applications and secrets are in place;
       only the dashboard metadata is missing. Re-run to retry."
      sed -n '1,20p' /tmp/headlamp-status-response.json >&2 2>/dev/null || true ;;
esac
rm -f /tmp/headlamp-status-response.json

# --- Summary -----------------------------------------------------------------
echo ""
echo "============================================================"
echo " Headlamp identity ready"
echo "============================================================"
echo " Tenant:        $TENANT_ID"
echo " $APP_NAME"
echo "   App ID:      $APP_ID"
echo "   Secret:      $HEADLAMP_ORIGIN"
echo " $PATCH_APP_NAME"
echo "   App ID:      $PATCH_APP_ID"
echo "   Secret:      $PATCH_ORIGIN"
echo "   Owns:        $APP_NAME (Application.ReadWrite.OwnedBy)"
echo " Stores:        ${STORES_WRITTEN:-none}"
echo "============================================================"
