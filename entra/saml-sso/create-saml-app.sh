#!/usr/bin/env bash
# Copyright (c) 2026 GitOps Manager, S.L. All rights reserved.
# ==============================================================================
# create-saml-app.sh
# ==============================================================================
# Creates the Entra SAML Enterprise Application used for Cognito SSO, then
# reports the resulting SAML metadata back to EKS Manager so it can
# configure the Cognito SAML identity provider.
#
# WHAT THIS SCRIPT DOES
#   1. Creates (or reuses) an Entra app registration with the Cognito ACS URL
#      as its redirect URI and the Cognito entity ID as its identifier URI
#   2. Creates a service principal in SAML single sign-on mode
#   3. Creates a self-signed token signing certificate on the service principal
#   4. Obtains its own M2M bearer token from Cognito
#   5. POSTs the resulting app ID, entity ID, federation metadata URL and
#      signing certificate to the EKS Manager API so Cognito can be
#      configured automatically
#
# Idempotent — safe to re-run. If the app already exists it is reused.
#
# PREREQUISITES
#   - Azure CLI (az) installed and authenticated: az login
#   - Signed in user must hold the Cloud Application Administrator directory
#     role (or higher, e.g. Global Administrator) — required to create app
#     registrations and service principals
#   - curl
#   - Network egress from wherever this script runs must be reachable by
#     the client's EKS Manager API — if the API sits behind an IP
#     allowlist, run this from a host whose public IP is already allowlisted
#     (the same NAT Gateway IP used by the eksmanager-bootstrap CodeBuild
#     pipeline satisfies this — see the root README.md)
#
# USAGE
#   This script reads everything from environment variables — nothing is
#   typed or stored in the file itself, so it's reusable as-is across every
#   client. Set the required variables, then run:
#     chmod +x create-saml-app.sh
#     ./create-saml-app.sh
#
#   Get the export block to copy-paste from Settings → Terraform tile in
#   your EKS Manager dashboard — it provides ready-to-paste bash exports
#   for all EKSMANAGER_* values and the SAML-specific values shown under
#   "topology.json — example" → the "saml" section.
#
#   Required environment variables:
#     COGNITO_ACS_URL           saml.cognitoAcsUrl
#     COGNITO_ENTITY_ID         saml.cognitoEntityId
#     COGNITO_SIGN_ON_URL       saml.cognitoSignOnUrl
#     EKSMANAGER_API_URL        EKS Manager API URL
#     EKSMANAGER_CLIENT_ID      M2M client ID
#     EKSMANAGER_CLIENT_SECRET  M2M client secret
#     EKSMANAGER_COGNITO_URL    Cognito token endpoint
#   Optional:
#     PROVIDER_NAME             App registration name suffix (default: EntraSAML)
# ==============================================================================

set -euo pipefail

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
# Everything is read from the environment — nothing is stored in this file.

PROVIDER_NAME="${PROVIDER_NAME:-EntraSAML}"
COGNITO_ACS_URL="${COGNITO_ACS_URL:-}"
COGNITO_ENTITY_ID="${COGNITO_ENTITY_ID:-}"
COGNITO_SIGN_ON_URL="${COGNITO_SIGN_ON_URL:-}"
EKSMANAGER_API_URL="${EKSMANAGER_API_URL:-}"
EKSMANAGER_CLIENT_ID="${EKSMANAGER_CLIENT_ID:-}"
EKSMANAGER_CLIENT_SECRET="${EKSMANAGER_CLIENT_SECRET:-}"
EKSMANAGER_COGNITO_URL="${EKSMANAGER_COGNITO_URL:-}"

# ── VALIDATION ─────────────────────────────────────────────────────────────────

for var in COGNITO_ACS_URL COGNITO_ENTITY_ID COGNITO_SIGN_ON_URL \
           EKSMANAGER_API_URL EKSMANAGER_CLIENT_ID EKSMANAGER_CLIENT_SECRET EKSMANAGER_COGNITO_URL; do
  if [ -z "${!var}" ]; then
    echo "ERROR: ${var} is not set. Export it before running this script — see USAGE at the top of the file." >&2
    exit 1
  fi
done

if ! command -v az >/dev/null 2>&1; then
  echo "ERROR: Azure CLI (az) is not installed. See https://learn.microsoft.com/cli/azure/install-azure-cli" >&2
  exit 1
fi

echo "Checking az login session..."
ACCOUNT_JSON=$(az account show 2>/dev/null) || {
  echo "ERROR: Not logged in. Run: az login" >&2
  exit 1
}
TENANT_ID=$(echo "${ACCOUNT_JSON}" | grep -o '"tenantId": *"[^"]*"' | cut -d'"' -f4)
echo "Logged in. Tenant: ${TENANT_ID}"

# Plain ASCII "--", not an em dash. The PowerShell script has to be ASCII to
# parse under Windows PowerShell 5.1, and both scripts find an existing app by
# this exact display name -- so if the two names differ, running one after the
# other creates a second app registration instead of reusing the first.
APP_NAME="EKS Manager SAML -- ${PROVIDER_NAME}"

# Cognito's entity ID is urn:amazon:cognito:sp:<pool-id>, which contains no
# verified domain, no tenant ID and no app ID — so newer tenants reject it under
# their default application policy. Microsoft's own error says the restriction
# may not apply when requestedAccessTokenVersion is 2, so that is set first and
# the URI attempted afterwards. Order matters: Graph will not raise the token
# version once a v1-style URI is already on the application.
#
# If it still fails, stop. Cognito requires its entity ID to match, and that
# value cannot be changed — so an application without it looks created and
# cannot federate.
set_identifier_uri() {
  local client_id="$1" uri="$2"

  local object_id
  object_id=$(az ad app show --id "${client_id}" --query "id" -o tsv) || {
    echo "ERROR: could not read the object ID for app ${client_id}." >&2
    exit 1
  }

  az rest --method PATCH \
    --uri "https://graph.microsoft.com/v1.0/applications/${object_id}" \
    --headers "Content-Type=application/json" \
    --body '{"api":{"requestedAccessTokenVersion":2}}' >/dev/null

  echo "Setting identifier URI ${uri} ..."
  if ! az ad app update --id "${client_id}" --identifier-uris "${uri}" >/dev/null; then
    cat >&2 <<EOF

ERROR: the tenant refused the identifier URI '${uri}'.

Cognito requires its entity ID to be the application's identifier URI, and that
value cannot be changed — so SAML will not work until the tenant accepts it.

An administrator needs to relax the identifier URI restriction for this tenant,
or grant this application an exemption. See:
  https://aka.ms/identifier-uri-formatting-error

Microsoft's own message is printed above this one.
EOF
    exit 1
  fi
  echo "Identifier URI set."
}

# ── STEP 1 — App registration ────────────────────────────────────────────────

echo ""
echo "Step 1/5 — Checking for existing app registration '${APP_NAME}'..."

EXISTING_APP_ID=$(az ad app list --display-name "${APP_NAME}" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [ -n "${EXISTING_APP_ID}" ] && [ "${EXISTING_APP_ID}" != "null" ]; then
  echo "App already exists. App ID: ${EXISTING_APP_ID}"
  CLIENT_ID="${EXISTING_APP_ID}"

  echo "Updating redirect URI to match current Cognito config..."
  az ad app update --id "${CLIENT_ID}" \
    --web-redirect-uris "${COGNITO_ACS_URL}" \
    >/dev/null

  set_identifier_uri "${CLIENT_ID}" "${COGNITO_ENTITY_ID}"
else
  echo "Creating app registration '${APP_NAME}'..."
  CLIENT_ID=$(az ad app create \
    --display-name "${APP_NAME}" \
    --sign-in-audience "AzureADMyOrg" \
    --web-redirect-uris "${COGNITO_ACS_URL}" \
    --query "appId" -o tsv)

  if [ -z "${CLIENT_ID}" ]; then
    echo "ERROR: could not create the app registration." >&2
    exit 1
  fi
  echo "App created. App ID: ${CLIENT_ID}"

  # identifier-uris must be set after creation — az ad app create doesn't accept it directly
  set_identifier_uri "${CLIENT_ID}" "${COGNITO_ENTITY_ID}"
fi

# ── STEP 2 — Service principal with SAML SSO mode ───────────────────────────

echo ""
echo "Step 2/5 — Checking for existing service principal..."

SP_OBJECT_ID=$(az ad sp list --filter "appId eq '${CLIENT_ID}'" --query "[0].id" -o tsv 2>/dev/null || echo "")

if [ -n "${SP_OBJECT_ID}" ] && [ "${SP_OBJECT_ID}" != "null" ]; then
  echo "Service principal already exists. Object ID: ${SP_OBJECT_ID}"
else
  echo "Creating service principal..."
  SP_OBJECT_ID=$(az ad sp create --id "${CLIENT_ID}" --query "id" -o tsv)
  echo "Service principal created. Object ID: ${SP_OBJECT_ID}"
fi

echo "Setting single sign-on mode to SAML..."

# The Entra portal's "Enterprise applications" list defaults to filtering on
# Application type = Enterprise Applications, which shows only service
# principals carrying this tag. One created by the CLI has no tags, so it is
# invisible there — the administrator sees the app registration and concludes
# the enterprise application was never created. It was; the list is filtered.
#
# Tags are replaced wholesale by PATCH, so any already present are carried
# forward rather than overwritten.
PORTAL_TAG="WindowsAzureActiveDirectoryIntegratedApp"
EXISTING_TAGS=$(az ad sp show --id "${SP_OBJECT_ID}" --query "join(',', not_null(tags, \`[]\`))" -o tsv)

TAGS_FRAGMENT=""
case ",${EXISTING_TAGS}," in
  *",${PORTAL_TAG},"*)
    : ;;   # already tagged, leave it alone
  *)
    if [ -n "${EXISTING_TAGS}" ]; then
      ALL_TAGS="${EXISTING_TAGS},${PORTAL_TAG}"
    else
      ALL_TAGS="${PORTAL_TAG}"
    fi
    TAGS_FRAGMENT=", \"tags\": [\"$(echo "${ALL_TAGS}" | sed 's/,/","/g')\"]"
    echo "Tagging as an enterprise application so it appears in the portal list..."
    ;;
esac

# az ad sp update does not yet expose preferredSingleSignOnMode directly —
# use the Graph API via az rest.
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}" \
  --headers "Content-Type=application/json" \
  --body "{\"preferredSingleSignOnMode\": \"saml\", \"loginUrl\": \"${COGNITO_SIGN_ON_URL}\", \"appRoleAssignmentRequired\": false${TAGS_FRAGMENT}}"
echo "SAML SSO mode set."

# ── Claims: guarantee an emailaddress claim ──────────────────────────────────
#
# An application created through Graph has no claims configuration, because the
# portal's SAML wizard is what normally writes one and these apps never go near
# it. Entra then emits only its implicit defaults, which for a member account do
# NOT include emailaddress — even when the user's mail attribute is populated.
#
# Cognito requires an email to create a federated user, and GitOps Manager
# matches that email against its own user records, so an assertion without one
# fails at sign-in with "Invalid user attributes: emails: The attribute emails is
# required" — a message that points at Cognito and hides the cause entirely.
#
# Guest accounts get an emailaddress anyway, resolved from their home identity,
# which is why a tenant whose operator is a guest appears to work and a tenant of
# ordinary members does not.
#
# IncludeBasicClaimSet keeps everything Entra already emits; this only adds the
# one claim that is missing.
CLAIMS_POLICY_NAME="GitOpsManager-SAML-EmailClaim"

echo "Ensuring the application emits an emailaddress claim..."

CLAIMS_POLICY_ID=$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies" \
  --query "value[?displayName=='${CLAIMS_POLICY_NAME}'].id | [0]" -o tsv)

if [ -z "${CLAIMS_POLICY_ID}" ] || [ "${CLAIMS_POLICY_ID}" = "null" ]; then
  # Written to a file rather than inlined: the definition is JSON inside a JSON
  # string, and getting that through a shell intact is not worth the risk.
  POLICY_BODY=$(mktemp)
  cat > "${POLICY_BODY}" <<'POLICYEOF'
{
  "displayName": "GitOpsManager-SAML-EmailClaim",
  "isOrganizationDefault": false,
  "definition": [
    "{\"ClaimsMappingPolicy\":{\"Version\":1,\"IncludeBasicClaimSet\":\"true\",\"ClaimsSchema\":[{\"Source\":\"user\",\"ID\":\"mail\",\"SamlClaimType\":\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\"}]}}"
  ]
}
POLICYEOF

  CLAIMS_POLICY_ID=$(az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies" \
    --headers "Content-Type=application/json" \
    --body "@${POLICY_BODY}" --query "id" -o tsv)
  rm -f "${POLICY_BODY}"

  if [ -z "${CLAIMS_POLICY_ID}" ]; then
    echo "ERROR: could not create the claims mapping policy." >&2
    exit 1
  fi
  echo "Created claims policy '${CLAIMS_POLICY_NAME}'."
else
  echo "Reusing existing claims policy '${CLAIMS_POLICY_NAME}'."
fi

# A service principal takes at most one claims mapping policy. If something else
# already owns that slot, replacing it would silently change whatever configured
# it — so say so and stop rather than guess.
ASSIGNED_ID=$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/claimsMappingPolicies" \
  --query "value[0].id" -o tsv)

if [ -z "${ASSIGNED_ID}" ] || [ "${ASSIGNED_ID}" = "null" ]; then
  ASSIGN_BODY=$(mktemp)
  cat > "${ASSIGN_BODY}" <<EOF
{"@odata.id": "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/${CLAIMS_POLICY_ID}"}
EOF
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/claimsMappingPolicies/\$ref" \
    --headers "Content-Type=application/json" --body "@${ASSIGN_BODY}" >/dev/null
  rm -f "${ASSIGN_BODY}"
  echo "Claims policy assigned."
elif [ "${ASSIGNED_ID}" = "${CLAIMS_POLICY_ID}" ]; then
  echo "Claims policy already assigned."
else
  ASSIGNED_NAME=$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/claimsMappingPolicies" \
    --query "value[0].displayName" -o tsv)
  cat >&2 <<EOF

ERROR: this application already has a different claims mapping policy assigned:
  '${ASSIGNED_NAME}' (${ASSIGNED_ID})

A service principal can hold only one. Replacing it could break whatever
configured it, so this script will not do so. Check that policy emits an
emailaddress claim sourced from the user's mail attribute, or merge this claim
into it.
EOF
  exit 1
fi

# ── STEP 3 — Token signing certificate ───────────────────────────────────────

echo ""
echo "Step 3/5 — Checking for existing token signing certificate..."

# Signing certificates live in the service principal's keyCredentials. There is
# NO /tokenSigningCertificates navigation property to GET — asking for one
# returns "Resource 'tokenSigningCertificates' does not exist", every time,
# certificate or not. An earlier version of this script read that 404 as "none
# yet" and so minted a brand new certificate on every single run.
#
# Each certificate appears as two entries: usage "Verify" (the public half,
# which is the only one Graph returns a key for) and usage "Sign".
# A certificate inside the last 30 days does not count as reusable, so re-running
# this close to expiry issues a replacement instead. That is the whole rotation
# path: GitOps Manager warns from 30 days out, the operator re-runs, a new
# certificate is issued, made active and reported. Reusing anything still
# technically valid would leave that warning with no action that clears it.
ROTATE_BEFORE=$(date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
  || date -u -v+30d '+%Y-%m-%dT%H:%M:%SZ')

CERT_VALUE=$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}?\$select=keyCredentials" \
  --query "reverse(sort_by(keyCredentials[?usage=='Verify' && type=='AsymmetricX509Cert' && key!=null && endDateTime > '${ROTATE_BEFORE}'], &endDateTime))[0].key" \
  -o tsv)

if [ -n "${CERT_VALUE}" ] && [ "${CERT_VALUE}" != "null" ]; then
  echo "Reusing existing signing certificate."

  CERT_COUNT=$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}?\$select=keyCredentials" \
    --query "length(keyCredentials[?usage=='Verify' && type=='AsymmetricX509Cert' && key!=null && endDateTime > '${ROTATE_BEFORE}'])" \
    -o tsv)

  # The portal cannot fix this. Its SAML certificate UI is only offered for
  # non-gallery applications; an app registered in this same tenant gets the
  # OpenID Connect page instead, with no certificate list at all.
  if [ "${CERT_COUNT}" -gt 1 ] 2>/dev/null; then
    echo ""
    echo "NOTE: this application has ${CERT_COUNT} valid signing certificates, and the"
    echo "      federation metadata advertises every one of them. Earlier versions of"
    echo "      this script added one per run."
    echo ""
    echo "      Sign-in is unaffected — the active certificate signs, and the rest are"
    echo "      accepted but unused. To get back to one, delete this application and"
    echo "      re-run this script; it is idempotent and will create exactly one."
    echo ""
  fi
else
  echo "Creating self-signed token signing certificate..."
  CERT_JSON=$(az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/addTokenSigningCertificate" \
    --headers "Content-Type=application/json" \
    --body "{\"displayName\": \"CN=EKS Manager SAML Signing\", \"endDateTime\": \"$(date -u -d '+3 years' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v+3y '+%Y-%m-%dT%H:%M:%SZ')\"}")
  CERT_VALUE=$(echo "${CERT_JSON}" | grep -o '"key": *"[^"]*"' | cut -d'"' -f4)

  # Name it the active signing key. Without this the tenant leaves the choice
  # undefined, and the certificate reported to GitOps Manager may not be the one
  # Entra actually signs assertions with.
  CERT_THUMBPRINT=$(echo "${CERT_JSON}" | grep -o '"thumbprint": *"[^"]*"' | cut -d'"' -f4)
  if [ -n "${CERT_THUMBPRINT}" ]; then
    az rest --method PATCH \
      --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}" \
      --headers "Content-Type=application/json" \
      --body "{\"preferredTokenSigningKeyThumbprint\": \"${CERT_THUMBPRINT}\"}" >/dev/null
  fi

  echo "Certificate created."
fi

if [ -z "${CERT_VALUE}" ] || [ "${CERT_VALUE}" = "null" ]; then
  echo "ERROR: no signing certificate key available — nothing to report to GitOps Manager." >&2
  exit 1
fi

# ── STEP 4 — Get M2M bearer token ────────────────────────────────────────────

echo ""
echo "Step 4/5 — Obtaining M2M bearer token..."

TOKEN=$(curl -fsSL -X POST "${EKSMANAGER_COGNITO_URL}/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${EKSMANAGER_CLIENT_ID}&client_secret=${EKSMANAGER_CLIENT_SECRET}" \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "${TOKEN}" ] || [ "${TOKEN}" = "null" ]; then
  echo "ERROR: Failed to obtain M2M bearer token" >&2
  exit 1
fi

# ── STEP 5 — Report SAML status to EKS Manager ───────────────────────────

echo ""
echo "Step 5/5 — Reporting SAML configuration to EKS Manager..."

ENTITY_ID="https://sts.windows.net/${TENANT_ID}/"
METADATA_URL="https://login.microsoftonline.com/${TENANT_ID}/federationmetadata/2007-06/federationmetadata.xml?appid=${CLIENT_ID}"

HTTP_STATUS=$(curl -fsSL -X POST "${EKSMANAGER_API_URL}/config/saml/status" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"appId\":\"${CLIENT_ID}\",\"entityId\":\"${ENTITY_ID}\",\"metadataUrl\":\"${METADATA_URL}\",\"certificate\":\"${CERT_VALUE}\",\"providerName\":\"${PROVIDER_NAME}\"}" \
  -o /tmp/saml-status-response.json \
  -w "%{http_code}")

if [ "${HTTP_STATUS}" != "200" ] && [ "${HTTP_STATUS}" != "201" ] && [ "${HTTP_STATUS}" != "204" ]; then
  echo "ERROR: Failed to report SAML status to EKS Manager (HTTP ${HTTP_STATUS})" >&2
  cat /tmp/saml-status-response.json >&2
  exit 1
fi

echo ""
echo "================================================================"
echo "SAML app ready."
echo "  App ID:       ${CLIENT_ID}"
echo "  Entity ID:    ${ENTITY_ID}"
echo "  Metadata URL: ${METADATA_URL}"
echo "================================================================"
echo "EKS Manager has been notified and will configure Cognito SAML automatically."
