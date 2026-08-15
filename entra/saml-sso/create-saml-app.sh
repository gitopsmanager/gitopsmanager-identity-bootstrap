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

APP_NAME="EKS Manager SAML — ${PROVIDER_NAME}"

# ── STEP 1 — App registration ────────────────────────────────────────────────

echo ""
echo "Step 1/5 — Checking for existing app registration '${APP_NAME}'..."

EXISTING_APP_ID=$(az ad app list --display-name "${APP_NAME}" --query "[0].appId" -o tsv 2>/dev/null || echo "")

if [ -n "${EXISTING_APP_ID}" ] && [ "${EXISTING_APP_ID}" != "null" ]; then
  echo "App already exists. App ID: ${EXISTING_APP_ID}"
  CLIENT_ID="${EXISTING_APP_ID}"

  echo "Updating redirect URI and identifier URI to match current Cognito config..."
  az ad app update --id "${CLIENT_ID}" \
    --web-redirect-uris "${COGNITO_ACS_URL}" \
    --identifier-uris "${COGNITO_ENTITY_ID}" \
    >/dev/null
else
  echo "Creating app registration '${APP_NAME}'..."
  CLIENT_ID=$(az ad app create \
    --display-name "${APP_NAME}" \
    --sign-in-audience "AzureADMyOrg" \
    --web-redirect-uris "${COGNITO_ACS_URL}" \
    --query "appId" -o tsv)

  # identifier-uris must be set after creation — az ad app create doesn't accept it directly
  az ad app update --id "${CLIENT_ID}" --identifier-uris "${COGNITO_ENTITY_ID}" >/dev/null

  echo "App created. App ID: ${CLIENT_ID}"
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
# az ad sp update does not yet expose preferredSingleSignOnMode directly —
# use the Graph API via az rest.
az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}" \
  --headers "Content-Type=application/json" \
  --body "{\"preferredSingleSignOnMode\": \"saml\", \"loginUrl\": \"${COGNITO_SIGN_ON_URL}\", \"appRoleAssignmentRequired\": false}"
echo "SAML SSO mode set."

# ── STEP 3 — Token signing certificate ───────────────────────────────────────

echo ""
echo "Step 3/5 — Checking for existing token signing certificate..."

EXISTING_CERT=$(az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/tokenSigningCertificates" \
  --query "value[0].thumbprint" -o tsv 2>/dev/null || echo "")

if [ -n "${EXISTING_CERT}" ] && [ "${EXISTING_CERT}" != "null" ]; then
  echo "Token signing certificate already exists. Thumbprint: ${EXISTING_CERT}"
  CERT_VALUE=$(az rest --method GET \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/tokenSigningCertificates" \
    --query "value[0].key" -o tsv)
else
  echo "Creating self-signed token signing certificate..."
  CERT_JSON=$(az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/addTokenSigningCertificate" \
    --headers "Content-Type=application/json" \
    --body "{\"displayName\": \"CN=EKS Manager SAML Signing\", \"endDateTime\": \"$(date -u -d '+3 years' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v+3y '+%Y-%m-%dT%H:%M:%SZ')\"}")
  CERT_VALUE=$(echo "${CERT_JSON}" | grep -o '"key": *"[^"]*"' | cut -d'"' -f4)
  echo "Certificate created."
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
