# Copyright (c) 2026 GitOps Manager, S.L. All rights reserved.
<#
.SYNOPSIS
    Creates the Entra SAML Enterprise Application used for Cognito SSO.

.DESCRIPTION
    Creates (or reuses) an Entra app registration and service principal in
    SAML single sign-on mode, generates a token signing certificate, obtains
    its own M2M bearer token, and reports the resulting metadata to GitOps
    Manager so it can configure the Cognito SAML identity provider
    automatically.

    WHAT THIS SCRIPT DOES
      1. Creates (or reuses) an Entra app registration with the Cognito ACS
         URL as its redirect URI and the Cognito entity ID as its identifier URI
      2. Creates a service principal in SAML single sign-on mode
      3. Creates a self-signed token signing certificate on the service principal
      4. Obtains its own M2M bearer token from Cognito
      5. POSTs the resulting app ID, entity ID, federation metadata URL and
         signing certificate to the EKS Manager API

    Idempotent — safe to re-run. If the app already exists it is reused.

.NOTES
    PREREQUISITES
      - Azure CLI (az) installed and authenticated: az login
      - Signed in user must hold the Cloud Application Administrator directory
        role (or higher, e.g. Global Administrator)
      - Network egress from wherever this script runs must be reachable by
        the client's EKS Manager API — if the API sits behind an IP
        allowlist, run this from a host whose public IP is already
        allowlisted (the same NAT Gateway IP used by the eksmanager-bootstrap
        CodeBuild pipeline satisfies this — see
        the root README.md)

    USAGE
      This script reads everything from environment variables — nothing is
      typed or stored in the file itself, so it's reusable as-is across
      every client. Set the required variables, then run:
        .\create-saml-app.ps1

      Get the export block to copy-paste from Settings -> Terraform tile in
      your EKS Manager dashboard — it provides ready-to-paste PowerShell
      $env: assignments for all EKSMANAGER_* values and the SAML-specific
      values shown under "topology.json - example" -> the "saml" section.

      Required environment variables:
        COGNITO_ACS_URL           saml.cognitoAcsUrl
        COGNITO_ENTITY_ID         saml.cognitoEntityId
        COGNITO_SIGN_ON_URL       saml.cognitoSignOnUrl
        EKSMANAGER_API_URL        EKS Manager API URL
        EKSMANAGER_CLIENT_ID      M2M client ID
        EKSMANAGER_CLIENT_SECRET  M2M client secret
        EKSMANAGER_COGNITO_URL    Cognito token endpoint
      Optional:
        PROVIDER_NAME             App registration name suffix (default: EntraSAML)
#>

$ErrorActionPreference = "Stop"

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
# Everything is read from the environment — nothing is stored in this file.

$ProviderName            = if ($env:PROVIDER_NAME) { $env:PROVIDER_NAME } else { "EntraSAML" }
$CognitoAcsUrl            = $env:COGNITO_ACS_URL
$CognitoEntityId          = $env:COGNITO_ENTITY_ID
$CognitoSignOnUrl         = $env:COGNITO_SIGN_ON_URL
$EksManagerApiUrl         = $env:EKSMANAGER_API_URL
$EksManagerClientId       = $env:EKSMANAGER_CLIENT_ID
$EksManagerClientSecret   = $env:EKSMANAGER_CLIENT_SECRET
$EksManagerCognitoUrl     = $env:EKSMANAGER_COGNITO_URL

# ── VALIDATION ─────────────────────────────────────────────────────────────────

$required = @{
    COGNITO_ACS_URL          = $CognitoAcsUrl
    COGNITO_ENTITY_ID        = $CognitoEntityId
    COGNITO_SIGN_ON_URL      = $CognitoSignOnUrl
    EKSMANAGER_API_URL       = $EksManagerApiUrl
    EKSMANAGER_CLIENT_ID     = $EksManagerClientId
    EKSMANAGER_CLIENT_SECRET = $EksManagerClientSecret
    EKSMANAGER_COGNITO_URL   = $EksManagerCognitoUrl
}
foreach ($key in $required.Keys) {
    if ([string]::IsNullOrWhiteSpace($required[$key])) {
        Write-Error "ERROR: $key is not set. Export it before running this script — see USAGE at the top of the file."
        exit 1
    }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "ERROR: Azure CLI (az) is not installed. See https://learn.microsoft.com/cli/azure/install-azure-cli"
    exit 1
}

Write-Host "Checking az login session..."
try {
    $account = az account show | ConvertFrom-Json
} catch {
    Write-Error "ERROR: Not logged in. Run: az login"
    exit 1
}
$TenantId = $account.tenantId
Write-Host "Logged in. Tenant: $TenantId"

$AppName = "EKS Manager SAML — $ProviderName"

# ── STEP 1 — App registration ────────────────────────────────────────────────

Write-Host ""
Write-Host "Step 1/5 — Checking for existing app registration '$AppName'..."

$existingApp = az ad app list --display-name "$AppName" --query "[0]" | ConvertFrom-Json

if ($existingApp) {
    $ClientId = $existingApp.appId
    Write-Host "App already exists. App ID: $ClientId"

    Write-Host "Updating redirect URI and identifier URI to match current Cognito config..."
    az ad app update --id $ClientId `
        --web-redirect-uris $CognitoAcsUrl `
        --identifier-uris $CognitoEntityId | Out-Null
} else {
    Write-Host "Creating app registration '$AppName'..."
    $ClientId = az ad app create `
        --display-name "$AppName" `
        --sign-in-audience "AzureADMyOrg" `
        --web-redirect-uris $CognitoAcsUrl `
        --query "appId" -o tsv

    # identifier-uris must be set after creation
    az ad app update --id $ClientId --identifier-uris $CognitoEntityId | Out-Null

    Write-Host "App created. App ID: $ClientId"
}

# ── STEP 2 — Service principal with SAML SSO mode ───────────────────────────

Write-Host ""
Write-Host "Step 2/5 — Checking for existing service principal..."

$existingSp = az ad sp list --filter "appId eq '$ClientId'" --query "[0]" | ConvertFrom-Json

if ($existingSp) {
    $SpObjectId = $existingSp.id
    Write-Host "Service principal already exists. Object ID: $SpObjectId"
} else {
    Write-Host "Creating service principal..."
    $SpObjectId = az ad sp create --id $ClientId --query "id" -o tsv
    Write-Host "Service principal created. Object ID: $SpObjectId"
}

Write-Host "Setting single sign-on mode to SAML..."
$ssoBody = @{
    preferredSingleSignOnMode = "saml"
    loginUrl                  = $CognitoSignOnUrl
    appRoleAssignmentRequired = $false
} | ConvertTo-Json -Compress

az rest --method PATCH `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId" `
    --headers "Content-Type=application/json" `
    --body $ssoBody
Write-Host "SAML SSO mode set."

# ── STEP 3 — Token signing certificate ───────────────────────────────────────

Write-Host ""
Write-Host "Step 3/5 — Checking for existing token signing certificate..."

$existingCerts = az rest --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId/tokenSigningCertificates" `
    | ConvertFrom-Json

if ($existingCerts.value -and $existingCerts.value.Count -gt 0) {
    Write-Host "Token signing certificate already exists. Thumbprint: $($existingCerts.value[0].thumbprint)"
    $CertValue = $existingCerts.value[0].key
} else {
    Write-Host "Creating self-signed token signing certificate..."
    $expiry = (Get-Date).AddYears(3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $certBody = @{
        displayName = "CN=EKS Manager SAML Signing"
        endDateTime = $expiry
    } | ConvertTo-Json -Compress

    $certResult = az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId/addTokenSigningCertificate" `
        --headers "Content-Type=application/json" `
        --body $certBody | ConvertFrom-Json

    $CertValue = $certResult.key
    Write-Host "Certificate created."
}

# ── STEP 4 — Get M2M bearer token ────────────────────────────────────────────

Write-Host ""
Write-Host "Step 4/5 — Obtaining M2M bearer token..."

$tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "$EksManagerCognitoUrl/oauth2/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{
        grant_type    = "client_credentials"
        client_id     = $EksManagerClientId
        client_secret = $EksManagerClientSecret
    }

$Token = $tokenResponse.access_token
if ([string]::IsNullOrWhiteSpace($Token)) {
    Write-Error "ERROR: Failed to obtain M2M bearer token"
    exit 1
}

# ── STEP 5 — Report SAML status to EKS Manager ───────────────────────────

Write-Host ""
Write-Host "Step 5/5 — Reporting SAML configuration to EKS Manager..."

$EntityId    = "https://sts.windows.net/$TenantId/"
$MetadataUrl = "https://login.microsoftonline.com/$TenantId/federationmetadata/2007-06/federationmetadata.xml?appid=$ClientId"

$statusBody = @{
    appId        = $ClientId
    entityId     = $EntityId
    metadataUrl  = $MetadataUrl
    certificate  = $CertValue
    providerName = $ProviderName
} | ConvertTo-Json -Compress

try {
    $response = Invoke-RestMethod -Method Post `
        -Uri "$EksManagerApiUrl/config/saml/status" `
        -Headers @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" } `
        -Body $statusBody
} catch {
    Write-Error "ERROR: Failed to report SAML status to EKS Manager. $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "================================================================"
Write-Host "SAML app ready."
Write-Host "  App ID:       $ClientId"
Write-Host "  Entity ID:    $EntityId"
Write-Host "  Metadata URL: $MetadataUrl"
Write-Host "================================================================"
Write-Host "EKS Manager has been notified and will configure Cognito SAML automatically."
