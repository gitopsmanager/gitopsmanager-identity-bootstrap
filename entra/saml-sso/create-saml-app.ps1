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

    Idempotent -- safe to re-run. If the app already exists it is reused.

.NOTES
    PREREQUISITES
      - Azure CLI (az) installed and authenticated: az login
      - Signed in user must hold the Cloud Application Administrator directory
        role (or higher, e.g. Global Administrator)
      - Network egress from wherever this script runs must be reachable by
        the client's EKS Manager API -- if the API sits behind an IP
        allowlist, run this from a host whose public IP is already
        allowlisted (the same NAT Gateway IP used by the eksmanager-bootstrap
        CodeBuild pipeline satisfies this -- see
        the root README.md)

    USAGE
      This script reads everything from environment variables -- nothing is
      typed or stored in the file itself, so it's reusable as-is across
      every client. Set the required variables, then run:
        .\create-saml-app.ps1

      Get the export block to copy-paste from Settings -> Terraform tile in
      your EKS Manager dashboard -- it provides ready-to-paste PowerShell
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

# -- CONFIGURATION -------------------------------------------------------------
# Everything is read from the environment -- nothing is stored in this file.

$ProviderName            = if ($env:PROVIDER_NAME) { $env:PROVIDER_NAME } else { "EntraSAML" }
$CognitoAcsUrl            = $env:COGNITO_ACS_URL
$CognitoEntityId          = $env:COGNITO_ENTITY_ID
$CognitoSignOnUrl         = $env:COGNITO_SIGN_ON_URL
$EksManagerApiUrl         = $env:EKSMANAGER_API_URL
$EksManagerClientId       = $env:EKSMANAGER_CLIENT_ID
$EksManagerClientSecret   = $env:EKSMANAGER_CLIENT_SECRET
$EksManagerCognitoUrl     = $env:EKSMANAGER_COGNITO_URL

# -- VALIDATION -----------------------------------------------------------------

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
        Write-Error "ERROR: $key is not set. Export it before running this script -- see USAGE at the top of the file."
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
if (-not $account -or -not $account.tenantId) {
    Write-Error "ERROR: Not logged in, or 'az account show' returned nothing. Run: az login"
    exit 1
}
$TenantId = $account.tenantId
Write-Host "Logged in. Tenant: $TenantId"

$AppName = "EKS Manager SAML -- $ProviderName"


# Runs az, captures stdout, and reports the exit code.
#
# Deliberately does NOT redirect stderr. Under Windows PowerShell 5.1 every form
# of redirecting a native command's stderr causes trouble, and this script runs
# with $ErrorActionPreference = "Stop":
#
#   2>&1              wraps each stderr line in an ErrorRecord, so az's routine
#                     warnings arrive glued to the front of the JSON.
#   2>file, 2>$null   raise a terminating NativeCommandError on the first line
#                     az writes to stderr -- so any exit-code check placed after
#                     the call never runs at all. This is how an earlier version
#                     of this script printed "SAML SSO mode set." immediately
#                     after the call that set nothing.
#
# Left alone, stderr goes straight to the console: the user reads Microsoft's
# error verbatim, multi-line and unmangled, while $stdout stays clean enough to
# hand to ConvertFrom-Json. The exit code is what decides control flow.
function Invoke-Az {
    param([string[]] $Arguments)

    $stdout = & az @Arguments
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = ($stdout | Out-String).Trim()
    }
}

# Passing JSON to a native command from PowerShell is where this used to fail.
# PowerShell does not escape embedded double quotes when handing arguments to an
# executable, so az received {key:value} rather than {"key":"value"} and Graph
# answered "Unable to read JSON request payload" -- while the script printed
# success on the very next line. Writing the body to a file and using az's
# documented @file syntax sidesteps the quoting entirely.
function Invoke-GraphJson {
    param(
        [string]    $Method,
        [string]    $Uri,
        [hashtable] $Body,
        [switch]    $AllowFailure
    )

    $bodyFile = New-TemporaryFile
    try {
        ($Body | ConvertTo-Json -Compress -Depth 6) |
            Set-Content -Path $bodyFile.FullName -Encoding ascii

        $result = Invoke-Az @(
            'rest', '--method', $Method, '--uri', $Uri,
            '--headers', 'Content-Type=application/json',
            '--body', "@$($bodyFile.FullName)"
        )

        if ($result.ExitCode -ne 0) {
            if ($AllowFailure) { return $null }
            Write-Error "ERROR: $Method $Uri failed -- az reported the reason above."
            exit 1
        }

        # 204 No Content is the normal answer to a successful PATCH.
        if (-not $result.Output) { return $null }
        return ($result.Output | ConvertFrom-Json)
    }
    finally { Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue }
}

# Cognito's entity ID is urn:amazon:cognito:sp:<pool-id>, which contains no
# verified domain, no tenant ID and no app ID -- so newer tenants reject it under
# their default application policy. Microsoft's own error says the restriction
# may not apply when requestedAccessTokenVersion is 2, so that is set first and
# the URI attempted afterwards.
#
# If it still fails, stop. Cognito requires its entity ID to match, and it cannot
# be changed -- so an application without it looks created and cannot federate.
function Set-IdentifierUri {
    param([string] $ClientId, [string] $Uri)

    $objectId = az ad app show --id $ClientId --query "id" -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $objectId) {
        Write-Error "ERROR: could not read the object ID for app $ClientId."
        exit 1
    }

    # Order matters: the token version has to be raised while identifierUris is
    # still empty. Graph will not accept the change once a v1-style URI is on the
    # application.
    Invoke-GraphJson -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/applications/$objectId" `
        -Body @{ api = @{ requestedAccessTokenVersion = 2 } } | Out-Null

    Write-Host "Setting identifier URI $Uri ..."
    $result = Invoke-Az @('ad', 'app', 'update', '--id', $ClientId, '--identifier-uris', $Uri)

    if ($result.ExitCode -ne 0) {
        Write-Error "ERROR: the tenant refused the identifier URI '$Uri'.

Cognito requires its entity ID to be the application's identifier URI, and that
value cannot be changed -- so SAML will not work until the tenant accepts it.

An administrator needs to relax the identifier URI restriction for this tenant,
or grant this application an exemption. See:
  https://aka.ms/identifier-uri-formatting-error

Microsoft's own message is printed directly above this one."
        exit 1
    }
    Write-Host "Identifier URI set."
}

# -- STEP 1 -- App registration ------------------------------------------------

Write-Host ""
Write-Host "Step 1/5 -- Checking for existing app registration '$AppName'..."

# A failed lookup must not fall through to the create branch. "Could not tell"
# and "does not exist" are different answers, and treating the first as the
# second creates a second app registration alongside the working one.
$appList = Invoke-Az @('ad', 'app', 'list', '--display-name', $AppName, '--query', '[0]')
if ($appList.ExitCode -ne 0) {
    Write-Error "ERROR: could not list app registrations -- az reported the reason above.
Re-running is safe; this stops rather than risk creating a duplicate of '$AppName'."
    exit 1
}
$existingApp = if ($appList.Output) { $appList.Output | ConvertFrom-Json } else { $null }

if ($existingApp) {
    $ClientId = $existingApp.appId
    Write-Host "App already exists. App ID: $ClientId"

    Write-Host "Updating redirect URI to match current Cognito config..."
    $update = Invoke-Az @('ad', 'app', 'update', '--id', $ClientId, '--web-redirect-uris', $CognitoAcsUrl)
    if ($update.ExitCode -ne 0) {
        Write-Error "ERROR: could not set the redirect URI on app $ClientId.
Cognito posts its SAML response to $CognitoAcsUrl -- sign-in fails without it."
        exit 1
    }

    Set-IdentifierUri -ClientId $ClientId -Uri $CognitoEntityId
} else {
    Write-Host "Creating app registration '$AppName'..."
    $ClientId = az ad app create `
        --display-name "$AppName" `
        --sign-in-audience "AzureADMyOrg" `
        --web-redirect-uris $CognitoAcsUrl `
        --query "appId" -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $ClientId) {
        Write-Error "ERROR: could not create the app registration."
        exit 1
    }
    Write-Host "App created. App ID: $ClientId"

    Set-IdentifierUri -ClientId $ClientId -Uri $CognitoEntityId
}

# -- STEP 2 -- Service principal with SAML SSO mode ---------------------------

Write-Host ""
Write-Host "Step 2/5 -- Checking for existing service principal..."

$spList = Invoke-Az @('ad', 'sp', 'list', '--filter', "appId eq '$ClientId'", '--query', '[0]')
if ($spList.ExitCode -ne 0) {
    Write-Error "ERROR: could not list service principals -- az reported the reason above."
    exit 1
}
$existingSp = if ($spList.Output) { $spList.Output | ConvertFrom-Json } else { $null }

if ($existingSp) {
    $SpObjectId = $existingSp.id
    Write-Host "Service principal already exists. Object ID: $SpObjectId"
} else {
    Write-Host "Creating service principal..."
    $SpObjectId = az ad sp create --id $ClientId --query "id" -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $SpObjectId) {
        Write-Error "ERROR: could not create the service principal for app $ClientId."
        exit 1
    }
    Write-Host "Service principal created. Object ID: $SpObjectId"
}

Write-Host "Setting single sign-on mode to SAML..."
$ssoBody = @{
    preferredSingleSignOnMode = "saml"
    loginUrl                  = $CognitoSignOnUrl
    appRoleAssignmentRequired = $false
}

# The Entra portal's "Enterprise applications" list defaults to filtering on
# Application type = Enterprise Applications, which shows only service
# principals carrying this tag. One created by the CLI has no tags, so it is
# invisible there -- the administrator sees the app registration and concludes
# the enterprise application was never created. It was; the list is filtered.
#
# Tags are replaced wholesale by PATCH, so any already present are carried
# forward rather than overwritten.
$PortalTag = 'WindowsAzureActiveDirectoryIntegratedApp'
$currentTags = @()
if ($existingSp -and $existingSp.tags) { $currentTags = @($existingSp.tags) }

if ($currentTags -notcontains $PortalTag) {
    $ssoBody['tags'] = @($currentTags + $PortalTag)
    Write-Host "Tagging as an enterprise application so it appears in the portal list..."
}

Invoke-GraphJson -Method PATCH `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId" `
    -Body $ssoBody | Out-Null
Write-Host "SAML SSO mode set."

# -- Claims: guarantee an emailaddress claim -----------------------------------
#
# An application created through Graph has no claims configuration, because the
# portal's SAML wizard is what normally writes one and these apps never go near
# it. Entra then emits only its implicit defaults, which for a member account do
# NOT include emailaddress -- even when the user's mail attribute is populated.
#
# Cognito requires an email to create a federated user, and GitOps Manager
# matches that email against its own user records, so an assertion without one
# fails at sign-in with "Invalid user attributes: emails: The attribute emails is
# required" -- a message that points at Cognito and hides the cause entirely.
#
# Guest accounts get an emailaddress anyway, resolved from their home identity,
# which is why a tenant whose operator is a guest appears to work and a tenant of
# ordinary members does not.
#
# IncludeBasicClaimSet keeps everything Entra already emits; this only adds the
# one claim that is missing.
$ClaimsPolicyName = "GitOpsManager-SAML-EmailClaim"
$ClaimsDefinition = '{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true","ClaimsSchema":[{"Source":"user","ID":"mail","SamlClaimType":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"}]}}'

Write-Host "Ensuring the application emits an emailaddress claim..."

$policyList = Invoke-GraphJson -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies"
$ClaimsPolicy = $policyList.value | Where-Object { $_.displayName -eq $ClaimsPolicyName } | Select-Object -First 1

if (-not $ClaimsPolicy) {
    $ClaimsPolicy = Invoke-GraphJson -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies" `
        -Body @{
            displayName           = $ClaimsPolicyName
            isOrganizationDefault = $false
            definition            = @($ClaimsDefinition)
        }
    Write-Host "Created claims policy '$ClaimsPolicyName'."
} else {
    Write-Host "Reusing existing claims policy '$ClaimsPolicyName'."
}

# A service principal takes at most one claims mapping policy. If something else
# already owns that slot, replacing it would silently change whatever configured
# it -- so say so and stop rather than guess.
$assigned = Invoke-GraphJson -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId/claimsMappingPolicies"
$assignedPolicy = $assigned.value | Select-Object -First 1

if (-not $assignedPolicy) {
    Invoke-GraphJson -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId/claimsMappingPolicies/`$ref" `
        -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$($ClaimsPolicy.id)" } | Out-Null
    Write-Host "Claims policy assigned."
} elseif ($assignedPolicy.id -eq $ClaimsPolicy.id) {
    Write-Host "Claims policy already assigned."
} else {
    Write-Error "ERROR: this application already has a different claims mapping policy assigned:
  '$($assignedPolicy.displayName)' ($($assignedPolicy.id))

A service principal can hold only one. Replacing it could break whatever
configured it, so this script will not do so. Check that policy emits an
emailaddress claim sourced from the user's mail attribute, or merge this claim
into it:

  $ClaimsDefinition"
    exit 1
}

# -- STEP 3 -- Token signing certificate ---------------------------------------

Write-Host ""
Write-Host "Step 3/5 -- Checking for existing token signing certificate..."

# Signing certificates live in the service principal's keyCredentials. There is
# NO /tokenSigningCertificates navigation property to GET -- asking for one
# returns "Resource 'tokenSigningCertificates' does not exist", every time,
# certificate or not. An earlier version of this script read that 404 as "none
# yet" and so minted a brand new certificate on every single run.
#
# Each certificate appears as two entries: usage "Verify" (the public half,
# which is the only one Graph returns a key for) and usage "Sign".
$spUri = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=keyCredentials,preferredTokenSigningKeyThumbprint' -f $SpObjectId
$spResult = Invoke-Az @('rest', '--method', 'GET', '--uri', $spUri)
if ($spResult.ExitCode -ne 0) {
    Write-Error "ERROR: could not read the service principal's certificates -- az reported the reason above."
    exit 1
}
$spInfo = $spResult.Output | ConvertFrom-Json

# A certificate inside the last 30 days does not count as reusable, so re-running
# this close to expiry issues a replacement instead. That is the whole rotation
# path: GitOps Manager warns from 30 days out, the operator re-runs, a new
# certificate is issued, made active and reported. Reusing anything still
# technically valid would leave that warning with no action that clears it.
$nowUtc      = (Get-Date).ToUniversalTime()
$rotateBefore = $nowUtc.AddDays(30)

$existingCerts = @($spInfo.keyCredentials | Where-Object {
    $_.usage -eq 'Verify' -and
    $_.type  -eq 'AsymmetricX509Cert' -and
    $_.key -and
    ([datetime]$_.endDateTime).ToUniversalTime() -gt $rotateBefore
})

# Distinguishes "first run" from "rotating" in the message below.
$expiringCerts = @($spInfo.keyCredentials | Where-Object {
    $_.usage -eq 'Verify' -and
    $_.type  -eq 'AsymmetricX509Cert' -and
    ([datetime]$_.endDateTime).ToUniversalTime() -le $rotateBefore
})

if ($existingCerts.Count -gt 0) {
    $activeCert = $existingCerts |
        Sort-Object { [datetime]$_.endDateTime } -Descending |
        Select-Object -First 1

    Write-Host "Reusing existing signing certificate. Expires: $($activeCert.endDateTime)"
    $CertValue = $activeCert.key

    if ($existingCerts.Count -gt 1) {
        # The portal cannot fix this. Its SAML certificate UI is only offered for
        # non-gallery applications; an app registered in this same tenant gets the
        # OpenID Connect page instead, with no certificate list at all.
        Write-Host ""
        Write-Host "NOTE: this application has $($existingCerts.Count) valid signing certificates, and the"
        Write-Host "      federation metadata advertises every one of them. Earlier versions of"
        Write-Host "      this script added one per run."
        Write-Host ""
        Write-Host "      Sign-in is unaffected -- the active certificate signs, and the rest are"
        Write-Host "      accepted but unused. To get back to one, delete this application and"
        Write-Host "      re-run this script; it is idempotent and will create exactly one."
        if (-not $spInfo.preferredTokenSigningKeyThumbprint) {
            Write-Host "      No active certificate is designated, so which one signs is undefined."
        }
        Write-Host ""
    }
} else {
    if ($expiringCerts.Count -gt 0) {
        $soonest = $expiringCerts |
            Sort-Object { [datetime]$_.endDateTime } -Descending |
            Select-Object -First 1
        $daysLeft = [int][math]::Ceiling((([datetime]$soonest.endDateTime).ToUniversalTime() - $nowUtc).TotalDays)

        Write-Host ""
        if ($daysLeft -le 0) {
            Write-Host "The existing signing certificate EXPIRED on $($soonest.endDateTime)."
        } else {
            Write-Host "The existing signing certificate expires in $daysLeft day(s), on $($soonest.endDateTime)."
        }
        Write-Host "Issuing a replacement and making it the active signing key."
        Write-Host "The old certificate stays until it expires, so sign-in is not interrupted."
        Write-Host ""
    }

    Write-Host "Creating self-signed token signing certificate..."
    $expiry = (Get-Date).AddYears(3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $certResult = Invoke-GraphJson -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId/addTokenSigningCertificate" `
        -Body @{
            displayName = "CN=EKS Manager SAML Signing"
            endDateTime = $expiry
        }

    $CertValue = $certResult.key
    if (-not $CertValue) {
        Write-Error "ERROR: the certificate call returned no key -- nothing to report to GitOps Manager."
        exit 1
    }

    # Name it the active signing key. Without this the tenant leaves the choice
    # undefined, and the certificate reported to GitOps Manager may not be the
    # one Entra actually signs assertions with.
    if ($certResult.thumbprint) {
        Invoke-GraphJson -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpObjectId" `
            -Body @{ preferredTokenSigningKeyThumbprint = $certResult.thumbprint } | Out-Null
    }

    Write-Host "Certificate created."
}

# -- STEP 4 -- Get M2M bearer token --------------------------------------------

Write-Host ""
Write-Host "Step 4/5 -- Obtaining M2M bearer token..."

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

# -- STEP 5 -- Report SAML status to EKS Manager ---------------------------

Write-Host ""
Write-Host "Step 5/5 -- Reporting SAML configuration to EKS Manager..."

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
    Invoke-RestMethod -Method Post `
        -Uri "$EksManagerApiUrl/config/saml/status" `
        -Headers @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" } `
        -Body $statusBody | Out-Null
} catch {
    # $_.Exception.Message is only ever "The remote server returned an error:
    # (500) Internal Server Error." The endpoint returns an RFC 7807 problem
    # document naming the actual cause -- a failed stored procedure, a denied
    # Cognito call -- and that body is what is worth reading. PowerShell 7 puts
    # it in ErrorDetails; 5.1 leaves it on the response stream.
    $detail = $_.ErrorDetails.Message
    if (-not $detail -and $_.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $detail = $reader.ReadToEnd()
            $reader.Close()
        } catch { }
    }

    Write-Error "ERROR: Failed to report SAML status to EKS Manager.
$($_.Exception.Message)

The server replied:
$detail

The Entra side is complete and correct -- the app registration, SAML mode and
signing certificate are all in place. Only the report to GitOps Manager failed,
so re-running this script once the cause is fixed will not create anything new."
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
