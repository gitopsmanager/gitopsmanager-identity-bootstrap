# Copyright (c) 2026 GitOps Manager, S.L. All rights reserved.
<#
.SYNOPSIS
    Creates the two Entra applications Headlamp needs and stores their
    credentials.

.DESCRIPTION
    headlamp                          the OIDC client that signs users in
    gitopsmanager-headlamp-patch-url  owns the above; patches its redirect URIs

    Talks to Entra, Key Vault and Secrets Manager directly. GitOps Manager is
    told only metadata -- application IDs and credential expiry dates -- so no
    customer secret ever reaches its database.

    Safe to re-run. See "Secret resolution" below for why, and for the one
    case where it deliberately refuses.

    This is the PowerShell twin of create-headlamp-app.sh. It needs no python3
    and no curl -- only the Azure CLI, and the AWS CLI when -EnableAws is used.

.PARAMETER KeyVault
    Store the credentials in this Key Vault. Requires an Azure subscription.

.PARAMETER EnableAws
    Store them in AWS Secrets Manager.

.PARAMETER HeadlampId
    Name the Headlamp application directly instead of searching by display
    name. Use when more than one application shares the name.

.PARAMETER Trust
    azure or aws. Resolves a disagreement between the two stores that cannot
    be settled from credential hints.

.NOTES
    PREREQUISITES
      - Azure CLI (az), authenticated. A tenant is enough -- an installation
        with no Azure subscription signs in with:
            az login --allow-no-subscriptions
        App registrations are directory objects, not Azure resources.
      - AWS CLI, authenticated, when using -EnableAws
      - Rights to create app registrations and service principals
        (Cloud Application Administrator or higher)

    USAGE
      Paste the block from Settings -> Terraform tile -> Pipeline credentials
      first, then:

        .\create-headlamp-app.ps1 -KeyVault <name>              # Azure
        .\create-headlamp-app.ps1 -EnableAws                    # AWS
        .\create-headlamp-app.ps1 -KeyVault <name> -EnableAws   # both
#>

[CmdletBinding()]
param(
    [string] $KeyVault,
    [switch] $EnableAws,
    [string] $HeadlampId,
    [ValidateSet("azure", "aws")]
    [string] $Trust
)

$ErrorActionPreference = "Stop"

if (-not $KeyVault -and -not $EnableAws) {
    Write-Error "Nothing to do -- pass -KeyVault, -EnableAws, or both."
    exit 1
}

# -- CONFIGURATION -------------------------------------------------------------

$AppName             = "headlamp"
$PatchAppName        = "gitopsmanager-headlamp-patch-url"

$KvOidcName          = "global-headlamp-oidc"
$KvPatchName         = "global-headlamp-patch-url"
$SmOidcName          = "/EKSManagerBootstrap/headlamp-oidc"
$SmPatchName         = "/EKSManagerBootstrap/headlamp-patch-url"

$K8sSecretName       = "headlamp-oidc"
$K8sNamespace        = "headlamp"
$SecretYearsValid    = 2
# Two names: Key Vault names cannot contain slashes, and the AWS probe has to
# sit where a scoped policy can see it. A probe outside
# /EKSManagerBootstrap/headlamp-* would fail preflight on an operator whose
# permissions are correct.
$KvProbeName         = "gitopsmanager-preflight-probe"
$SmProbeName         = "/EKSManagerBootstrap/headlamp-preflight-probe"

# Fixed Microsoft identifier used as the access-token audience. Not tenant
# specific, and not a secret.
$ValidatorClientId   = "6dae42f8-4368-4678-94ff-3960e28e3630"

$EksManagerApiUrl       = $env:EKSMANAGER_API_URL
$EksManagerCognitoUrl   = $env:EKSMANAGER_COGNITO_URL
$EksManagerClientId     = $env:EKSMANAGER_CLIENT_ID
$EksManagerClientSecret = $env:EKSMANAGER_CLIENT_SECRET

function Write-Step  { param($m) Write-Host "" ; Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Good  { param($m) Write-Host "[OK] $m"   -ForegroundColor Green }
function Write-Warn2 { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Stop-With   { param($m) Write-Error $m ; exit 1 }

function ConvertTo-B64 { param([string]$s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
function ConvertFrom-B64 { param([string]$s) [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }

# Offers to install a missing CLI rather than just naming it. Asks first --
# installing software on someone's machine is not something to do because a
# script felt like it.
function Install-CliIfMissing {
    param(
        [string] $Command,
        [string] $FriendlyName,
        [string] $WingetId,
        [string] $ManualUrl
    )

    if (Get-Command $Command -ErrorAction SilentlyContinue) { return }

    Write-Host ""
    Write-Warn2 "$FriendlyName is not installed."

    # Never prompt where nothing can answer. A script that hangs waiting for
    # input inside automation is worse than one that fails with instructions.
    if (-not [Environment]::UserInteractive) {
        Stop-With "$FriendlyName is required. Install it from $ManualUrl and re-run."
    }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Stop-With "$FriendlyName is required, and winget is not available on this machine to install it. Install from $ManualUrl and re-run."
    }

    Write-Host ""
    Write-Host "    winget install -e --id $WingetId" -ForegroundColor Cyan
    Write-Host ""
    $answer = Read-Host "Type 'yes' to run that now, or anything else to stop"
    if ($answer -ne "yes") {
        Stop-With "$FriendlyName is required. Install it from $ManualUrl and re-run."
    }

    winget install -e --id $WingetId --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Stop-With "winget did not complete successfully. Install $FriendlyName from $ManualUrl and re-run."
    }

    # winget writes the new location into the machine PATH, but this process
    # inherited its environment at launch and will not see it. Refresh here
    # rather than telling the operator to reopen a shell and start again.
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")

    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Stop-With "$FriendlyName installed, but '$Command' is still not on PATH. Open a new PowerShell session and re-run."
    }
    Write-Good "$FriendlyName installed."
}

# =============================================================================
# PREFLIGHT
#
# All of this runs before anything is created. The ordering is the point, not
# politeness: Entra reveals a client secret exactly once, so minting one and
# then failing to store it leaves an application holding a credential nobody
# has. That is the only unrecoverable failure here, and proving the writes
# first avoids it entirely.
# =============================================================================

Write-Step "Preflight: Entra"

Install-CliIfMissing -Command "az" -FriendlyName "Azure CLI" `
    -WingetId "Microsoft.AzureCLI" -ManualUrl "https://aka.ms/installazurecliwindows"

try   { $account = az account show 2>$null | ConvertFrom-Json }
catch { $account = $null }
if (-not $account) {
    Stop-With "Not signed in to Azure. Run 'az login', or 'az login --allow-no-subscriptions' if this tenant has no subscription."
}
$TenantId = $account.tenantId

az ad app list --top 1 --query "[0].appId" -o tsv 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Stop-With "Cannot read applications in tenant $TenantId. Check your directory role."
}
Write-Good "Tenant $TenantId, directory readable."

Write-Step "Preflight: GitOps Manager API"
$missing = @()
foreach ($pair in @(
    @{ n = "EKSMANAGER_API_URL";       v = $EksManagerApiUrl },
    @{ n = "EKSMANAGER_COGNITO_URL";   v = $EksManagerCognitoUrl },
    @{ n = "EKSMANAGER_CLIENT_ID";     v = $EksManagerClientId },
    @{ n = "EKSMANAGER_CLIENT_SECRET"; v = $EksManagerClientSecret })) {
    if ([string]::IsNullOrWhiteSpace($pair.v)) { $missing += $pair.n }
}
if ($missing.Count -gt 0) {
    Stop-With "Not set: $($missing -join ', '). Paste the credentials block from Settings -> Terraform tile."
}

try {
    $tokenResponse = Invoke-RestMethod -Method Post -Uri "$EksManagerCognitoUrl/oauth2/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $EksManagerClientId
            client_secret = $EksManagerClientSecret
        }
    $ApiToken = $tokenResponse.access_token
} catch {
    Stop-With "Could not obtain an M2M token: $($_.Exception.Message). Check the pipeline credentials and that this host is allowlisted."
}
if (-not $ApiToken) { Stop-With "Token endpoint returned no access_token." }
Write-Good "API reachable, token obtained."

if ($KeyVault) {
    Write-Step "Preflight: Key Vault '$KeyVault'"
    az keyvault show --name $KeyVault --query "name" -o tsv 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-With "Key Vault '$KeyVault' not found or not accessible." }

    # Prove write, do not assume it.
    az keyvault secret set --vault-name $KeyVault --name $KvProbeName --value "probe" --output none 2>$null
    if ($LASTEXITCODE -ne 0) {
        Stop-With "Cannot write to Key Vault '$KeyVault'. Grant Key Vault Secrets Officer and retry."
    }
    az keyvault secret delete --vault-name $KeyVault --name $KvProbeName --output none 2>$null | Out-Null
    Write-Good "Key Vault writable."
}

if ($EnableAws) {
    Write-Step "Preflight: AWS Secrets Manager"
    Install-CliIfMissing -Command "aws" -FriendlyName "AWS CLI" `
        -WingetId "Amazon.AWSCLI" -ManualUrl "https://aws.amazon.com/cli/"

    $AwsAccount = aws sts get-caller-identity --query "Account" --output text 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $AwsAccount) { Stop-With "No usable AWS credentials. Sign in, then retry." }

    $AwsRegion = if ($env:AWS_REGION) { $env:AWS_REGION }
                 elseif ($env:AWS_DEFAULT_REGION) { $env:AWS_DEFAULT_REGION }
                 else { aws configure get region 2>$null }
    if (-not $AwsRegion) { Stop-With "No AWS region resolved. Set AWS_REGION and retry." }

    # This writes to Secrets Manager and uses EKSManagerCMK, both of which live
    # in the SHARED SERVICES account. Nothing is assumed to get there -- so the
    # session has to be the right one to begin with, and this check is the only
    # thing standing between a wrong session and a secret in the wrong account.
    if ($env:EKSMANAGER_AWS_ACCOUNT_ID -and $env:EKSMANAGER_AWS_ACCOUNT_ID -ne $AwsAccount) {
        Stop-With @"
Wrong AWS account.

    Signed in to : $AwsAccount
    Expected     : $($env:EKSMANAGER_AWS_ACCOUNT_ID)  (shared services)

Sign in with credentials for the shared services account and re-run. This
script does not assume a role to get there.

Worth knowing: setup-pipeline.ps1 runs from the MANAGEMENT account. This one
does not, which is an easy thing to carry over out of habit.
"@
    }
    if ($env:EKSMANAGER_AWS_REGION -and $env:EKSMANAGER_AWS_REGION -ne $AwsRegion) {
        Stop-With "AWS region is $AwsRegion but this installation expects $($env:EKSMANAGER_AWS_REGION)."
    }
    if (-not $env:EKSMANAGER_AWS_ACCOUNT_ID) {
        Write-Warn2 "The expected account was not supplied in the environment, so this session cannot be checked."
        Write-Warn2 "About to write to $AwsAccount / $AwsRegion -- confirm that is your shared services account."
    }

    # Proves the write path and kms:GenerateDataKey on EKSManagerCMK end to end.
    aws secretsmanager create-secret --name $SmProbeName --secret-string "probe" --region $AwsRegion 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        aws secretsmanager put-secret-value --secret-id $SmProbeName --secret-string "probe" --region $AwsRegion 2>$null | Out-Null
    }
    if ($LASTEXITCODE -ne 0) {
        Stop-With "Cannot write to Secrets Manager in $AwsAccount / $AwsRegion (check secretsmanager and kms permissions)."
    }
    aws secretsmanager delete-secret --secret-id $SmProbeName --force-delete-without-recovery --region $AwsRegion 2>$null | Out-Null
    Write-Good "Secrets Manager writable in $AwsAccount / $AwsRegion."
}

# =============================================================================
# APPLICATIONS
# =============================================================================

# Entra does not enforce unique display names. Configuring the wrong
# application -- disabling assignment-required on something unrelated, granting
# it a Graph role -- is far worse than refusing, so ambiguity stops.
function Resolve-App {
    param([string]$DisplayName, [string]$Override)

    if ($Override) {
        $byId = az ad app list --filter "appId eq '$Override'" --query "[].appId" -o tsv 2>$null
        if (-not $byId) { Stop-With "No application found with appId $Override." }
        return $Override
    }

    $ids = @(az ad app list --display-name $DisplayName --query "[].appId" -o tsv 2>$null | Where-Object { $_ })
    if ($ids.Count -gt 1) {
        Stop-With ("More than one application is named '$DisplayName':`n  " + ($ids -join "`n  ") +
                   "`nRe-run with -HeadlampId <appId> naming the one you mean.")
    }
    if ($ids.Count -eq 1) { return $ids[0] }
    return $null
}

function New-AppIfMissing {
    param([string]$DisplayName, [string]$AppId)
    if ($AppId) { Write-Warn2 "Application '$DisplayName' exists ($AppId). Reusing it."; return $AppId }
    Write-Step "Creating application '$DisplayName'..."
    $newId = az ad app create --display-name $DisplayName --query "appId" -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $newId) { Stop-With "Could not create '$DisplayName'. Check your directory role." }
    Write-Good "Created. App ID: $newId"
    return $newId
}

function Get-OrCreateSp {
    param([string]$AppId)
    $spId = az ad sp list --filter "appId eq '$AppId'" --query "[0].id" -o tsv 2>$null
    if (-not $spId -or $spId -eq "None") {
        $spId = az ad sp create --id $AppId --query "id" -o tsv
        Write-Good "Service principal created: $spId"
    }
    return $spId
}

Write-Step "Resolving '$AppName'"
$AppId       = New-AppIfMissing -DisplayName $AppName -AppId (Resolve-App -DisplayName $AppName -Override $HeadlampId)
$SpObjectId  = Get-OrCreateSp -AppId $AppId
$AppObjectId = az ad app show --id $AppId --query "id" -o tsv

Write-Step "Asserting sign-in configuration on '$AppName'"

if ((az ad sp show --id $SpObjectId --query "appRoleAssignmentRequired" -o tsv 2>$null) -ne "false") {
    az ad sp update --id $SpObjectId --set "appRoleAssignmentRequired=false" | Out-Null
    Write-Good "Assignment required disabled."
}

if ((az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        --query "api.requestedAccessTokenVersion" -o tsv 2>$null) -ne "2") {
    az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        --body '{"api": {"requestedAccessTokenVersion": 2}}' | Out-Null
    Write-Good "Access token version set to v2.0."
}

if ((az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        --query "groupMembershipClaims" -o tsv 2>$null) -ne "SecurityGroup") {
    az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        --body '{"groupMembershipClaims": "SecurityGroup"}' | Out-Null
    Write-Good "groupMembershipClaims set to SecurityGroup."
}

# Separate from the Headlamp application deliberately. Adding a redirect URI IS
# the sensitive operation -- a callback pointing at someone else's
# infrastructure harvests authorization codes for every user who signs in. If
# Headlamp owned itself, one leaked secret would buy both.
Write-Step "Resolving '$PatchAppName'"
$PatchAppId = New-AppIfMissing -DisplayName $PatchAppName -AppId (Resolve-App -DisplayName $PatchAppName -Override "")
$PatchSpId  = Get-OrCreateSp -AppId $PatchAppId

$owners = az ad app owner list --id $AppId --query "[?id=='$PatchSpId'].id" -o tsv 2>$null
if (-not $owners) {
    az ad app owner add --id $AppId --owner-object-id $PatchSpId | Out-Null
    Write-Good "'$PatchAppName' added as owner of '$AppName'."
}

# Application.ReadWrite.OwnedBy is the narrowest permission Graph offers --
# there is no scope for "manage redirect URIs only". It confines the caller to
# applications it owns, plus any it creates.
$graphSp        = az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "id" -o tsv
$ownedByRoleId  = az ad sp show --id 00000003-0000-0000-c000-000000000000 `
                    --query "appRoles[?value=='Application.ReadWrite.OwnedBy'].id" -o tsv
$existingGrant  = az rest --method GET `
                    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PatchSpId/appRoleAssignments" `
                    --query "value[?appRoleId=='$ownedByRoleId'].id" -o tsv 2>$null
if (-not $existingGrant) {
    $grantBody = @{ principalId = $PatchSpId; resourceId = $graphSp; appRoleId = $ownedByRoleId } | ConvertTo-Json -Compress
    az rest --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PatchSpId/appRoleAssignments" `
        --body $grantBody | Out-Null
    Write-Good "Application.ReadWrite.OwnedBy granted."
}

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

function Get-KvDoc { param($Name)
    if (-not $KeyVault) { return $null }
    $v = az keyvault secret show --vault-name $KeyVault --name $Name --query "value" -o tsv 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return $v
}

function Get-SmDoc { param($Name)
    if (-not $EnableAws) { return $null }
    $v = aws secretsmanager get-secret-value --secret-id $Name --region $AwsRegion --query "SecretString" --output text 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return $v
}

# Entra returns a hint -- the first characters -- for every credential on an
# application. The values themselves are never returned, but the hint is enough
# to tell a live credential from a stale stored copy.
function Test-SecretLive {
    param([string]$AppId, [string]$Value)
    if (-not $Value) { return $false }
    $hints = @(az ad app credential list --id $AppId --query "[].hint" -o tsv 2>$null)
    return $hints -contains $Value.Substring(0, [Math]::Min(3, $Value.Length))
}

function Resolve-Secret {
    param([string]$AppId, [string]$Label, [string]$AzureValue, [string]$AwsValue)

    if ($AzureValue -and $AwsValue -and $AzureValue -ne $AwsValue) {
        $azLive  = Test-SecretLive -AppId $AppId -Value $AzureValue
        $awsLive = Test-SecretLive -AppId $AppId -Value $AwsValue

        if ($azLive -and -not $awsLive) {
            Write-Warn2 "${Label}: the Secrets Manager copy is no longer a live credential. Using Key Vault."
            return @{ Secret = $AzureValue; Origin = "key vault" }
        }
        if ($awsLive -and -not $azLive) {
            Write-Warn2 "${Label}: the Key Vault copy is no longer a live credential. Using Secrets Manager."
            return @{ Secret = $AwsValue; Origin = "secrets manager" }
        }
        if (-not $azLive -and -not $awsLive) {
            Stop-With "${Label}: neither stored secret matches a live credential on the application. Both are stale -- this needs a deliberate rotation."
        }

        # Both live. Someone added a secret without updating both sides;
        # nothing is broken, but only the operator can say which should win.
        switch ($Trust) {
            "azure" { return @{ Secret = $AzureValue; Origin = "key vault (-Trust azure)" } }
            "aws"   { return @{ Secret = $AwsValue;   Origin = "secrets manager (-Trust aws)" } }
            default {
                Stop-With "${Label}: Key Vault and Secrets Manager hold different secrets and both are live. Re-run with -Trust azure or -Trust aws, then remove the losing credential from the application so this does not recur."
            }
        }
    }

    if ($AzureValue) { return @{ Secret = $AzureValue; Origin = "key vault" } }
    if ($AwsValue)   { return @{ Secret = $AwsValue;   Origin = "secrets manager" } }

    $credCount = az ad app credential list --id $AppId --query "length(@)" -o tsv 2>$null
    if ($credCount -and [int]$credCount -gt 0) {
        Stop-With "$Label already has $credCount client secret(s), and Entra does not return one after creation. No enabled store holds it, so it cannot be recovered.`n`nRe-run including the store that does hold it, or rotate deliberately -- a rotation invalidates the credential every running Headlamp is using and needs every cluster refreshed."
    }

    Write-Step "Minting a client secret for $Label (valid $SecretYearsValid years)..."
    $endDate = (Get-Date).ToUniversalTime().AddYears($SecretYearsValid).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $pwd = az ad app credential reset --id $AppId --display-name $Label --end-date $endDate --query "password" -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $pwd) { Stop-With "Could not create a client secret for $Label." }
    Write-Good "Created."
    return @{ Secret = $pwd; Origin = "minted" }
}

Write-Step "Resolving credentials"

$kvOidcDoc  = Get-KvDoc $KvOidcName
$kvPatchDoc = Get-KvDoc $KvPatchName
$smOidcDoc  = Get-SmDoc $SmOidcName
$smPatchDoc = Get-SmDoc $SmPatchName

function Get-ManifestSecret { param($Doc)
    if (-not $Doc) { return $null }
    try { return ConvertFrom-B64 (($Doc | ConvertFrom-Json).data.clientSecret) } catch { return $null }
}
function Get-JsonField { param($Doc, $Field)
    if (-not $Doc) { return $null }
    try { return ($Doc | ConvertFrom-Json).$Field } catch { return $null }
}

$headlamp = Resolve-Secret -AppId $AppId -Label $AppName `
    -AzureValue (Get-ManifestSecret $kvOidcDoc) -AwsValue (Get-ManifestSecret $smOidcDoc)
$patch = Resolve-Secret -AppId $PatchAppId -Label $PatchAppName `
    -AzureValue (Get-JsonField $kvPatchDoc "clientSecret") -AwsValue (Get-JsonField $smPatchDoc "clientSecret")

# =============================================================================
# WRITE TO STORES
# =============================================================================

# All seven keys are always present, even when empty. The deployment reads them
# with secretKeyRef and no `optional: true`, so a missing key does not fall
# back to a default -- the pod fails with CreateContainerConfigError.
function New-Manifest {
    param([bool]$UseAccessToken)
    $scopes    = if ($UseAccessToken) { "$ValidatorClientId/user.read,openid,email,profile" } else { "openid,email,profile" }
    $validator = if ($UseAccessToken) { $ValidatorClientId } else { "" }
    $validIss  = if ($UseAccessToken) { "https://sts.windows.net/$TenantId/" } else { "" }

    [ordered]@{
        apiVersion = "v1"; kind = "Secret"; type = "Opaque"
        metadata   = [ordered]@{ name = $K8sSecretName; namespace = $K8sNamespace }
        data       = [ordered]@{
            clientID           = ConvertTo-B64 $AppId
            clientSecret       = ConvertTo-B64 $headlamp.Secret
            issuerURL          = ConvertTo-B64 "https://login.microsoftonline.com/$TenantId/v2.0"
            scopes             = ConvertTo-B64 $scopes
            validatorClientID  = ConvertTo-B64 $validator
            validatorIssuerURL = ConvertTo-B64 $validIss
            useAccessToken     = ConvertTo-B64 $(if ($UseAccessToken) { "true" } else { "false" })
        }
    } | ConvertTo-Json -Depth 5 -Compress
}

function New-PatchDoc {
    [ordered]@{ clientId = $PatchAppId; clientSecret = $patch.Secret; tenantId = $TenantId } |
        ConvertTo-Json -Depth 3 -Compress
}

$storesWritten = @()

if ($KeyVault) {
    Write-Step "Key Vault"
    $wantOidc  = New-Manifest -UseAccessToken $true
    $wantPatch = New-PatchDoc
    if ($wantOidc -ne $kvOidcDoc) {
        az keyvault secret set --vault-name $KeyVault --name $KvOidcName --value $wantOidc --output none
        Write-Good "$KvOidcName written."
    } else { Write-Good "$KvOidcName already current." }
    if ($wantPatch -ne $kvPatchDoc) {
        az keyvault secret set --vault-name $KeyVault --name $KvPatchName --value $wantPatch --output none
        Write-Good "$KvPatchName written."
    } else { Write-Good "$KvPatchName already current." }
    $storesWritten += "azure"
}

if ($EnableAws) {
    Write-Step "Secrets Manager"
    # useAccessToken is false on AWS: the EKS API server requires an aud claim
    # that Entra access tokens do not carry in the form it expects. The ID
    # token does, which makes the validator pair unnecessary -- but the keys stay.
    $wantOidc  = New-Manifest -UseAccessToken $false
    $wantPatch = New-PatchDoc

    function Set-SmSecret { param($Name, $Value)
        aws secretsmanager put-secret-value --secret-id $Name --secret-string $Value --region $AwsRegion 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            aws secretsmanager create-secret --name $Name --secret-string $Value --region $AwsRegion | Out-Null
            if ($LASTEXITCODE -ne 0) { Stop-With "Could not write $Name to Secrets Manager." }
        }
    }

    if ($wantOidc -ne $smOidcDoc) { Set-SmSecret $SmOidcName $wantOidc; Write-Good "$SmOidcName written." }
    else { Write-Good "$SmOidcName already current." }
    if ($wantPatch -ne $smPatchDoc) { Set-SmSecret $SmPatchName $wantPatch; Write-Good "$SmPatchName written." }
    else { Write-Good "$SmPatchName already current." }
    $storesWritten += "aws"
}

# =============================================================================
# REPORT METADATA
#
# No secrets. Application IDs and expiry dates only -- enough for the credential
# view, and nothing that would matter if it were logged. Entra sends no
# notification before an application client secret expires, so these dates are
# the only warning that will exist.
# =============================================================================

Write-Step "Reporting to GitOps Manager"

function Get-AppExpiry { param($AppId)
    az ad app credential list --id $AppId --query "[0].endDateTime" -o tsv 2>$null
}

$payload = [ordered]@{
    headlampAppId        = $AppId
    patchUrlAppId        = $PatchAppId
    tenantId             = $TenantId
    issuerURL            = "https://login.microsoftonline.com/$TenantId/v2.0"
    headlampSecretExpiry = (Get-AppExpiry $AppId)
    patchUrlSecretExpiry = (Get-AppExpiry $PatchAppId)
    storesWritten        = ($storesWritten -join ",")
} | ConvertTo-Json -Depth 3

try {
    Invoke-RestMethod -Method Post -Uri "$EksManagerApiUrl/config/headlamp/status" `
        -Headers @{ Authorization = "Bearer $ApiToken" } `
        -ContentType "application/json" -Body $payload | Out-Null
    Write-Good "Reported."
} catch {
    Write-Warn2 "Could not report to GitOps Manager: $($_.Exception.Message)"
    Write-Warn2 "The applications and secrets are in place; only the dashboard metadata is missing. Re-run to retry."
}

# -- SUMMARY -------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================"
Write-Host " Headlamp identity ready"
Write-Host "============================================================"
Write-Host " Tenant:        $TenantId"
Write-Host " $AppName"
Write-Host "   App ID:      $AppId"
Write-Host "   Secret:      $($headlamp.Origin)"
Write-Host " $PatchAppName"
Write-Host "   App ID:      $PatchAppId"
Write-Host "   Secret:      $($patch.Origin)"
Write-Host "   Owns:        $AppName (Application.ReadWrite.OwnedBy)"
Write-Host " Stores:        $(if ($storesWritten) { $storesWritten -join ',' } else { 'none' })"
Write-Host "============================================================"
