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

# Deliberately not "Stop". PowerShell 5.1 converts a native command's stderr
# into ErrorRecords whenever that stream is redirected -- 2>$null counts -- and
# under "Stop" the first such line becomes a terminating error. az writes
# warnings and ordinary "not found" messages to stderr all the time, so every
# "call az, then check $LASTEXITCODE" below would abort on output it was
# written to tolerate: probing Key Vault for a secret that is not there,
# listing credentials on an application that has none, reading tags off a new
# service principal.
#
# Native failures are caught explicitly instead -- every az call is followed by
# a $LASTEXITCODE test, and Invoke-GraphJson enforces it for Graph writes.
# Cmdlets whose silent failure would matter carry -ErrorAction Stop where they
# are called.
$ErrorActionPreference = "Continue"

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
# Write-Error wraps the message in PowerShell's error decoration -- the "At
# line:N char:M", the source extract, the CategoryInfo -- which buries a
# multi-line instruction the operator is meant to read and act on. Straight to
# stderr keeps the stream correct for CI without the noise.
function Stop-With   { param($m) [Console]::Error.WriteLine("`n[ERROR] $m`n") ; exit 1 }

function ConvertTo-B64 { param([string]$s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
function ConvertFrom-B64 { param([string]$s) [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }

# Every Graph write goes through here. PowerShell 5.1 does not escape embedded
# double quotes when handing an argument to a native executable, and this is
# true of a single-quoted literal just as much as a runtime-built string --
# '{"api": {"requestedAccessTokenVersion": 2}}' reaches az as
# {api: {requestedAccessTokenVersion: 2}} and Graph answers "Unable to read
# JSON request payload". Writing the body to a file and using az's documented
# @file syntax sidesteps the quoting entirely.
#
# The exit-code check is not optional. A failing native command does not throw
# -- $ErrorActionPreference has no effect on it -- so without this the caller
# carries straight on and prints its own success line over a write that never
# happened. That is how a missing Application.ReadWrite.OwnedBy grant would
# stay hidden until a cluster build failed with 403 hours later.
function Invoke-GraphJson {
    param(
        [ValidateSet("POST", "PATCH", "PUT")]
        [string] $Method,
        [string] $Uri,
        [object] $Body,
        [string] $ErrorMessage
    )

    # -ErrorAction Stop on both: a body file that silently failed to write would
    # be sent to Graph as an empty document, and an empty PATCH of "tags" or
    # "redirectUris" clears the property rather than failing.
    $bodyFile = New-TemporaryFile -ErrorAction Stop
    try {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Compress -Depth 5 }
        $json | Set-Content -Path $bodyFile.FullName -Encoding ascii -ErrorAction Stop

        az rest --method $Method --uri $Uri `
            --headers "Content-Type=application/json" `
            --body "@$($bodyFile.FullName)" | Out-Null

        if ($LASTEXITCODE -ne 0) { Stop-With $ErrorMessage }
    }
    finally { Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue }
}

# Offers to install everything missing rather than just naming it, and does so
# in one pass. Asks first -- installing software on someone's machine is not
# something to do because a script felt like it -- but asks once, with the full
# list. Handling one CLI per call meant an operator with neither installed
# installed the Azure CLI, re-ran, and only then learned the AWS CLI was also
# missing.
#
# $Required is a list of @{ Command; FriendlyName; WingetId; ManualUrl }.
function Install-MissingClis {
    param([array] $Required)

    $missing = @($Required | Where-Object { -not (Get-Command $_.Command -ErrorAction SilentlyContinue) })
    if ($missing.Count -eq 0) { return }

    Write-Host ""
    foreach ($m in $missing) { Write-Warn2 "$($m.FriendlyName) is not installed." }

    $manual = ($missing | ForEach-Object { "    $($_.FriendlyName): $($_.ManualUrl)" }) -join "`n"

    # Never prompt where nothing can answer. A script that hangs waiting for
    # input inside automation is worse than one that fails with instructions.
    if (-not [Environment]::UserInteractive) {
        Stop-With "Required, and not installed:`n`n$manual"
    }

    # Name how to get winget too. Sending someone to two vendor download pages
    # when one command would have done it is what this function exists to avoid,
    # and winget's absence is not obvious to fix if you have not met it before.
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Stop-With @"
Required, and not installed:

$manual

winget is not on this machine, so they cannot be installed for you. It ships as
"App Installer":

    Microsoft Store  ->  search "App Installer"
    or               ->  https://github.com/microsoft/winget-cli/releases

Install that and re-run to be offered both, or install each of the above by hand.
"@
    }

    Write-Host ""
    foreach ($m in $missing) {
        Write-Host "    winget install -e --id $($m.WingetId)" -ForegroundColor Cyan
    }
    Write-Host ""
    $what   = if ($missing.Count -gt 1) { "those $($missing.Count) commands" } else { "that" }
    $answer = Read-Host "Type 'yes' to run $what now, or anything else to stop"
    if ($answer -ne "yes") {
        Stop-With "Required, and not installed:`n`n$manual"
    }

    foreach ($m in $missing) {
        Write-Step "Installing $($m.FriendlyName)..."
        winget install -e --id $m.WingetId --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            Stop-With "winget did not install $($m.FriendlyName) successfully. Install it from $($m.ManualUrl) and re-run."
        }
    }

    # winget writes the new location into the machine PATH, but this process
    # inherited its environment at launch and will not see it. Refresh here
    # rather than telling the operator to reopen a shell and start again.
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")

    foreach ($m in $missing) {
        if (-not (Get-Command $m.Command -ErrorAction SilentlyContinue)) {
            Stop-With "$($m.FriendlyName) installed, but '$($m.Command)' is still not on PATH. Open a new PowerShell session and re-run."
        }
        Write-Good "$($m.FriendlyName) installed."
    }
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

# -----------------------------------------------------------------------------
# Sign-in gate
#
# Every cloud this run touches is proven here, and all failures are reported in
# one message. Checking each where it is first needed meant an operator signed
# in to neither fixed Azure, re-ran, sat through the Entra and API preflights,
# and only then learned AWS was missing too -- two round trips for one setup
# problem. -KeyVault needs Azure; -EnableAws needs AWS; Entra is always needed.
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# TLS trust
#
# az and aws are Python. They validate certificates against their own bundled
# CA list, not the Windows certificate store. On a corporate network that
# decrypts and re-signs TLS -- Zscaler, Netskope, and the like -- the browser
# accepts the re-signed certificate because the inspection root is installed in
# Windows, and both CLIs reject it. What the operator sees is a Python
# traceback in the middle of a preflight, which says nothing about the cause.
#
# Trusting what the machine already trusts is not a security downgrade, so this
# resolves it rather than reporting it: export the Windows roots to a PEM and
# point both CLIs at that. Verification stays on throughout -- nothing here
# passes --no-verify or AZURE_CLI_DISABLE_CONNECTION_VERIFICATION, which would
# turn off validation for a session that is about to read and write secrets.
# -----------------------------------------------------------------------------
function Test-TlsTrustFailure {
    param($Output)
    $t = ($Output | Out-String)
    return $t -match 'CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLError|SSLCertVerificationError|unable to get local issuer|self.signed certificate|SSL: '
}

# Names the interceptor in the failure message. .NET validates against the
# Windows store, so this succeeds where the CLIs fail -- which is the whole
# point: it can see the certificate they are refusing.
function Get-ServedCertIssuer {
    param([string] $Uri)
    try {
        $r = [System.Net.HttpWebRequest]::Create($Uri)
        $r.Timeout = 10000
        $r.ServerCertificateValidationCallback = { $true }
        try { $r.GetResponse().Dispose() } catch { }
        if ($r.ServicePoint.Certificate) { return $r.ServicePoint.Certificate.Issuer }
    } catch { }
    return $null
}

$script:CaBundleApplied = $false

function Set-CorporateCaBundle {
    if ($script:CaBundleApplied) { return $true }

    # An operator who has already pointed these somewhere gets left alone. A
    # bundle that is set but wrong is its own problem, and silently replacing
    # their choice would hide it.
    if ($env:REQUESTS_CA_BUNDLE -or $env:AWS_CA_BUNDLE -or $env:SSL_CERT_FILE) {
        Write-Warn2 "A CA bundle is already set in this session -- leaving it alone."
        Write-Warn2 "  REQUESTS_CA_BUNDLE = $env:REQUESTS_CA_BUNDLE"
        Write-Warn2 "  AWS_CA_BUNDLE      = $env:AWS_CA_BUNDLE"
        Write-Warn2 "  SSL_CERT_FILE      = $env:SSL_CERT_FILE"
        return $false
    }

    # Every scope, not just LocalMachine\Root. An inspection root can be
    # deployed to any of them -- a user-mode proxy agent puts it in
    # CurrentUser\Root, and some installers drop it in Personal -- and
    # exporting only the machine root store would miss the one certificate
    # that matters, producing a bundle of 60-odd public roots that fails in
    # exactly the same way. That is worse than not trying, because it looks
    # like the fix was applied.
    #
    # Deduplicated by thumbprint: the same root commonly appears in more than
    # one scope, and a PEM containing it twice is valid but confusing to read.
    $bundle  = Join-Path $env:USERPROFILE "gitopsmanager-ca-bundle.pem"
    $sb      = New-Object System.Text.StringBuilder
    $seen    = New-Object 'System.Collections.Generic.HashSet[string]'
    $notable = New-Object 'System.Collections.Generic.List[string]'

    # $seen, $sb and $notable are reference types deliberately: a nested
    # function shares the enclosing scope for reads, but assigning to a value
    # type here would create a local copy and silently lose the result.
    function Add-Pem {
        param($Cert, $Origin)
        if (-not $seen.Add($Cert.Thumbprint)) { return }
        [void]$sb.AppendLine("-----BEGIN CERTIFICATE-----")
        [void]$sb.AppendLine([Convert]::ToBase64String($Cert.RawData, 'InsertLineBreaks'))
        [void]$sb.AppendLine("-----END CERTIFICATE-----")
        # Anything outside the machine root store is worth naming, so the
        # operator can see the corporate root was picked up rather than having
        # to trust a count.
        if ($Origin -ne "LocalMachine\Root") { $notable.Add("$Origin -> $($Cert.Subject)") }
    }

    foreach ($scope in @("LocalMachine", "CurrentUser")) {
        foreach ($store in @("Root", "CA")) {
            foreach ($c in (Get-ChildItem "Cert:\$scope\$store" -ErrorAction SilentlyContinue)) {
                Add-Pem $c "$scope\$store"
            }
        }
    }

    # Personal, filtered to CA certificates only.
    #
    # Some proxy agents install their signing root into Personal rather than
    # Root, where nothing looking for trust anchors would find it. But Personal
    # is also where user identity lives -- client authentication certificates,
    # VPN certificates, national ID certificates -- and turning those into
    # trust anchors for every subsequent TLS call is not something to do by
    # accident. The basicConstraints CA flag separates the two exactly: a
    # misfiled signing root has it, an identity certificate does not. Only the
    # public certificate is read; private keys are never touched.
    foreach ($scope in @("LocalMachine", "CurrentUser")) {
        foreach ($c in (Get-ChildItem "Cert:\$scope\My" -ErrorAction SilentlyContinue)) {
            $bc = $c.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
            if (-not $bc) { continue }
            if (-not ([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$bc).CertificateAuthority) { continue }
            Add-Pem $c "$scope\My"
        }
    }
    $count = $seen.Count
    if ($count -eq 0) {
        Write-Warn2 "No trusted roots could be read from the Windows certificate store."
        return $false
    }

    try { [IO.File]::WriteAllText($bundle, $sb.ToString()) }
    catch { Write-Warn2 "Could not write $bundle -- $($_.Exception.Message)"; return $false }

    $env:REQUESTS_CA_BUNDLE = $bundle    # Azure CLI, and anything else on requests
    $env:AWS_CA_BUNDLE      = $bundle    # AWS CLI
    $script:CaBundleApplied = $true

    Write-Good "Exported $count trusted roots from the Windows store to $bundle."
    foreach ($n in $notable) { Write-Good "  includes: $n" }
    Write-Good "Both CLIs now validate against it. Retrying."
    return $true
}

# Emitted once, at the end, if the bundle was needed. Setting it for the
# session is enough to finish this run; saying so avoids the operator
# discovering tomorrow that it has come undone.
function Show-CaBundleAdvice {
    if (-not $script:CaBundleApplied) { return }
    Write-Host ""
    Write-Warn2 "This session is using an exported CA bundle because the network re-signs TLS."
    Write-Warn2 "It lasts for this window only. To keep it for future runs:"
    Write-Host ""
    Write-Host "    [Environment]::SetEnvironmentVariable('REQUESTS_CA_BUNDLE', '$env:REQUESTS_CA_BUNDLE', 'User')" -ForegroundColor Cyan
    Write-Host "    [Environment]::SetEnvironmentVariable('AWS_CA_BUNDLE',      '$env:AWS_CA_BUNDLE', 'User')" -ForegroundColor Cyan
}

Write-Step "Preflight: sign-in"

# Both are resolved before either is checked, so an operator starting from a
# bare machine is offered everything this run needs in one prompt.
$requiredClis = @(
    @{ Command = "az"; FriendlyName = "Azure CLI"; WingetId = "Microsoft.AzureCLI"
       ManualUrl = "https://aka.ms/installazurecliwindows" }
)
if ($EnableAws) {
    $requiredClis += @{ Command = "aws"; FriendlyName = "AWS CLI"; WingetId = "Amazon.AWSCLI"
                        ManualUrl = "https://aws.amazon.com/cli/" }
}
Install-MissingClis $requiredClis

$signInErrors = @()

$azOut = az account show 2>&1
if ($LASTEXITCODE -ne 0 -and (Test-TlsTrustFailure $azOut)) {
    Write-Host ""
    Write-Warn2 "The Azure CLI could not validate the TLS certificate chain."
    if (Set-CorporateCaBundle) { $azOut = az account show 2>&1 }
}

$account = $null
if ($LASTEXITCODE -eq 0) {
    try { $account = ($azOut | Out-String) | ConvertFrom-Json } catch { $account = $null }
}

if ($account) {
    $TenantId = $account.tenantId
    Write-Good "Azure: tenant $TenantId."
} elseif (Test-TlsTrustFailure $azOut) {
    $issuer = Get-ServedCertIssuer "https://login.microsoftonline.com/"
    $signInErrors += @"
Azure -- the CLI rejected the TLS certificate, and pointing it at the Windows
trust store did not resolve it.

    certificate issued by : $(if ($issuer) { $issuer } else { "could not be read" })

If that is not a Microsoft CA, this network re-signs TLS and the inspection
root is not in the Windows store either -- ask whoever runs it for the root
certificate, save it as a PEM, and set REQUESTS_CA_BUNDLE and AWS_CA_BUNDLE to
a file containing it. Do not disable certificate verification; this run reads
and writes client secrets.
"@
} else {
    $signInErrors += @"
Azure -- not signed in. The Entra applications live here, so this is always
required, with or without -EnableAws.

    az login
    az login --allow-no-subscriptions    # tenant with no subscription
"@
}

if ($EnableAws) {
    # REGION and SHARED_SERVICES_ACCOUNT_ID come from the same Settings ->
    # Terraform environment block as the EKSMANAGER_* credentials, so both are
    # required rather than best-effort. This writes to Secrets Manager and uses
    # EKSManagerCMK, both of which live in the SHARED SERVICES account, and
    # nothing here assumes a role to get there -- the session has to be the
    # right one to begin with. Treating the expected account as optional made
    # the check skip itself in exactly the case it exists to catch.
    $AwsRegion       = $env:REGION
    $ExpectedAccount = $env:SHARED_SERVICES_ACCOUNT_ID

    $unsetVars = @()
    if (-not $AwsRegion)       { $unsetVars += "REGION" }
    if (-not $ExpectedAccount) { $unsetVars += "SHARED_SERVICES_ACCOUNT_ID" }

    if ($unsetVars.Count -gt 0) {
        $signInErrors += "AWS -- not set: $($unsetVars -join ', ').`n`n" +
                         "    Paste the environment block from Settings -> Terraform tile."
    } else {
        # Every aws call passes --region explicitly; this covers the CLI's own
        # need for one on calls that do not, sts included.
        $env:AWS_REGION = $AwsRegion

        $stsOut = aws sts get-caller-identity --query "Account" --output text 2>&1
        if ($LASTEXITCODE -ne 0 -and (Test-TlsTrustFailure $stsOut)) {
            Write-Host ""
            Write-Warn2 "The AWS CLI could not validate the TLS certificate chain."
            if (Set-CorporateCaBundle) {
                $stsOut = aws sts get-caller-identity --query "Account" --output text 2>&1
            }
        }
        $AwsAccount = if ($LASTEXITCODE -eq 0) { ($stsOut | Out-String).Trim() } else { $null }

        if (Test-TlsTrustFailure $stsOut) {
            $issuer = Get-ServedCertIssuer "https://secretsmanager.$AwsRegion.amazonaws.com/"
            $signInErrors += @"
AWS -- the CLI rejected the TLS certificate, and pointing it at the Windows
trust store did not resolve it.

    certificate issued by : $(if ($issuer) { $issuer } else { "could not be read" })

If that is not an Amazon CA, this network re-signs TLS and the inspection root
is not in the Windows store either. Set AWS_CA_BUNDLE to a PEM containing it.
Do not disable certificate verification.
"@
        } elseif (-not $AwsAccount) {
            # On a machine with named profiles this is a selection problem, not
            # a sign-in problem, and "sign in and retry" sends the operator
            # looking in the wrong place. Name what is configured.
            $awsProfiles = @(aws configure list-profiles 2>$null)
            $hint = if ($awsProfiles.Count -gt 0) {
                "    Configured profiles: " + ($awsProfiles -join ', ') + "`n`n" +
                '    $env:AWS_PROFILE = "<profile>"' + "`n" +
                '    aws sso login --profile <profile>    # if the session has lapsed'
            } else {
                "    No named profiles are configured."
            }
            $signInErrors += "AWS -- no usable credentials. -EnableAws was passed, so shared`n" +
                             "services account $ExpectedAccount is required.`n`n$hint"
        } elseif ($ExpectedAccount -ne $AwsAccount) {
            $signInErrors += @"
AWS -- wrong account.

    Signed in to : $AwsAccount
    Expected     : $ExpectedAccount  (shared services)

    This script does not assume a role to get there. Worth knowing:
    setup-pipeline.ps1 runs from the MANAGEMENT account and this one does
    not, which is an easy thing to carry over out of habit.
"@
        } else {
            Write-Good "AWS: shared services account $AwsAccount in $AwsRegion."
        }
    }
}

# -----------------------------------------------------------------------------
# Data-plane TLS
#
# The checks above do not prove TLS to the endpoints this script actually
# writes to. 'az account show' reads the local token cache and makes no network
# call at all; Graph, ARM and STS are different hosts from the Key Vault data
# plane and the Secrets Manager endpoint, and an inspecting proxy does not
# necessarily treat them alike. A run got all the way through sign-in, Entra,
# the API and into the Key Vault write before failing on
# CERTIFICATE_VERIFY_FAILED, by which point the trust fix was never offered.
#
# So each enabled store is reached here, over its real endpoint, before
# anything is written. A permission error is not interesting at this point and
# is left for the write probe that follows; only a trust failure is acted on.
# -----------------------------------------------------------------------------
if ($signInErrors.Count -eq 0) {
    $planeProbes = @()
    if ($KeyVault) {
        $planeProbes += @{
            Name    = "Key Vault data plane"
            Host    = "https://$KeyVault.vault.azure.net/"
            Probe   = { az keyvault secret list --vault-name $KeyVault --maxresults 1 --query "[0].id" -o tsv 2>&1 }
            Advice  = "Set REQUESTS_CA_BUNDLE to a PEM containing it."
        }
    }
    if ($EnableAws) {
        $planeProbes += @{
            Name    = "Secrets Manager"
            Host    = "https://secretsmanager.$AwsRegion.amazonaws.com/"
            Probe   = { aws secretsmanager list-secrets --max-results 1 --region $AwsRegion --query "SecretList[0].Name" --output text 2>&1 }
            Advice  = "Set AWS_CA_BUNDLE to a PEM containing it."
        }
    }

    foreach ($p in $planeProbes) {
        $out = & $p.Probe
        if (-not (Test-TlsTrustFailure $out)) { continue }

        Write-Host ""
        Write-Warn2 "$($p.Name): the CLI could not validate the TLS certificate chain."

        # Named up front, before any remediation. .NET validates against the
        # Windows store, so it can read the certificate the CLI is refusing --
        # and if the issuer is not the expected cloud provider, that settles
        # whether the network is re-signing rather than leaving it a theory.
        $seenIssuer = Get-ServedCertIssuer $p.Host
        if ($seenIssuer) { Write-Warn2 "  served by: $seenIssuer" }

        if (Set-CorporateCaBundle) { $out = & $p.Probe }

        if (Test-TlsTrustFailure $out) {
            $issuer = Get-ServedCertIssuer $p.Host
            $signInErrors += @"
$($p.Name) -- the CLI rejected the TLS certificate, and pointing it at the
Windows trust store did not resolve it.

    endpoint              : $($p.Host)
    certificate issued by : $(if ($issuer) { $issuer } else { "could not be read" })

This network re-signs TLS and the inspection root is not in the Windows store
either. Ask whoever runs it for the root certificate, save it as a PEM, and
$($p.Advice) Do not disable certificate verification -- this run reads and
writes client secrets.
"@
        }
    }
}

if ($signInErrors.Count -gt 0) {
    Stop-With ("This run cannot reach everything it needs.`n`n" +
               ($signInErrors -join "`n`n") + "`n`nFix all of the above, then re-run.")
}

Write-Step "Preflight: Entra"

# 'az ad app list' has no --top. A filter that cannot match anything is the
# cheapest call that still exercises the /applications read the rest of this
# script depends on, and it returns an empty list rather than the whole
# directory.
az ad app list --filter "appId eq '00000000-0000-0000-0000-000000000000'" `
    --query "[0].appId" -o tsv 2>$null | Out-Null
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
    #
    # The probe is deliberately NOT deleted afterwards. Key Vault soft-delete
    # reserves a deleted name for the retention period -- 90 days by default --
    # and 'secret set' against a name in that state fails with a conflict, not
    # a permission error. Deleting the probe each run therefore made the
    # preflight work exactly once, and every run after that reported "Cannot
    # write to Key Vault, grant Key Vault Secrets Officer" at operators who
    # already had it. One probe secret left in the vault, named for what it is,
    # costs less than a preflight that only works the first time.
    $probeOut = az keyvault secret set --vault-name $KeyVault --name $KvProbeName `
        --value "probe" --output none 2>&1

    if ($LASTEXITCODE -ne 0) {
        # Clean up after the version of this script that did delete the probe.
        # Recover rather than purge: recovery needs no purge permission and
        # works on vaults with purge protection enabled, where purging a
        # soft-deleted secret is impossible and the name would otherwise be
        # unusable until the retention period expired.
        $softDeleted = az keyvault secret list-deleted --vault-name $KeyVault `
            --query "[?name=='$KvProbeName'].name" -o tsv 2>$null
        if ($softDeleted) {
            Write-Warn2 "A preflight probe was left soft-deleted by an earlier run. Recovering it."
            az keyvault secret recover --vault-name $KeyVault --name $KvProbeName --output none 2>$null | Out-Null

            # Recovery is asynchronous. A set issued before it completes is
            # rejected with ObjectIsBeingRecovered -- a conflict that reads like
            # a failure but only means "not yet". Wait for the secret to become
            # readable instead of retrying straight into it.
            $recovered = $false
            foreach ($attempt in 1..12) {
                az keyvault secret show --vault-name $KeyVault --name $KvProbeName `
                    --query "id" -o tsv 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) { $recovered = $true; break }
                Start-Sleep -Seconds 5
            }
            if (-not $recovered) {
                Stop-With "The preflight probe '$KvProbeName' in '$KeyVault' is still recovering after 60 seconds. Re-run shortly -- no action needed beyond waiting."
            }

            $probeOut = az keyvault secret set --vault-name $KeyVault --name $KvProbeName `
                --value "probe" --output none 2>&1
        }
    }

    if ($LASTEXITCODE -ne 0) {
        # Report what az said rather than naming a cause. Asserting "grant Key
        # Vault Secrets Officer" is what sent someone holding Key Vault
        # Administrator into the portal looking for a role they already had.
        Stop-With "Cannot write to Key Vault '$KeyVault'.`n`naz reported:`n`n$probeOut"
    }
    Write-Good "Key Vault writable."
}

if ($EnableAws) {
    Write-Step "Preflight: AWS Secrets Manager"

    # Credentials, region, and the account match are all settled by the sign-in
    # gate above. What is left is the one thing a successful sts call does not
    # prove: that this identity can actually write.
    #
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

# The Entra portal's "Enterprise applications" list defaults to Application
# type = Enterprise Applications, which shows only service principals carrying
# this tag. One created by the CLI has no tags, so it is invisible there -- the
# administrator sees the app registration, finds nothing under Enterprise
# applications, and concludes the enterprise application was never created. It
# was; the list is filtered.
#
# Applied in Get-OrCreateSp so both service principals get it. The patcher is
# not a sign-in app and might look like it does not belong in that list, but it
# holds Application.ReadWrite.OwnedBy, and Enterprise applications ->
# Permissions is the only place that grant can be reviewed or revoked.
$PortalTag = "WindowsAzureActiveDirectoryIntegratedApp"

function Set-PortalTag {
    param([string]$SpId)

    $existing = az ad sp show --id $SpId --query "tags" -o json 2>$null

    # Enumerate rather than wrap. An untagged principal returns "[]", and
    # ConvertFrom-Json yields that as a single empty-array object, not as no
    # items -- so @($existing | ConvertFrom-Json) produced a one-element list
    # whose only element was itself an array. ConvertTo-Json then rendered it
    # as {"value":[],"Count":0} and Graph rejected the PATCH with "An
    # unexpected 'StartObject' node was found ... A 'PrimitiveValue' node was
    # expected." A typed list of strings cannot take that shape.
    #
    # Piped, not -InputObject. A principal that already has tags returns
    # pretty-printed JSON, which PowerShell captures as a string array, and
    # -InputObject rejects anything but a single string. The pipeline form
    # buffers the lines and parses them as one document; it is also what makes
    # the "[]" case above enumerate to nothing instead of throwing.
    $tags = [System.Collections.Generic.List[string]]::new()
    if ($existing) {
        foreach ($t in ($existing | ConvertFrom-Json)) {
            if ($null -ne $t -and "$t" -ne "") { $tags.Add([string]$t) }
        }
    }
    if ($tags -contains $PortalTag) { return }   # already tagged, leave it alone

    # PATCH replaces tags wholesale, so carry forward any already present.
    $tags.Add($PortalTag)

    Invoke-GraphJson -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SpId" `
        -Body @{ tags = @($tags) } `
        -ErrorMessage "Could not tag service principal $SpId -- az reported the reason above."

    Write-Good "Tagged as an enterprise application so it appears in the portal list."
}

function Get-OrCreateSp {
    param([string]$AppId)
    $spId = az ad sp list --filter "appId eq '$AppId'" --query "[0].id" -o tsv 2>$null
    if (-not $spId -or $spId -eq "None") {
        $spId = az ad sp create --id $AppId --query "id" -o tsv
        Write-Good "Service principal created: $spId"
    }
    Set-PortalTag -SpId $spId
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
    Invoke-GraphJson -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        -Body @{ api = @{ requestedAccessTokenVersion = 2 } } `
        -ErrorMessage "Could not set the access token version on '$AppName' -- az reported the reason above."
    Write-Good "Access token version set to v2.0."
}

if ((az rest --method GET --uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        --query "groupMembershipClaims" -o tsv 2>$null) -ne "SecurityGroup") {
    Invoke-GraphJson -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/applications/$AppObjectId" `
        -Body @{ groupMembershipClaims = "SecurityGroup" } `
        -ErrorMessage "Could not set groupMembershipClaims on '$AppName' -- az reported the reason above."
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
    Invoke-GraphJson -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PatchSpId/appRoleAssignments" `
        -Body @{ principalId = $PatchSpId; resourceId = $graphSp; appRoleId = $ownedByRoleId } `
        -ErrorMessage "Could not grant Application.ReadWrite.OwnedBy to '$PatchAppName' -- az reported the reason above. Without it the patcher cannot register a cluster's redirect URI, and Headlamp sign-in fails at the end of every build."
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

    # Counted from a list of ids rather than with length(@). On Windows 'az' is
    # a .cmd batch file and PowerShell 5.1 only quotes an argument containing a
    # space, so a bare length(@) reached cmd's parser, which treats parentheses
    # as syntax -- it answered "-o was unexpected at this time" and the read
    # failed for reasons that had nothing to do with Entra. Queries with spaces
    # in them survive by accident; this one had none. Brackets and dots are not
    # special to cmd, so [].keyId is safe.
    $credOut = az ad app credential list --id $AppId --query "[].keyId" -o tsv 2>&1

    # Fail closed. The 'credential reset' below is the one destructive call in
    # this script -- it removes every credential the application already has --
    # and this count is the only thing standing between it and a live app. When
    # the read itself fails (expired login, throttling, a directory role that
    # cannot read credentials) treating that as "no credentials" would mint
    # straight over the secret every running Headlamp is authenticating with.
    if ($LASTEXITCODE -ne 0) {
        Stop-With ("${Label}: could not read the existing credentials from Entra, so minting " +
                   "is not safe -- it would remove any secret this application already holds." +
                   "`n`naz reported:`n`n" + ($credOut -join "`n"))
    }

    $credCount = @($credOut | Where-Object { "$_".Trim() }).Count

    if ($credCount -gt 0) {
        Stop-With "$Label already has $credCount client secret(s), and Entra does not return one after creation. No enabled store holds it, so it cannot be recovered.`n`nRe-run including the store that does hold it, or rotate deliberately -- a rotation invalidates the credential every running Headlamp is using and needs every cluster refreshed."
    }

    Write-Step "Minting a client secret for $Label (valid $SecretYearsValid years)..."
    $endDate = (Get-Date).ToUniversalTime().AddYears($SecretYearsValid).ToString("yyyy-MM-ddTHH:mm:ssZ")
    # Not $pwd -- that is an automatic variable in PowerShell.
    $newSecret = az ad app credential reset --id $AppId --display-name $Label --end-date $endDate --query "password" -o tsv
    if ($LASTEXITCODE -ne 0 -or -not $newSecret) { Stop-With "Could not create a client secret for $Label." }
    Write-Good "Created."
    return @{ Secret = $newSecret; Origin = "minted" }
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

# JSON handed to a native command as an argument loses its double quotes on
# PowerShell 5.1 -- the same defect that broke the Graph PATCHes. Passing a
# compressed manifest as --value stored {apiVersion:v1,kind:Secret,...} in Key
# Vault instead of {"apiVersion":"v1",...}: unparseable, and silent, because
# the store accepted the string quite happily and only the next run's read
# failed. Both CLIs can take the value from a file, which sidesteps quoting
# entirely.
#
# Written without a BOM. Both CLIs treat the file as raw text, so a BOM would
# be carried into the stored secret and break the JSON parse at the far end --
# in the cluster, not here.
function New-JsonTempFile {
    param([string] $Json)
    $f = New-TemporaryFile -ErrorAction Stop
    [System.IO.File]::WriteAllText($f.FullName, $Json, (New-Object System.Text.UTF8Encoding($false)))
    return $f.FullName
}

# Compare content, not bytes. A document written by earlier tooling has the
# same meaning but different spacing and key order, and a string comparison
# calls that "changed" -- so the script rewrote a perfectly good secret, and
# minted a new Key Vault version, for a difference that did not exist. That
# needless write is what put a corrupt document over a working one.
#
# Sorting the properties makes the comparison order-insensitive; an unparseable
# stored document is never equivalent, so a corrupt value is always replaced.
function ConvertTo-CanonicalJson {
    param($Obj)
    if ($null -eq $Obj) { return "null" }
    if ($Obj -is [string] -or $Obj -is [bool] -or $Obj -is [int] -or
        $Obj -is [long]   -or $Obj -is [double]) {
        return ($Obj | ConvertTo-Json -Compress)
    }
    if ($Obj -is [System.Collections.IEnumerable]) {
        return "[" + (($Obj | ForEach-Object { ConvertTo-CanonicalJson $_ }) -join ",") + "]"
    }
    $parts = foreach ($p in ($Obj.PSObject.Properties | Sort-Object Name)) {
        (ConvertTo-Json $p.Name -Compress) + ":" + (ConvertTo-CanonicalJson $p.Value)
    }
    return "{" + ($parts -join ",") + "}"
}

function Test-JsonEquivalent {
    param($A, $B)
    if (-not $A -or -not $B) { return $false }
    try {
        $x = ConvertTo-CanonicalJson ((($A -join '')) | ConvertFrom-Json)
        $y = ConvertTo-CanonicalJson ((($B -join '')) | ConvertFrom-Json)
    } catch { return $false }
    return $x -eq $y
}

# Pulls the credential out of either document shape: the k8s Secret manifest,
# where it is base64 under data.clientSecret, or the flat patcher document.
function Get-DocSecret {
    param($Doc)
    if (-not $Doc) { return $null }
    try {
        $d = (($Doc -join '')) | ConvertFrom-Json
        if ($d.data -and $d.data.clientSecret) { return ConvertFrom-B64 $d.data.clientSecret }
        if ($d.clientSecret) { return [string]$d.clientSecret }
    } catch { }
    return $null
}

# A stored credential is never replaced with a different one. Non-secret fields
# may legitimately drift -- key order, scopes, useAccessToken -- and rewriting
# those is harmless. Replacing the credential is not: every Headlamp already
# running is authenticating with the stored value, and overwriting it breaks
# them all at once, silently, until someone tries to sign in.
#
# Writing where nothing is stored, or where the stored document cannot be
# parsed, is allowed -- that is a create or a repair, not a replacement.
function Assert-NoSecretReplacement {
    param($Name, $Existing, $Want)

    $have = Get-DocSecret $Existing
    if (-not $have) { return }

    $new = Get-DocSecret $Want
    if ($have -eq $new) { return }

    $newHint = if ($new) { $new.Substring(0, [Math]::Min(3, $new.Length)) + "..." } else { "(none)" }
    Stop-With @"
Refusing to replace the credential already stored in $Name.

    stored      : $($have.Substring(0, [Math]::Min(3, $have.Length)))...
    would write : $newHint

Whatever is already authenticating with the stored credential would stop doing
so. Nothing has been written.

If the replacement is intended, rotate deliberately and refresh every cluster
that holds a copy -- the Entra credential, both stores, and each cluster's
headlamp-oidc secret.
"@
}

if ($KeyVault) {
    Write-Step "Key Vault"
    $wantOidc  = New-Manifest -UseAccessToken $true
    $wantPatch = New-PatchDoc

    function Set-KvSecret { param($Name, $Value)
        $tmp = New-JsonTempFile $Value
        try {
            az keyvault secret set --vault-name $KeyVault --name $Name --file $tmp --output none
            if ($LASTEXITCODE -ne 0) { Stop-With "Could not write $Name to Key Vault '$KeyVault'." }
        }
        finally { Remove-Item $tmp -ErrorAction SilentlyContinue }

        # Read back before moving on. A store accepting the call is not proof it
        # holds what was sent: a quote-stripped document was stored here once,
        # az reported success, and it only surfaced on the next run's read --
        # by which point the good version was one back in the history.
        $back = az keyvault secret show --vault-name $KeyVault --name $Name --query "value" -o tsv 2>$null
        if (-not (Test-JsonEquivalent $Value $back)) {
            Stop-With "Wrote $Name to Key Vault '$KeyVault', but reading it back returned something different. Stopping before anything else is touched. The previous value is still in the vault's version history."
        }
    }

    if (-not (Test-JsonEquivalent $wantOidc $kvOidcDoc)) {
        Assert-NoSecretReplacement $KvOidcName $kvOidcDoc $wantOidc
        Set-KvSecret $KvOidcName $wantOidc
        Write-Good "$KvOidcName written."
    } else { Write-Good "$KvOidcName already current." }
    if (-not (Test-JsonEquivalent $wantPatch $kvPatchDoc)) {
        Assert-NoSecretReplacement $KvPatchName $kvPatchDoc $wantPatch
        Set-KvSecret $KvPatchName $wantPatch
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

    # file:// for the same reason Key Vault uses --file: a compressed JSON
    # argument reaches the CLI with its double quotes stripped.
    function Set-SmSecret { param($Name, $Value)
        $tmp = New-JsonTempFile $Value
        try {
            aws secretsmanager put-secret-value --secret-id $Name --secret-string "file://$tmp" --region $AwsRegion 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                aws secretsmanager create-secret --name $Name --secret-string "file://$tmp" --region $AwsRegion | Out-Null
                if ($LASTEXITCODE -ne 0) { Stop-With "Could not write $Name to Secrets Manager." }
            }
        }
        finally { Remove-Item $tmp -ErrorAction SilentlyContinue }

        # Read back, for the same reason Key Vault does.
        $back = aws secretsmanager get-secret-value --secret-id $Name --region $AwsRegion --query "SecretString" --output text 2>$null
        if (-not (Test-JsonEquivalent $Value $back)) {
            Stop-With "Wrote $Name to Secrets Manager, but reading it back returned something different. Stopping before anything else is touched."
        }
    }

    if (-not (Test-JsonEquivalent $wantOidc $smOidcDoc)) {
        Assert-NoSecretReplacement $SmOidcName $smOidcDoc $wantOidc
        Set-SmSecret $SmOidcName $wantOidc
        Write-Good "$SmOidcName written."
    } else { Write-Good "$SmOidcName already current." }
    if (-not (Test-JsonEquivalent $wantPatch $smPatchDoc)) {
        Assert-NoSecretReplacement $SmPatchName $smPatchDoc $wantPatch
        Set-SmSecret $SmPatchName $wantPatch
        Write-Good "$SmPatchName written."
    } else { Write-Good "$SmPatchName already current." }
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

# Only prints if the bundle was actually needed. Says how to make it stick, so
# the next run on this machine does not rediscover the same problem.
Show-CaBundleAdvice
