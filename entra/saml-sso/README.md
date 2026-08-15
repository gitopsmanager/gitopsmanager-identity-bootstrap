# entra/saml-sso

Creates the Entra SAML Enterprise Application used for Cognito SSO. This is
independent of license type — an AWS-only customer still needs an Entra SAML
app if SSO is enabled, since Cognito federates to Entra regardless of which
cloud the workload infrastructure runs in.

This is a standalone script, not part of the Terraform install. Run it once
per client, any time before or after the main bootstrap.

## What it does

1. Creates (or reuses) an Entra app registration, with the Cognito ACS
   (reply) URL as its redirect URI and the Cognito entity ID as its
   identifier URI
2. Creates a service principal in SAML single sign-on mode
3. Creates a self-signed token signing certificate on the service principal
4. Obtains its own M2M bearer token from Cognito
5. Reports the app ID, entity ID, federation metadata URL and signing
   certificate back to EKS Manager, which uses them to configure the
   Cognito SAML identity provider automatically

Idempotent — safe to re-run. If the app already exists it is reused and its
redirect/identifier URIs are kept in sync with the current Cognito
configuration.

## Prerequisites

- [Install the Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) and run `az login`. `curl` is also needed for the bash script — `create-saml-app.ps1` uses PowerShell's native `Invoke-RestMethod` instead
- The signed-in user must hold the **Cloud Application Administrator** directory role (or higher, e.g. Global Administrator) — required to create app registrations and service principals in Entra
- Network egress from wherever this script runs must be reachable by the client's EKS Manager API. The API sits behind an IP allowlist, so this must be run from a host whose public IP is already allowlisted — the same NAT Gateway IP used by the `eksmanager-bootstrap` CodeBuild pipeline satisfies this, see that repository's `README.md`

## Setup

Paste the bash or PowerShell block from **Settings → Terraform tile → Pipeline credentials** in your EKS Manager dashboard into your shell — then run:

```bash
az login
./create-saml-app.sh
```

or on Windows:

```powershell
az login
.\create-saml-app.ps1
```

Since nothing is stored in the script file, there's nothing to remove afterward — closing the terminal session clears the environment variables, including the client secret.

## After running

EKS Manager is notified automatically in step 5 — no further action is
needed on your part. You can verify the app was created correctly in the
Entra portal under **Enterprise Applications**, searching for "GitOps
Manager SAML".

## Re-running

Safe to re-run at any time. If the Cognito SP details change (for example,
a new environment or a Cognito domain change), re-run the script with the
updated values — it will detect the existing app and update the redirect
URI and identifier URI to match.
