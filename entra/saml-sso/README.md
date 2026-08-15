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

EKS Manager is notified automatically in step 5 — no further action is needed
on your part.

To see the application in the portal, look under **Enterprise applications**
for `EKS Manager SAML -- EntraSAML` (or your `PROVIDER_NAME` in place of the
suffix). Two things about that view are worth knowing before you go looking:

- The list defaults to filtering on *Application type: Enterprise
  Applications*. The script tags the service principal so it appears there, but
  if you are looking at one created before that tag existed, switch the filter
  to **All Applications**.
- Its **Single sign-on** page will show the OpenID Connect view, not a SAML
  one, and **no certificate list at all**. That is expected for an application
  registered in your own tenant, and does not mean SAML is misconfigured. The
  signing certificates live on the service principal; query Graph to see them,
  or read the expiry in GitOps Manager's Settings page.

## Re-running

Safe to re-run at any time, and the way to rotate.

Outside 30 days of the certificate's expiry a re-run deliberately changes
nothing: the existing application, service principal and certificate are
detected and reused. If the Cognito details change — a new environment, a
different Cognito domain — re-run with the updated values and the redirect URI
and identifier URI are brought into line.

**Inside 30 days of expiry** the existing certificate stops counting as
reusable. The script issues a replacement, makes it the active signing key, and
reports the new date, which clears the warning in Settings. The old certificate
is left alone until it expires, so nobody's sign-in is interrupted during the
overlap.

## Certificate expiry

The signing certificate is valid for three years.

Do not rely on Entra to tell you when it is running out. Its expiry email needs
notification addresses on the application, and Microsoft documents that when
those are set programmatically an administrator must open the single sign-on
blade in the portal once before the emails fire — and as described above, that
blade is not reachable for an application registered in your own tenant.

**Settings is the warning.** From 30 days out it shows the days remaining
against the Entra SAML row and raises a notification when the page loads,
becoming an error once the date has passed. Re-run this script when you see it.
