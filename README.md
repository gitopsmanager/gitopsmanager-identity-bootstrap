# gitopsmanager-identity-bootstrap

Creates the identity provider applications GitOps Manager needs — SAML for
dashboard SSO, OIDC for Headlamp — in your own directory, whichever cloud your
clusters run in.

## Why this is separate from the cloud bootstraps

These applications live in **your identity provider**, not in AWS or Azure. They
are independent of which cloud your clusters run in and of which licence you
hold: an AWS-only installation still needs a SAML application if SSO is enabled,
because sign-in federates to your directory regardless of where the workload
infrastructure sits.

Keeping them in `eksmanager-bootstrap` implied they were AWS-specific. They are
not, so they live here.

## What's here

```
entra/
  saml-sso/         Dashboard SSO — SAML application, signing certificate
  headlamp-oidc/    Headlamp sign-in — two applications, client secrets
```

Organised by **provider**, then by **application**, so additional providers slot
in alongside. Microsoft Entra ID is the only one supported today.

## The applications, and what each is for

| Application | Signs in | Credential | Expiry warning |
|---|---|---|---|
| SAML SSO | users, to the GitOps Manager dashboard | signing certificate | Entra emails at 60/30/7 days |
| `headlamp` | users, to Headlamp | client secret | **none** |
| `gitopsmanager-headlamp-patch-url` | nobody — it registers redirect URIs | client secret | **none** |

Sign-in to the dashboard reaches your directory through Cognito; Headlamp
reaches it directly, because the Kubernetes API server has to validate the same
token and only accepts certain issuers. Two paths, one directory.

## Credential expiry — read this before relying on either

**The SAML signing certificate is the only credential your identity provider
will warn you about**, and only if notification addresses are configured on the
application. Microsoft documents that when those are set programmatically, an
administrator must open the application's single sign-on blade in the portal
once before notifications actually fire — so confirm in the portal rather than
assuming.

**Application client secrets get no notification at all.** Entra emails about
SAML certificates and nothing else. When the Headlamp secret lapses, sign-in
fails on every cluster simultaneously, with no warning and no recent change to
point at. When the patcher's lapses, new clusters get no callback registered.

Both scripts report expiry dates back to EKS Manager for exactly this reason.
That view is the only warning that will exist.

## Running these

Each directory has its own README with prerequisites and usage. In general you
need to be signed in to the provider with rights to create applications, plus
the pipeline credentials from **Settings → Terraform tile** in your dashboard.

Both scripts are idempotent — safe to re-run, and re-running is how you add a
second cloud to an installation that already works.

Nothing here stores credentials on disk. Values come from environment variables
or arguments, so closing the terminal is all the cleanup required.
