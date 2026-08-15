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
| SAML SSO | users, to the GitOps Manager dashboard | signing certificate | **GitOps Manager, from 30 days out** |
| `headlamp` | users, to Headlamp | client secret | GitOps Manager, from 30 days out — *planned* |
| `gitopsmanager-headlamp-patch-url` | nobody — it registers redirect URIs | client secret | GitOps Manager, from 30 days out — *planned* |

From 30 days before expiry, **Settings** shows the remaining days against the
credential and raises a warning on page load, escalating to an error once the
date has passed. The SAML signing certificate is live today; the two Headlamp
client secrets report their expiry dates already and the warning for them is
being built on the same mechanism.

Sign-in to the dashboard reaches your directory through Cognito; Headlamp
reaches it directly, because the Kubernetes API server has to validate the same
token and only accepts certain issuers. Two paths, one directory.

## Credential expiry — read this before relying on either

**Treat GitOps Manager as the only warning you will get.** Everything below is
why.

**Application client secrets get no notification from Entra at all.** It emails
about SAML signing certificates and nothing else. When the Headlamp secret
lapses, sign-in fails on every cluster simultaneously, with no warning and no
recent change to point at. When the patcher's lapses, new clusters get no
callback registered.

**Do not count on the SAML certificate email either.** It requires notification
addresses on the application, and Microsoft documents that when those are set
programmatically an administrator must open the application's single sign-on
blade in the portal once before the emails actually fire. For an application
registered in your own tenant — which is what these scripts create — **that
blade is not reachable**: the portal serves the OpenID Connect page instead and
offers no SAML certificate view at all. The certificates are there and working;
the portal simply has nowhere to show them.

That is the gap these scripts close. Each reports its expiry dates back to
GitOps Manager, and Settings warns from 30 days out — on the page, and as a
notification when the page loads.

To see the certificates themselves, ask Graph rather than the portal:

```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>?\$select=keyCredentials,preferredTokenSigningKeyThumbprint" \
  --query "keyCredentials[?usage=='Verify'].{expires:endDateTime}"
```

### Rotating before it lapses

Re-run the same script. Inside 30 days of expiry it stops treating the existing
credential as reusable and issues a replacement, makes it the active signing
key, and reports the new date — which clears the warning. Outside that window a
re-run deliberately changes nothing, so it is safe to run at any time.

The previous certificate is left in place until it expires, so the rotation
does not interrupt anyone signing in.

## Running these

Each directory has its own README with prerequisites and usage. In general you
need to be signed in to the provider with rights to create applications, plus
the pipeline credentials from **Settings → Terraform tile** in your dashboard.

Both scripts are idempotent — safe to re-run, and re-running is how you add a
second cloud to an installation that already works.

Nothing here stores credentials on disk. Values come from environment variables
or arguments, so closing the terminal is all the cleanup required.
