# entra/headlamp-oidc

Creates the Entra applications Headlamp needs and puts their credentials in
whichever secret stores your installation uses.

## Which script

Two versions, aimed at two customer shapes rather than at two preferences:

| Customer | Script | Stores |
|---|---|---|
| AWS + Microsoft 365, no Azure subscription | `.sh` on Linux — python3 already present | Secrets Manager only |
| Azure or hybrid, has a subscription | `.ps1` — no python3, no curl | Key Vault, or both |

The first is more common than it sounds. Buying Microsoft 365 creates an Entra
tenant; it does not create an Azure subscription. An organisation running its
workloads on AWS and its email on Microsoft has a directory to authenticate
against and no Azure resources at all — so there is no Key Vault to write to,
and everything lands in Secrets Manager.

## Prerequisites

**Azure CLI** — required either way. It performs every directory operation, and
it is the only Microsoft component needed: no subscription, no portal visit, no
Windows machine.

```bash
# Ubuntu / Debian
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

```powershell
# Windows
winget install -e --id Microsoft.AzureCLI
# or the MSI: https://aka.ms/installazurecliwindows
```

**AWS CLI** — only when writing to Secrets Manager.

**python3 and curl** — only for the `.sh` version, and both are already present
on a standard Ubuntu install. The `.ps1` needs neither.

### Signing in

```bash
az login
az login --allow-no-subscriptions              # tenant with no subscription
az login --use-device-code                     # headless box, no browser
```

Combine the last two on a headless server in a tenant with no subscription.
Without `--allow-no-subscriptions` the CLI reports what looks like a login
failure, and it is easy to conclude the product needs an Azure subscription —
it does not. App registrations are directory objects, not Azure resources.

You also need rights to create app registrations and service principals
(Cloud Application Administrator or higher), and write access to whichever
stores you enable.

## Usage

```bash
./create-headlamp-app.sh --key-vault <name>                # Azure
./create-headlamp-app.sh --enable-aws                      # AWS
./create-headlamp-app.sh --key-vault <name> --enable-aws   # both
```

```powershell
.\create-headlamp-app.ps1 -KeyVault <name>                 # Azure
.\create-headlamp-app.ps1 -EnableAws                       # AWS
.\create-headlamp-app.ps1 -KeyVault <name> -EnableAws      # both
```

At least one store is required. The Entra work happens either way — it is the
same directory whichever clouds are involved, and `az login` needs only a
tenant, so an **EKS-only installation does not need an Azure subscription**.

Two further flags, both for situations the script refuses to guess its way
through:

```
--headlamp-id <appId>   name the application directly instead of searching
--trust azure | aws     resolve a disagreement between the two stores
```

Everything else — AWS account and region, Azure tenant — comes from the
environment. Paste the block from **Settings → Terraform tile → Pipeline
credentials** before running.

## Two applications

| Application | Purpose | Credential |
|---|---|---|
| `headlamp` | signs users in — the OIDC client | client secret |
| `gitopsmanager-headlamp-patch-url` | owns the above; patches its redirect URIs as clusters come and go | client secret |

Separate deliberately. Adding a redirect URI **is** the sensitive operation — a
callback pointing at someone else's infrastructure harvests authorization codes
for every user who signs in. If the Headlamp application owned itself, the
credential that signs your users in would also be the one that can redirect
them, and a single leak would buy both.

The patcher holds `Application.ReadWrite.OwnedBy`, the narrowest permission
Graph offers. Granting it requires admin consent. Precisely what it allows:

- **Applications it does not own — nothing.** It also cannot add itself as an
  owner elsewhere, since that would already require write access it lacks.
- **Applications it owns — everything.** Read, update, credentials, delete.
- **Creating new applications — permitted**, becoming owner of what it creates.
  There is no narrower alternative; Graph has no per-application scope and
  nothing for redirect URIs specifically. A new application has no API
  permissions until an administrator consents, so the exposure is directory
  clutter rather than escalation, and creation appears in the audit log.

An application credential rather than a managed identity, because a
system-assigned identity dies with its VM — replace the agent and every grant
made to the old identity refers to a principal that no longer exists.

## Nothing is created until every write is proven

Entra reveals a client secret **exactly once**. Minting one and then failing to
store it leaves an application holding a credential nobody has — the only
unrecoverable failure here.

So the preflight proves everything first: Azure sign-in and directory read, the
EKS Manager token, and an actual **probe write** to each enabled store. The AWS
probe also proves `kms:GenerateDataKey` on `EKSManagerCMK` end to end. Where the
environment says which AWS account and region to expect, the resolved session is
checked against them — the ambient profile is convenient and is exactly how
someone writes to the wrong account.

## How a secret is resolved

For each application, in order:

1. **Key Vault**, if enabled and the entry exists
2. **Secrets Manager**, if enabled and the entry exists
3. **Mint one** — only if the application has no credentials at all
4. Otherwise **stop**

Steps 1 and 2 do double duty: they make re-running safe, and they copy an
existing value from one cloud to the other. Adding `--enable-aws` to an
installation that already works on Azure needs no new credential and causes no
disruption.

Step 4 is the case where the application exists, has a secret, and no enabled
store holds it. Entra will not return it, so it cannot be recovered. The script
says so and exits rather than resetting quietly — a reset invalidates the
credential every running Headlamp is using, on every cluster at once.

### If the two stores disagree

They should not, but if someone added a secret without updating both sides,
Entra returns a **hint** for each live credential — enough to tell a working
value from a stale copy:

| Hints show | Action |
|---|---|
| One store's value is not a live credential | The other wins, automatically |
| Neither is live | Both are stale; a rotation is unavoidable |
| Both are live | Nothing is broken, but only you can choose — `--trust azure` or `--trust aws` |

After using `--trust`, remove the losing credential from the application or the
same disagreement recurs on the next run.

## Where things are written

**Key Vault** — `global-headlamp-oidc`, `global-headlamp-patch-url`

**Secrets Manager** — `/EKSManagerBootstrap/headlamp-oidc`,
`/EKSManagerBootstrap/headlamp-patch-url`, alongside the existing bootstrap
secrets so one convention covers them all.

Written only when the content differs, so an unchanged run creates no new secret
versions.

### The AWS copy is not identical

`useAccessToken` is **`false`** there. The EKS API server requires an `aud`
claim that Entra access tokens do not carry in the expected form; the ID token
does. The validator pair is then unnecessary — but **all seven keys are still
present**, empty where unused, because the deployment reads them with
`secretKeyRef` and no `optional: true`. A missing key fails the pod with
`CreateContainerConfigError` rather than defaulting.

## What reaches the server

**Metadata only.** Application IDs, tenant, issuer, both expiry dates, and which
stores were written. No credential ever reaches the EKS Manager database.

The expiry dates matter more than they look: **Entra sends no notification
before an application client secret expires** — that warning exists only for
SAML signing certificates. These dates are the only warning you will get, and
they feed the credential view in the dashboard.

If the report fails the script says so and continues. The applications and
secrets are already in place; only the dashboard metadata is missing, and
re-running retries it.

## Credential expiry

Both secrets are valid for two years. When the Headlamp secret lapses, sign-in
fails on every cluster at once. When the patcher's lapses, new clusters get no
callback registered and their Headlamp cannot be signed into at all.

## What happens after this

Registering each cluster's redirect URI is separate work, done at Headlamp
deployment time using the patcher credential this script stored. That is where
the ingress already exists, so the actual hostname is read rather than composed.
