# genesis-umami

Optional, **default-off** subchart that self-hosts [Umami](https://umami.is)
web analytics (MIT-licensed `umami-software/umami`) for the Genesis platform.

It mirrors the other optional bundles (`genesis-observability`,
`genesis-opencost`): nothing renders unless you enable it.

## Enable

```yaml
# umbrella values
genesis-umami:
  enabled: true
```

By default this also deploys an in-chart PostgreSQL (StatefulSet + PVC), so the
analytics stack is turnkey.

## Use an external database (password auth)

```yaml
genesis-umami:
  enabled: true
  database:
    bundled: false
    external:
      url: "postgresql://<user>:<password>@<host>:5432/umami"
    # or: existingSecret: my-umami-db   # Secret with a DATABASE_URL key
```

`APP_SECRET` is never read from `database.existingSecret`, so that Secret only
needs a `DATABASE_URL` key. To supply `APP_SECRET` yourself use
`app.existingSecret` (below).

## Use the customer's existing Postgres with Azure Managed Identity

No password exists anywhere in this mode: the application requests a short-lived
Microsoft Entra token per database connection. That requires Entra support in the
image, which the stock upstream image does not have — the chart therefore defaults
to `genesis-umami`, built from [autonomize-ai/umami](https://github.com/autonomize-ai/umami)
by its Azure DevOps pipeline. Pointing `image.repository` back at
`ghcr.io/umami-software/umami` breaks this mode entirely.

Most environments need one line, because host, user, port and TLS mode are
inherited from the platform's own `global.database`, and the pod inherits the
platform ServiceAccount (`global.serviceAccount.name`, normally
`genesis-platform-sa`) which already carries the workload-identity annotations:

```yaml
genesis-umami:
  enabled: true
  database:
    bundled: false          # use the server the platform already talks to
```

Set `serviceAccount.create: true` only if umami needs a **dedicated** identity —
for example narrower database grants. That means registering a new federated
credential in Entra for the new ServiceAccount; inheriting the platform SA needs
no Entra change at all.

Override per-chart only where umami differs from the platform defaults:

```yaml
genesis-umami:
  database:
    authMethod: managed-identity   # or inherit global.database.authMethod
    external:
      host: customer-pg.postgres.database.azure.com   # "" => global.database.host
      user: umami-identity                            # the Entra principal
      name: umami                                     # database
      schema: umami                                   # keeps ~25 tables isolated
      sslMode: require                                # "" => global.database.sslMode
```

which renders a connection string carrying no credential at all:

```
postgresql://umami-identity@customer-pg.postgres.database.azure.com:5432/umami?schema=umami&sslmode=require
```

The chart then also sets `AZURE_USE_MANAGED_IDENTITY=true`, labels the pod
`azure.workload.identity/use: "true"`, and annotates the ServiceAccount with the
client and tenant IDs from `global.managedIdentity`.

### Required outside the chart

Helm cannot do these for you:

1. Map the identity as a Postgres principal on the server:
   `SELECT * FROM pgaadauth_create_principal('<identity-name>', false, false);`
2. Create the database named by `database.external.name` (default `umami`). It is
   a separate database on the customer's server, and `CREATE DATABASE` is usually
   a DBA-only grant.
3. Create the schema named by `database.external.schema` and grant `CREATE` on it
   — the app runs its own migrations into it on every start.
4. Only if you set `serviceAccount.create: true`: register a federated credential
   in Entra for that ServiceAccount **and** namespace. Inheriting the platform
   ServiceAccount (the default) requires nothing here.

### Cloud support

`managed-identity` here means **Azure Entra** specifically. The image acquires
tokens via `DefaultAzureCredential` against the Azure PostgreSQL scope, so there
is no AWS equivalent — RDS IAM auth is a different mechanism, where the signed
token *is* the password. On AWS (or anywhere non-Azure) use
`authMethod: password` with `database.existingSecret`.

The wider platform makes the same assumption: `genesis-lib` emits
`AZURE_USE_MANAGED_IDENTITY` for any managed-identity auth without consulting
`global.managedIdentity.provider`, so this is a platform-level constraint rather
than an umami one.

### TLS

`sslMode` is passed straight through to the image, which treats it differently
from libpq: **only the literal `disable` turns TLS off**. Every other value —
including `require` — connects with TLS *and* verifies the server certificate
against the system CA store, so `require`, `verify-ca` and `verify-full` behave
identically. Azure Database for PostgreSQL presents a publicly-trusted
certificate, so `require` works there as-is; a server using a private CA needs
that CA in the image's trust store.

### GitOps

**Every generated credential must be set explicitly under Argo CD.** The
generate-once path relies on a cluster `lookup`, which is always empty under
`helm template`, so anything it generates is re-minted on every sync — the same
constraint documented in `genesis/templates/01-internal-secrets.yaml`.

Two values are affected, and the second is the more damaging:

| Value | Set it to | If you don't |
|---|---|---|
| `app.appSecret` (or `app.existingSecret`) | any stable secret | `APP_SECRET` changes each sync, invalidating every session — users are logged out |
| `postgresql.auth.password` | any stable password | **only with `database.bundled: true`** — a new password is written to the chart Secret each sync while the already-initialised Postgres still expects its `initdb`-time password, so Umami cannot authenticate to its own database at all |

The Postgres case is easy to miss because it is the chart's **default** path
(`database.bundled: true`). `initdb` runs once, on an empty volume, and ignores
`POSTGRES_PASSWORD` on every later start — so the database keeps the original
password forever while `DATABASE_URL` drifts away from it on each sync.

Verify with two consecutive renders of identical values: the generated
`APP_SECRET` and `POSTGRES_PASSWORD` differ.

Customer installs typically avoid the second entirely by running
`database.bundled: false` against an existing server, where no password is
generated — under managed identity none exists at all.

## Notable values

| Key | Default | Notes |
|---|---|---|
| `enabled` | `false` | Gates the whole subchart (`genesis-umami.enabled`). |
| `image.repository` | `genesis-umami` | Bare name, composed with `global.imageRegistry`, so a customer registry override relocates it. The stock `ghcr.io/umami-software/umami` cannot do managed-identity auth. |
| `image.tag` | CI-managed | Written by the pipeline in `autonomize-ai/umami` on every build of its `develop` branch (`<upstream>-mi.<counter>`). amd64 only — a Node build cannot cross-compile, so arm64 would need QEMU. Exact version, never `latest`: umami owns a schema. |
| `image.digest` | `""` | Optional digest pin; wins over `tag` when set. |
| `imagePullSecrets` | `[]` | Usually unnecessary — the inherited platform ServiceAccount already carries them. Falls back to `global.serviceAccount.imagePullSecrets.{enabled,secretNames}`, the platform's own shape. |
| `database.bundled` | `true` | In-chart Postgres vs. external. |
| `database.authMethod` | `""` | `password` or `managed-identity`. Empty inherits `global.database.authMethod`. |
| `database.external.host` / `.user` / `.port` / `.sslMode` | `""` / `""` / `0` / `""` | Each falls back to the matching `global.database.*`. Read **only** under managed identity — password auth uses `external.url` or `existingSecret` and ignores these. |
| `database.external.name` | `umami` | Database to connect to. |
| `database.external.schema` | `umami` | Isolates umami's tables inside a shared database. |
| `serviceAccount.create` | `false` | `false` does **not** mean "no identity": with `name` also empty the pod inherits `global.serviceAccount.name` (`genesis-platform-sa`), which already has the workload-identity annotations and pull secrets. Set `true` only for a dedicated identity. |
| `app.existingSecret` / `.existingSecretKey` | `""` / `APP_SECRET` | Read `APP_SECRET` from a Secret you manage. Required under GitOps. |
| `database.existingSecret` / `.existingSecretKey` | `""` / `DATABASE_URL` | Read the connection string from a Secret you manage. Set the key to share the platform Secret — a namespaced name such as `UMAMI_DATABASE_URL` avoids colliding with other services in a Secret nearly every pod mounts. |
| `postgresql.image.repository` | `cgr.dev/chainguard/postgres` | Chainguard base; repoint to the org ACR mirror if policy requires. |
| `postgresql.image.digest` | pinned | Chainguard publishes only `latest` publicly, so the digest is pinned to stop a Postgres major bump landing on an existing PVC. Clear it to follow `tag`. |
| `postgresql.auth.password` | `""` | Empty → a strong password is generated into the chart Secret on first install (reused on upgrade). No default credential ships. |
| `postgresql.persistence.size` | `5Gi` | Set `enabled: false` for ephemeral. |
| `postgresql.podSecurityContext` | UID/GID `70` | The Chainguard image's `postgres` account. `initdb` hard-fails under any other UID. |
| `app.appSecret` | `""` | Auto-generated + reused across upgrades; set explicitly for GitOps. |
| `ingress.enabled` | `false` | Off by default; access via port-forward. |

## Tests

```bash
helm unittest genesis/charts/umami                       # rendering tests
genesis/charts/umami/tests/credential-consistency.sh     # generated-credential invariant
```

The suite covers default-off (0 resources, including the NOTES.txt message),
the enabled bundled-Postgres stack, both external-DB paths (`external.url` and
`existingSecret`), the `required` failure when neither is supplied, exact-version
and digest image pinning, the image-defined UIDs, storage and ingress gating.
Run it for the current count rather than quoting one here — a hardcoded number
goes stale the next time a case is added.

The shell check guards the one thing helm-unittest cannot express: `DATABASE_URL`
and `POSTGRES_PASSWORD` are separate Secret keys with no cross-field assertion, so
a regex check passes even when the two generated values disagree — which is
exactly the failure that made the bundled DB reject Umami on a first install.

## Container-image exceptions

Umami is third-party OSS with no Chainguard/Wolfi build, and both images run as
their own image-defined non-root UIDs (`1001` for Umami, `70` for Chainguard
Postgres) rather than the platform's usual `65532`. Both are marked
`helm-guard-exempt` in `values.yaml` with the reasoning inline. This is scoped to
an optional, default-off subchart — nothing is pulled unless
`genesis-umami.enabled=true`.

First login is `admin` / `umami` — **change it immediately**. After creating a
website in the UI, point the consuming app's tracker (`UMAMI_HOST` /
`UMAMI_WEBSITE_ID`) at this service.
