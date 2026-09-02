{{/* Expand the name of the chart. */}}
{{- define "umami.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "umami.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "umami.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "umami.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "umami.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "umami.labels" -}}
app.kubernetes.io/name: {{ include "umami.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: genesis
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "umami.selectorLabels" -}}
app.kubernetes.io/name: {{ include "umami.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Registry for PLATFORM-built images, mirroring genesis-lib.image so
`--set global.imageRegistry=<customer-acr>` relocates umami along with every
other platform image (the customer-registry-first install path). The `default`
also covers an explicitly empty value, not just a missing key.
*/}}
{{- define "umami.imageRegistry" -}}
{{- dig "imageRegistry" "" (.Values.global | default dict) | default "sprintregistry.azurecr.io" -}}
{{- end -}}

{{/*
Image reference. A digest, when set, wins over the tag so the pulled image is
immutable — required for the bundled Postgres, whose only public Chainguard tag
is the floating `latest`.

`registry` is OPTIONAL and prefixes the repository. Pass it for platform images,
whose repository is a bare name (`genesis-umami`) that global.imageRegistry
relocates. Omit it for third-party images that carry their own registry in
`repository` (cgr.dev/chainguard/postgres), which must not be rewritten — the
bundled Postgres is pulled from Chainguard directly, not from the platform ACR.

Usage: include "umami.image" (dict "img" .Values.image "registry" (include "umami.imageRegistry" .))
       include "umami.image" (dict "img" .Values.postgresql.image)
*/}}
{{- define "umami.image" -}}
{{- $repo := .img.repository -}}
{{- with .registry }}{{ $repo = printf "%s/%s" . $repo }}{{ end -}}
{{- if .img.digest -}}
{{- printf "%s@%s" $repo .img.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo .img.tag -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding DATABASE_URL + APP_SECRET. */}}
{{- define "umami.secretName" -}}
{{- if .Values.database.existingSecret -}}
{{- .Values.database.existingSecret -}}
{{- else -}}
{{- include "umami.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
Reuse a key already present in this chart's Secret (so helm upgrade doesn't
rotate generated credentials) or fall back to a freshly generated value.
Usage: include "umami.persistedOrRandom" (dict "ctx" . "key" "APP_SECRET" "len" 40)
*/}}
{{- define "umami.persistedOrRandom" -}}
{{- $ctx := .ctx -}}
{{- $existing := lookup "v1" "Secret" $ctx.Release.Namespace (include "umami.fullname" $ctx) -}}
{{- if and $existing $existing.data (hasKey $existing.data .key) -}}
{{- index $existing.data .key | b64dec -}}
{{- else -}}
{{- randAlphaNum (int .len) -}}
{{- end -}}
{{- end -}}

{{/*
Resolve a credential ONCE per render and memoise it on .Values, so every call
site in every template observes the same value.

Without this, each call to a generating helper mints a fresh random string on a
first install (no Secret exists yet to look up). That is how DATABASE_URL and
POSTGRES_PASSWORD came to disagree: Postgres initialised with one password while
Umami connected with another. Memoising makes the invariant structural rather
than something each call site has to remember to preserve.
Usage: include "umami.resolveOnce" (dict "ctx" . "into" $someDict "field" "_pw" "key" "POSTGRES_PASSWORD" "explicit" $v "len" 24)
*/}}
{{- define "umami.resolveOnce" -}}
{{- $into := .into -}}
{{- if not (hasKey $into .field) -}}
{{- $_ := set $into .field (.explicit | default (include "umami.persistedOrRandom" (dict "ctx" .ctx "key" .key "len" .len))) -}}
{{- end -}}
{{- get $into .field -}}
{{- end -}}

{{/* APP_SECRET: explicit value wins, else persisted, else generated (once). */}}
{{- define "umami.appSecret" -}}
{{- include "umami.resolveOnce" (dict "ctx" . "into" .Values.app "field" "_resolvedAppSecret" "key" "APP_SECRET" "explicit" .Values.app.appSecret "len" 40) -}}
{{- end -}}

{{/* Bundled-Postgres password: explicit value wins, else persisted, else generated (once). */}}
{{- define "umami.postgresPassword" -}}
{{- include "umami.resolveOnce" (dict "ctx" . "into" .Values.postgresql.auth "field" "_resolvedPassword" "key" "POSTGRES_PASSWORD" "explicit" .Values.postgresql.auth.password "len" 24) -}}
{{- end -}}

{{/*
Effective database auth method: this chart's value, else the platform's
global.database.authMethod, else "password". Inheriting from global is what lets
an environment already running on managed identity pick it up with no extra
configuration here.
*/}}
{{- define "umami.databaseAuthMethod" -}}
{{- $global := .Values.global | default dict -}}
{{- $gdb := dig "database" dict $global -}}
{{- .Values.database.authMethod | default (dig "authMethod" "" $gdb) | default "password" -}}
{{- end -}}

{{/*
True when Entra/Workload-Identity auth is in effect.

BOTH spellings are accepted, because the rest of the platform accepts both:
docs/GLOBAL-VALUES-REFERENCE.md documents the underscore, the umbrella prereq
guard allows it ("mirror that here rather than rejecting an overlay the platform
actually honours"), and genesis-de-db-auth-secret.yaml matches on either. Hyphen
only would treat `managed_identity` as password auth and then fail the WHOLE
umbrella render on a missing external.url — an optional default-off bundle
blocking a platform upgrade, with an error naming the wrong key.
*/}}
{{- define "umami.usesManagedIdentity" -}}
{{- if has (include "umami.databaseAuthMethod" .) (list "managed-identity" "managed_identity") -}}true{{- end -}}
{{- end -}}

{{/*
Name of the ServiceAccount the pod runs as. Workload Identity binds a federated
credential to a specific ServiceAccount + namespace, so this must be stable.

With neither create nor name set, inherit the platform's shared SA
(global.serviceAccount.name, i.e. genesis-platform-sa) exactly as every
genesis-lib service does. The umbrella already creates it WITH the
azure.workload.identity annotations AND the registry pull secrets, so MI works
with no per-environment Entra change and no extra pull-secret wiring. Without
this fallback the pod silently runs as `default` — a blank SA no federated
credential is bound to — so the render looks complete and the first database
connection fails.

Deliberately NOT genesis-lib's hardcoded "genesis-platform-sa" default: a
standalone install has no global, and naming an SA that does not exist stops the
pod from starting. Empty keeps the pre-existing behaviour there.
*/}}
{{- define "umami.serviceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else if .Values.serviceAccount.create -}}
{{- include "umami.fullname" . -}}
{{- else -}}
{{- dig "name" "" (dig "serviceAccount" dict (.Values.global | default dict)) -}}
{{- end -}}
{{- end -}}

{{/*
Image pull secrets in the platform's OWN shape:
global.serviceAccount.imagePullSecrets.{enabled,secretNames} — what
genesis-lib.imagePullSecrets reads and what every env-values overlay sets
(values-integration.yaml enables `acr-auth` there). The Bitnami-style
`global.imagePullSecrets` is set in NO values file in this repo, so reading that
address yields a blank and umami would be the one service that ignores a
platform-wide registry credential — ImagePullBackOff as soon as
image.repository is repointed at the ACR mirror, as values.yaml advises.

A chart-local imagePullSecrets (standard [{name: …}] form) overrides global for
standalone use. Redundant once the pod inherits genesis-platform-sa, which
already carries these — kept for a dedicated-SA or standalone install.
*/}}
{{- define "umami.imagePullSecrets" -}}
{{- if .Values.imagePullSecrets -}}
{{- toYaml .Values.imagePullSecrets -}}
{{- else -}}
{{- $gips := dig "imagePullSecrets" dict (dig "serviceAccount" dict (.Values.global | default dict)) -}}
{{- if $gips.enabled -}}
{{- range $gips.secretNames | default list }}
- name: {{ . }}
{{- end }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Workload-identity annotations, mirroring genesis-lib.serviceAccountAnnotations so
this subchart behaves like every other platform service. That includes
global.serviceAccount.annotations: an org that stamps every ServiceAccount
platform-wide (cost centre, ownership, compliance) must not find umami's the one
exception. Precedence mirrors genesis-lib's merge order — workload identity, then
global, then chart-local — where the first writer of a key wins.

Only reached when serviceAccount.create=true. On the default path the pod
inherits genesis-platform-sa, which the umbrella already annotates.
*/}}
{{- define "umami.serviceAccountAnnotations" -}}
{{- $annotations := dict -}}
{{- $mi := dig "managedIdentity" dict (.Values.global | default dict) -}}
{{- if $mi.enabled -}}
{{- if eq (default "azure" $mi.provider) "azure" -}}
{{- $_ := set $annotations "azure.workload.identity/client-id" (dig "azure" "clientId" "" $mi | toString) -}}
{{- $_ := set $annotations "azure.workload.identity/tenant-id" (dig "azure" "tenantId" "" $mi | toString) -}}
{{- else if eq $mi.provider "aws" -}}
{{- $_ := set $annotations "eks.amazonaws.com/role-arn" (dig "aws" "roleArn" "" $mi | toString) -}}
{{- end -}}
{{- end -}}
{{- $annotations = merge $annotations (dig "annotations" dict (dig "serviceAccount" dict (.Values.global | default dict))) -}}
{{- $annotations = merge $annotations (.Values.serviceAccount.annotations | default dict) -}}
{{- if $annotations -}}
{{- toYaml $annotations -}}
{{- end -}}
{{- end -}}

{{/*
Structured host/port/user/sslMode, each falling back to the platform's
global.database.* so a customer overlay does not restate what it already
configured for every other service.
*/}}
{{- define "umami.dbHost" -}}
{{- $gdb := dig "database" dict (.Values.global | default dict) -}}
{{- .Values.database.external.host | default (dig "host" "" $gdb) | required "database.external.host (or global.database.host) is required when database.bundled=false" -}}
{{- end -}}

{{- define "umami.dbPort" -}}
{{- $gdb := dig "database" dict (.Values.global | default dict) -}}
{{- $p := .Values.database.external.port | default (dig "port" 0 $gdb) -}}
{{- if $p }}{{ $p }}{{ else }}5432{{ end -}}
{{- end -}}

{{- define "umami.dbUser" -}}
{{- $gdb := dig "database" dict (.Values.global | default dict) -}}
{{- .Values.database.external.user | default (dig "username" "" $gdb) | required "database.external.user (or global.database.username) is required when database.bundled=false" -}}
{{- end -}}

{{- define "umami.dbSslMode" -}}
{{- $gdb := dig "database" dict (.Values.global | default dict) -}}
{{- .Values.database.external.sslMode | default (dig "sslMode" "" $gdb) | default "require" -}}
{{- end -}}

{{/*
Query string shared by every non-bundled URL: schema isolation and TLS mode.
*/}}
{{- define "umami.dbQuery" -}}
{{- $q := list -}}
{{- with .Values.database.external.schema }}{{ $q = append $q (printf "schema=%s" .) }}{{ end -}}
{{- $q = append $q (printf "sslmode=%s" (include "umami.dbSslMode" .)) -}}
{{- printf "?%s" (join "&" $q) -}}
{{- end -}}

{{/*
DATABASE_URL for the bundled or external Postgres (used in the chart Secret).

The bundled password MUST be passed in rather than resolved here: on a first
install there is no Secret to look up, so every call to umami.postgresPassword
mints a *different* random string. Resolving it once in secret.yaml and threading
it through keeps DATABASE_URL and POSTGRES_PASSWORD in agreement — otherwise
Postgres initialises with one password while Umami connects with another.
Usage: include "umami.databaseUrl" (dict "ctx" . "password" $pw)
*/}}
{{- define "umami.databaseUrl" -}}
{{- $ctx := .ctx -}}
{{- if $ctx.Values.database.bundled -}}
{{- printf "postgresql://%s:%s@%s:5432/%s" $ctx.Values.postgresql.auth.username .password (include "umami.postgresql.fullname" $ctx) $ctx.Values.postgresql.auth.database -}}
{{- else if include "umami.usesManagedIdentity" $ctx -}}
{{- /*
  Managed identity: deliberately NO password in the URL. The credential is a
  short-lived Entra token the application fetches per connection, so anything
  embedded here would be stale within the hour. `user` must be the Entra
  principal mapped on the server (pgaadauth_create_principal).
*/ -}}
{{- printf "postgresql://%s@%s:%s/%s%s"
      (include "umami.dbUser" $ctx)
      (include "umami.dbHost" $ctx)
      (include "umami.dbPort" $ctx)
      $ctx.Values.database.external.name
      (include "umami.dbQuery" $ctx) -}}
{{- else -}}
{{- /*
  Password auth against an external server. The credential must arrive as a
  whole connection string (or via database.existingSecret) — this chart
  deliberately offers no structured password field, so a plaintext password
  never has to live in values.yaml.
*/ -}}
{{- required "database.external.url is required when database.bundled=false with password auth and no existingSecret is set" $ctx.Values.database.external.url -}}
{{- end -}}
{{- end -}}

{{/*
Secret holding the credentials the staff-access containers need
(UMAMI_ADMIN_PASSWORD, UMAMI_STAFF_PASSWORD).

Defaults to the platform secret when one is configured for the app, so these
sit beside APP_SECRET and rotate in the same place, rather than introducing a
third Secret for two keys.
*/}}
{{- define "umami.staffSecretName" -}}
{{- if .Values.staffSetup.existingSecret -}}
{{- .Values.staffSetup.existingSecret -}}
{{- else if .Values.app.existingSecret -}}
{{- .Values.app.existingSecret -}}
{{- else -}}
{{- include "umami.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
Umami user id for the shared staff account.

CALCULATED, not stored -- the same reasoning as the website ids each app's
chart derives. `uuidv4` would return a new value on every render, so every
ArgoCD sync would create another account and orphan the last one; a `lookup`
of what already exists is always empty under `helm template`, which is exactly
how ArgoCD renders. A pure function of the release name survives both.

Sliced into the 8-4-4-4-12 shape with the version ('4') and variant ('a')
characters forced, because Umami validates the id strictly and rejects
anything that merely looks uuid-shaped.

Override staffSetup.userId to pin an exact value.
*/}}
{{- define "umami.staffUserId" -}}
{{- if .Values.staffSetup.userId -}}
{{- .Values.staffSetup.userId -}}
{{- else -}}
{{- $h := sha256sum (printf "%s/umami-staff" (include "umami.fullname" .)) -}}
{{- printf "%s-%s-4%s-a%s-%s" (substr 0 8 $h) (substr 8 12 $h) (substr 13 16 $h) (substr 17 20 $h) (substr 20 32 $h) -}}
{{- end -}}
{{- end -}}
