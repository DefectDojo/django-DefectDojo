{{- /* vim: set filetype=mustache: */}}
{{- /*
  Expand the name of the chart.
*/}}
{{- define "defectdojo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /*
  Create a default fully qualified app name.
  We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
  If release name contains chart name it will be used as a full name.
*/}}
{{- define "defectdojo.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- /*
  Create chart name and version as used by the chart label.
*/}}
{{- define "defectdojo.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /*
  Create the name of the service account to use
*/}}
{{- define "defectdojo.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "defectdojo.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "defectdojo" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- /*
  Determine the hostname to use for PostgreSQL/Redis.
*/}}
{{- define "postgresql.hostname" -}}
{{- if .Values.postgresql.enabled -}}
{{-  if eq .Values.postgresql.architecture "replication" -}}
{{-   printf "%s-%s-%s" .Release.Name "postgresql" .Values.postgresql.primary.name | trunc 63 | trimSuffix "-" -}}
{{-  else -}}
{{-   printf "%s-%s" .Release.Name "postgresql" | trunc 63 | trimSuffix "-" -}}
{{-  end -}}
{{- else -}}
{{- .Values.postgresServer | default "127.0.0.1" | quote -}}
{{- end -}}
{{- end -}}

{{- define "redis.hostname" -}}
{{- if eq .Values.celery.broker "redis" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-%s" .Release.Name "redis-master" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Values.redisServer | default "127.0.0.1" | quote -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- /*
  Determine the protocol to use for Redis.
*/}}
{{- define "redis.scheme" -}}
{{- if eq .Values.celery.broker "redis" -}}
{{- if .Values.redis.tls.enabled -}}
{{- printf "rediss" -}}
{{- else if .Values.redis.sentinel.enabled -}}
{{- printf "sentinel" -}}
{{- else -}}
{{- printf "redis" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- /*
  Builds the repository names for use with local or private registries
*/}}
{{- define "celery.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-django
{{- end -}}

{{- define "django.nginx.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-nginx
{{- end -}}

{{- define "django.uwsgi.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-django
{{- end -}}

{{- define "initializer.repository" -}}
{{- printf "%s" .Values.repositoryPrefix -}}/defectdojo-django
{{- end -}}

{{- define "initializer.jobname" -}}
{{- if .Values.initializer.staticName -}}
{{ .Release.Name }}-initializer
{{- else -}}
{{ .Release.Name }}-initializer-{{- printf "%s" now | date "2006-01-02-15-04" -}}
{{- end -}}
{{- end -}}

{{- /*
  Creates the array for DD_ALLOWED_HOSTS in configmap
*/}}
{{- define "django.allowed_hosts" -}}
{{- if .Values.alternativeHosts -}}
{{- $hosts := .Values.host -}}
{{- printf "%s,%s" $hosts (join "," .Values.alternativeHosts) -}}
{{- else -}}
{{ .Values.host }}
{{- end -}}
{{- end -}}

{{- /*
  Creates the persistentVolumeName
*/}}
{{- define "django.pvc_name" -}}
{{- if .Values.django.mediaPersistentVolume.persistentVolumeClaim.create -}}
{{- printf "%s-django-media" .Release.Name -}}
{{- else -}}
{{ .Values.django.mediaPersistentVolume.persistentVolumeClaim.name }}
{{- end -}}
{{- end -}}

{{- /*
  Define db-migration-checker
*/}}
{{- define "dbMigrationChecker" -}}
- name: db-migration-checker
  command:
  - sh
  - -c
  - while ! /app/manage.py migrate --check; do echo "Database is not migrated to the latest state yet"; sleep 5; done; echo "Database is migrated to the latest state";
  image: '{{ template "django.uwsgi.repository" . }}:{{ .Values.tag }}'
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  {{- if .Values.securityContext.enabled }}
  securityContext:
    {{- include "helpers.securityContext" (list
    .Values
    "securityContext.containerSecurityContext"
    "dbMigrationChecker.containerSecurityContext"
  ) | nindent 4 }}
  {{- end }}
  envFrom:
  - configMapRef:
      name: {{ .fullName }}
  - secretRef:
      name: {{ .fullName }}-extrasecrets
      optional: true
  env:
  {{- if .Values.django.uwsgi.enableDebug }}
  - name: DD_DEBUG
    value: 'True'
  {{- end }}
  - name: DD_DATABASE_PASSWORD
    valueFrom:
      secretKeyRef:
        name: {{ .Values.postgresql.auth.existingSecret | default "defectdojo-postgresql-specific" }}
        key: {{ .Values.postgresql.auth.secretKeys.userPasswordKey | default "postgresql-password" }}
  {{- with .Values.extraEnv }}
    {{- toYaml . | nindent 2 }}
  {{- end }}
  {{- with.Values.dbMigrationChecker.extraEnv }}
    {{- toYaml . | nindent 2 }}
  {{- end }}
  resources:
    {{- toYaml .Values.dbMigrationChecker.resources | nindent 4 }}
  {{- with .Values.dbMigrationChecker.extraVolumeMounts }}
  volumeMounts:
    {{- . | toYaml | nindent 4 }}
  {{- end }}
{{- end -}}

{{- /*
Returns the JSON representation of the value for a dot-notation path
from a given context.
  Args:
    0: context (e.g., .Values)
    1: path (e.g., "foo.bar")
*/}}
{{- define "helpers.getValue" -}}
  {{- $ctx := merge dict (index . 0) -}}
  {{- $path := index . 1 -}}
  {{- $parts := splitList "." $path -}}
  {{- $value := $ctx -}}
  {{- range $idx, $part := $parts -}}
    {{- if kindIs "map" $value -}}
      {{- $value = index $value $part -}}
    {{- else -}}
      {{- $value = "" -}}
      {{- /* Exit early by setting to last iteration */}}
      {{- $idx = sub (len $parts) 1 -}}
    {{- end -}}
  {{- end -}}
  {{- toJson $value -}}
{{- end -}}

{{- /*
  Build the security context.
  Args:
    0: values context (.Values)
    1: the default security context key (e.g. "securityContext.containerSecurityContext")
    2: the key under the context with security context (e.g., "foo.bar")
*/}}
{{- define "helpers.securityContext" -}}
{{- $securityContext := dict -}}
{{- $values := merge dict (index . 0) -}}
{{- $defaultSecurityContextKey := merge dict (index . 1) -}}
{{- $securityContextKey := merge dict (index . 2) -}}
{{- with $values }}
  {{- $securityContext = (merge
    $securityContext
    (include "helpers.getValue" (list $values $defaultSecurityContextKey) | fromJson)
    (include "helpers.getValue" (list $values $securityContextKey) | fromJson)
  ) -}}
{{- end -}}
{{- with $securityContext -}}
{{- . | toYaml | nindent 2 -}}
{{- end -}}
{{- end -}}
