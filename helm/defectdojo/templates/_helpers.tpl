{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "defectdojo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "defectdojo.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}


{{/*
  Determine the hostname to use for PostgreSQL/mySQL/Redis.
*/}}
{{- define "postgresql.hostname" -}}
{{- if eq .Values.database "postgresql" -}}
{{- if .Values.postgresql.enabled -}}
{{- printf "%s-%s" .Release.Name "postgresql" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Values.postgresql.postgresServer -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "postgresqlha.hostname" -}}
{{- if eq .Values.database "postgresqlha" -}}
{{- if .Values.postgresqlha.enabled -}}
{{- printf "%s-%s" .Release.Name "postgresqlha-pgpool" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Values.postgresqlha.postgresServer -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "mysql.hostname" -}}
{{- if eq .Values.database "mysql" -}}
{{- if .Values.mysql.enabled -}}
{{- printf "%s-%s" .Release.Name "mysql" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Values.mysql.mysqlServer -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "redis.hostname" -}}
{{- if eq .Values.celery.broker "redis" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-%s" .Release.Name "redis-master" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Values.redis.redisServer -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
  Determine the protocol to use for Redis.
*/}}
{{- define "redis.scheme" -}}
{{- if eq .Values.celery.broker "redis" -}}
{{- if .Values.redis.transportEncryption.enabled -}}
{{- printf "rediss" -}}
{{- else -}}
{{- printf "redis" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
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
{{ .Release.Name }}-initializer-{{- printf "%s" now | date "2006-01-02-15-04" -}}
{{- end -}}

{{/*
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
