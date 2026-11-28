---
title: "Configuration"
description: "DefectDojo is highly configurable."
draft: false
weight: 2
audience: opensource
aliases:
  - /en/open_source/installation/configuration
---
## dojo/settings/settings.dist.py

The main settings are stored in [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py). It is great to use this file as a reference for what can be configured, but it shouldn\'t be edited directly, because changes will be overwritten when updating DefectDojo. There are several methods to change the default settings:

### Environment variables

Most parameters can be set by environment variables. 

When you deploy DefectDojo via **Docker Compose**, you can set environment variables in [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml). Be aware you have to set the variables for three services: `uwsgi`, `celerybeat` and `celeryworker`.

When you deploy DefectDojo in a **Kubernetes** cluster, you can set environment variables as `extraConfigs` and `extraSecrets` in [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml).

### Environment file (not with Docker Compose or Kubernetes)

`settings.dist.py` reads environment variables from a file whose name is specified in the environment variable `DD_ENV_PATH`. If this variable is not set, the default `.env.prod` is used. The file must be located in the `dojo/settings` directory.

An example can be found in [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

### local_settings.py

`local_settings.py` can contain more complex customizations such as adding MIDDLEWARE or INSTALLED_APP entries.
This file is processed *after* settings.dist.py is processed, so you can modify settings delivered by DefectDojo out of the box.
 The file must be located in the `dojo/settings` directory. Environment variables in this file must not have the `DD_` prefix.
If the file is missing feel free to create it. Do not edit `settings.dist.py` directly.

An example can be found in [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

In Docker Compose release mode, files in `docker/extra_settings/` (relative to the file `docker-compose.yml`) will be copied into `dojo/settings/` in the docker container on startup.

`local_settings.py` can be used in Kubernetes as well. Variable `localsettingspy` will be stored as ConfigMap and mounted to responsible location of containers.

## Configuration in the UI

Users with the superuser status can configure more options via the UI under `Configuration` / `System Settings`. 

### Environment settings that System Settings can override

The settings below can also be saved for the instance in System Settings, in the UI or through `/api/v2/system_settings/`. A value saved there takes precedence over the environment variable. Leave the field empty to keep using the environment variable, which stays the default, so an instance that never saves a value behaves as before.

| Environment variable | System Settings field (API name) |
|---|---|
| `DD_EDITABLE_MITIGATED_DATA` | Editable mitigated data (`editable_mitigated_data`) |
| `DD_DISABLE_FINDING_MERGE` | Disable finding merge (`disable_finding_merge`) |
| `DD_TRACK_IMPORT_HISTORY` | Track import history (`track_import_history`) |
| `DD_DELETE_PREVIEW` | Delete preview (`delete_preview`) |
| `DD_DUPLICATE_CLUSTER_CASCADE_DELETE` | Delete duplicate clusters (`duplicate_cluster_cascade_delete`) |
| `DD_USE_FIRST_SEEN` | Use first seen date (`use_first_seen`) |
| `DD_QUALYS_LEGACY_SEVERITY_PARSING` | Qualys legacy severity parsing (`qualys_legacy_severity_parsing`) |
| `DD_QUALYS_WAS_UNIQUE_ID` | Qualys WAS unique id (`qualys_was_unique_id`) |
| `DD_QUALYS_WAS_WEAKNESS_IS_VULN` | Qualys WAS weakness is a vulnerability (`qualys_was_weakness_is_vuln`) |
| `DD_SONARQUBE_API_PARSER_HOTSPOTS` | SonarQube API hotspots (`sonarqube_api_parser_hotspots`) |
| `DD_JIRA_WEBHOOK_ALLOW_FINDING_GROUP_REOPEN` | Jira webhook reopens finding groups (`jira_webhook_allow_finding_group_reopen`) |
| `DD_ALERT_REFRESH` | Refresh alerts (`alert_refresh`) |
| `DD_DISABLE_ALERT_COUNTER` | Disable alert counter (`disable_alert_counter`) |
| `DD_MAX_ALERTS_PER_USER` | Maximum alerts per user (`max_alerts_per_user`) |
| `DD_NOTIFICATION_SCAN_ADDED_MAX_FINDINGS` | Findings listed in a scan notification (`notification_scan_added_max_findings`) |
| `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP` | System notifications that override personal ones (`notifications_system_level_trump`) |
| `DD_SLA_NOTIFY_PRE_BREACH` | Days before an SLA breach to notify (`sla_notify_pre_breach`) |
| `DD_SLA_NOTIFY_POST_BREACH` | Days after an SLA breach to keep notifying (`sla_notify_post_breach`) |
| `DD_HASHCODE_FIELDS_PER_SCANNER` | Hash code fields per scanner (`hashcode_fields_per_scanner`) |
| `DD_DEDUPLICATION_ALGORITHM_PER_PARSER` | Deduplication algorithm per parser (`deduplication_algorithm_per_parser`) |
| `DD_API_TOKENS_ENABLED` | API tokens enabled (`api_tokens_enabled`) |
| `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` | API token endpoint enabled (`api_token_auth_endpoint_enabled`) |
| `DD_API_TOKEN_DEFAULT_EXPIRY_DAYS` | API token expiry (days) (`api_token_default_expiry_days`) |
| `DD_AUDITLOG_FLUSH_RETENTION_PERIOD` | Audit log retention (months) (`auditlog_flush_retention_period`), where `-1` keeps every entry |
| `DD_JIRA_SSL_VERIFY` | Verify Jira TLS certificates (`jira_ssl_verify`) |
| `DD_JIRA_CONNECT_TIMEOUT` | Jira connect timeout (seconds) (`jira_connect_timeout`) |
| `DD_JIRA_READ_TIMEOUT` | Jira read timeout (seconds) (`jira_read_timeout`) |
| `DD_JIRA_MAX_RETRIES` | Jira retries (`jira_max_retries`) |
| `DD_JIRA_DESCRIPTION_MAX_LENGTH` | Jira description length limit (`jira_description_max_length`) |
| `DD_JIRA_EXTRA_ISSUE_TYPES` | Extra Jira issue types (`jira_extra_issue_types`), added to the types the variable lists rather than replacing them |

The two per-scanner maps, `hashcode_fields_per_scanner` and `deduplication_algorithm_per_parser`, hold only the entries you want to change: each entry replaces or adds to the deployment's map, the same way the environment variables do. Saving either one does not recompute the hash codes of existing Findings; run `python manage.py dedupe --hash_code_only` for that, adding `--parser '<scan type>'` to limit it to the scan types you changed.
