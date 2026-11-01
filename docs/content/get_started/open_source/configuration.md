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

#### Outgoing email with Helm

The Open Source chart can configure SMTP through `extraSecrets.DD_EMAIL_URL`.
This setting is used for password-reset emails and email notifications. Configure
it for both Django and Celery: the chart's `extraSecrets` mechanism makes the same
Secret available to the Django, Celery worker, Celery beat and initializer containers.

Create an override file such as `smtp-values.yaml`:

```yaml
extraSecrets:
  DD_EMAIL_URL: "smtp+tls://dojo%40example.com:URL_ENCODED_PASSWORD@smtp.example.com:587"

# Use the URL that recipients can open, including the scheme and any public port.
siteUrl: "https://dojo.example.com"

# Restart application pods when chart-managed configuration or secrets change.
trackConfig: enabled
```

Replace the example host and credentials with those supplied by your SMTP provider.
Percent-encode special characters in the username and password separately; for
example, `dojo@example.com` becomes `dojo%40example.com`. Do not encode the entire URL.

Choose the URL scheme that matches your server:

| Connection | Example |
| --- | --- |
| STARTTLS | `smtp+tls://USER:PASSWORD@smtp.example.com:587` |
| Implicit TLS | `smtp+ssl://USER:PASSWORD@smtp.example.com:465` |
| Internal relay without authentication or TLS | `smtp://mail-relay.example.internal:25` |

For a local test receiver such as Mailpit in the same namespace, use
`smtp://mailpit:1025` instead. The receiver must already be running and reachable
through a Service named `mailpit`. `localhost` points to the application's own Pod,
not to another Pod or your workstation.

Treat the override file as a credential: restrict access and keep it out of version
control. `extraSecrets` creates a Kubernetes Secret, but base64 encoding is not
encryption, and Helm also stores supplied values in its release data. Avoid placing
SMTP credentials directly in command-line arguments or sharing rendered Secrets.

Apply the override alongside your existing installation values. For example, for
an existing release named `defectdojo` in namespace `defectdojo`:

```bash
helm list --namespace defectdojo
helm upgrade defectdojo defectdojo/defectdojo \
  --namespace defectdojo \
  --version <CURRENT_CHART_VERSION> \
  -f your-existing-values.yaml \
  -f smtp-values.yaml
```

The command assumes the DefectDojo chart repository is already configured. Replace
`<CURRENT_CHART_VERSION>` with the installed chart version shown by `helm list`
(without the `defectdojo-` prefix) to avoid upgrading the application as part of
this configuration change. Use your maintained installation values, preserving
other `extraSecrets` entries. Do not reuse first-install `createSecret=true`,
`createPostgresqlSecret=true` or `createValkeySecret=true` flags on an upgrade.

With `trackConfig: enabled`, the updated Secret changes the application Pod template
checksums and triggers a rollout. Wait for Django and Celery to become ready:

```bash
kubectl -n defectdojo rollout status deployment/defectdojo-django
kubectl -n defectdojo rollout status deployment/defectdojo-celery-worker
kubectl -n defectdojo rollout status deployment/defectdojo-celery-beat
```

These resource names assume the release name above and no name overrides; adjust
them if your installation uses different names.

To test the SMTP transport from Django, replace `RECIPIENT@example.com` and the
sender with addresses accepted by your SMTP provider, then run:

```bash
kubectl -n defectdojo exec deployment/defectdojo-django -c uwsgi -- \
  python /app/manage.py shell -c 'from django.core.mail import send_mail; print(send_mail("DefectDojo SMTP test", "SMTP transport test", "dojo@example.com", ["RECIPIENT@example.com"], fail_silently=False))'
```

A result of `1` means the mail backend accepted one message for sending; verify
receipt in the target mailbox or local test receiver as well. Repeat the command
with `deployment/defectdojo-celery-worker -c celery` to check the worker's SMTP
configuration. This direct test does not exercise Celery task delivery or the
application's notification preferences.

Finally, set the sender address (`email_from`) and enable the applicable mail
notification settings under **Configuration / System Settings**, and review the
recipient's notification preferences. Test a password reset for an active test
user with an email address, check that the link uses your public `siteUrl`, and
trigger an email notification to verify the asynchronous Celery path.

If sending fails:

- A connection attempt to `localhost:25` usually means the expected `DD_EMAIL_URL`
  did not reach the process. Check the Secret reference and whether the Pod rolled
  out after the configuration change.
- A timeout or connection refusal to your SMTP host requires checking DNS, the
  Service and endpoints for an in-cluster receiver, network policies and outbound
  connectivity. Installing the Helm chart does not install an SMTP server.
- Authentication or TLS errors require checking the URL encoding, credentials,
  provider authentication requirements, scheme, port and certificate trust.
- If the direct tests succeed but notifications do not arrive, check the sender,
  notification settings, recipient preferences and Celery worker logs.

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
