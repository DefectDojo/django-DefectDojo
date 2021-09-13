---
title: "Configuration"
description: "DefectDojo is highly configurable."
draft: false
weight: 3
---

## Configuration in files

#### `dojo/settings/settings.dist.py`

The main settings are all stored in the [`settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py) file. Most of these parameters can be set by environment variables.

#### Environment file (not stored in git)

`settings.dist.py` reads environment variables from a file whose name is specified in the environment variable `DD_ENV_PATH`. If this variable is not set, the default `.env.prod` is used. The file must be located in the `dojo/settings` directory.

An example can be found in [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

#### `local_settings.py` (not stored in git, not used in release mode)

`local_settings.py` can contain more complex customizations such as adding MIDDLEWARE or INSTALLED_APP entries.
This file is processed *after* settings.dist.py is processed, so you can modify settings delivered by Defect Dojo out of the box.
 The file must be located in the `dojo/settings` directory.

An example can be found in [`template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

In docker-compose release mode, files in `docker/extra_settings/` will be copied into `dojo/settings/` on startup.

## Configuration in the UI

Users with the superuser status can configure more options via the UI under `Configuration` / `System Settings`. 
