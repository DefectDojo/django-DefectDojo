---
title: 配置
description: DefectDojo 具有高度可配置性。
draft: false
weight: 2
audience: opensource
aliases:
- /zh-hans/en/open_source/installation/configuration
---

## dojo/settings/settings.dist.py

主要设置存储在 [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py) 中。这个文件非常适合作为参考，了解可以配置哪些内容，但不应直接编辑它，因为在更新 DefectDojo 时，所做的更改会被覆盖。有以下几种方法可以更改默认设置：

### 环境变量

大多数参数都可以通过环境变量设置。

当您通过 **Docker Compose** 部署 DefectDojo 时，可以在 [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml) 中设置环境变量。请注意，您需要为三个服务分别设置变量：`uwsgi`、`celerybeat` 和 `celeryworker`。

当您在 **Kubernetes** 集群中部署 DefectDojo 时，可以在 [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml) 中以 `extraConfigs` 和 `extraSecrets` 的形式设置环境变量。

### 环境文件（不适用于 Docker Compose 或 Kubernetes）

`settings.dist.py` 会从一个文件中读取环境变量，该文件的名称由环境变量 `DD_ENV_PATH` 指定。如果未设置此变量，则使用默认值 `.env.prod`。该文件必须位于 `dojo/settings` 目录下。

您可以在 [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env) 中找到示例。

### local_settings.py

`local_settings.py` 可以包含更复杂的自定义配置，例如添加 MIDDLEWARE 或 INSTALLED_APP 条目。
此文件会在 settings.dist.py 处理*之后*被处理，因此您可以修改 DefectDojo 开箱即用交付的设置。
 该文件必须位于 `dojo/settings` 目录下。此文件中的环境变量不得带有 `DD_` 前缀。
如果该文件不存在，请随意创建它。请勿直接编辑 `settings.dist.py`。

您可以在 [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings) 中找到示例。

在 Docker Compose release 模式下，`docker/extra_settings/`（相对于 `docker-compose.yml` 文件的路径）中的文件会在容器启动时被复制到 docker 容器中的 `dojo/settings/`。

`local_settings.py` 同样可以在 Kubernetes 中使用。变量 `localsettingspy` 将作为 ConfigMap 存储，并挂载到容器的相应位置。

## 在 UI 中进行配置

具有超级用户身份的用户可以通过 UI 中的 `Configuration` / `System Settings` 配置更多选项。
