---
title: 在生产环境中运行
description: 在生产环境中使用时，建议进行性能调优并做好备份。
draft: false
weight: 4
audience: opensource
aliases:
- /zh-hans/en/open_source/installation/running-in-production
---

## 生产环境使用（配合 Docker compose）

该代码库中的 docker-compose.yml 文件功能完整，可用于在本地环境中评估 DefectDojo。

尽管 Docker Compose 是在生产环境中部署容器化 DefectDojo 的受支持安装方法之一，但在未先根据您的具体情况进行自定义之前，docker-compose.yml 文件并不适合直接用于生产环境。

有关如何使用 Docker Compose 运行 DefectDojo 的更多信息，请参阅[使用 Docker Compose 运行](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md)。

### 系统要求

建议使用专用数据库服务器，而不是预配置的 PostgreSQL 数据库。这将显著提升 DefectDojo 的性能。

#### 实例规模

在使用独立数据库的情况下，运行 DefectDojo 的最低建议配置为：

-   2 个 vCPU
-   8 GB 内存
-   10 GB 磁盘空间（请记住，数据库并不在这里\-- 因此
     您为操作系统分配的空间应该就足够了）。您可以为
    潜在的性能提升分配一块与操作系统\'s
    不同的磁盘。

### 安全性
请验证 `nginx` 配置以及安全标头等其他运行时方面的设置，以符合您的合规要求。
请将 `docker-compose.yml` 中的 AES256 加密密钥 `&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw` 更改为适用于您实例的唯一密钥。
该加密密钥用于加密存储在 Defect Dojo 中、用以连接 SonarQube 等外部工具的 API 密钥及其他凭据。可以通过多种方式生成密钥，例如使用密码管理器或 `openssl`：

```
     openssl rand -base64 32
```
```
      DD_CREDENTIAL_AES_256_KEY: "${DD_CREDENTIAL_AES_256_KEY:-<PUT THE GENERATED KEY HERE>o}"
```

## 文件备份

无论是哪种情况（专用数据库还是容器化部署），如果您是自行托管，建议您实施并定期创建数据备份。

### 媒体文件

上传文件（包括威胁模型和风险接受）的媒体文件存储在一个 docker 卷中。该卷需要定期备份。

## 性能调优

### uWSGI

默认情况下（调试用途的 `ptvsd` 模式除外），uWSGI 将
处理 16 个并发连接。

根据您的资源设置，您可以调优以下参数：

-   `DD_UWSGI_NUM_OF_PROCESSES`，用于设置生成的进程数量。
    （默认值为 4）
-   `DD_UWSGI_NUM_OF_THREADS`，用于设置这些进程中的
    线程数量。（默认值为 4）

例如，您可以配置 4 个进程，每个进程 6 个线程，从而产生 24 个
并发连接。

### Celery worker

默认情况下，会启动一个单一的单进程 celery worker。在存储大量发现项或执行大型导入时，调整这些参数有助于防止资源枯竭。

以下变量可以在保持单个 celery 容器的同时进行更改，以提升 worker 性能。

-   `DD_CELERY_WORKER_POOL_TYPE` 让您可以切换到 `prefork`。
    （默认值为 `solo`）

启用 `prefork` 后，必须使用以下
变量。请参阅
Dockerfile.django-* 中的文件内引用。

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` 默认值为 2。
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` 默认值为 8。
-   `DD_CELERY_WORKER_CONCURRENCY` 默认值为 8。
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` 默认值为 128。

您可以执行以下命令查看配置：

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
并查看当前生效的配置。

### 异步导入：已弃用
此功能已在 2.47.0 中移除
