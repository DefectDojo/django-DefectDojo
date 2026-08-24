---
title: FIPS 140-3 模式
date: 2026-07-27 00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro 可以部署为使用经 FIPS 140-3 验证的加密技术，适用于受 FedRAMP 控制项 **SC-13** 或类似要求约束的环境。

FIPS 模式以**一套独立的容器镜像**形式发布，通过 `-fips` 标签后缀加以标识。标准镜像保持不变：启用 FIPS 是一项显式选择，绝不会成为静默的默认设置。

如需获取 FIPS 镜像，请通过 [hello@defectdojo.com](mailto:hello@defectdojo.com) 联系我们。

## FIPS 镜像提供的内容

所有加密操作均由 **OpenSSL FIPS Provider 3.1.2** 执行，该组件持有 FIPS 140-3 下的 NIST CMVP 证书 **[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)**。Go 服务使用 **Go Cryptographic Module v1.0.0**，CMVP 证书为 **[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**。

由于强制执行发生在**容器内部**，FIPS 模式并不要求宿主机运行启用 FIPS 的内核。这正是它能够在诸如**采用 Fargate 启动类型的 Amazon ECS** 等托管容器运行时上可用的原因，因为在这些环境中宿主操作系统并不受您控制。

> **是 FIPS 140-3，而非 140-2。** FIPS 140-3 取代了 140-2，并满足针对后者编写的要求。所有 FIPS 140-2 证书将于 **2026 年 9 月 21 日**移入 CMVP 历史列表，此后不再支持新部署，因此新系统应针对 140-3 模块进行验证。

### 覆盖范围

| Component | Covered | Module |
|---|:---:|---|
| Django 应用程序（`dojo`） | yes | OpenSSL FIPS Provider 3.1.2 |
| 异步导入（`dojo-import-scan`） | yes | OpenSSL FIPS Provider 3.1.2 |
| Celery worker 与 beat | yes | OpenSSL FIPS Provider 3.1.2 |
| 初始化程序（`init`） | yes | OpenSSL FIPS Provider 3.1.2 |
| 编排工作节点（`ddorch-workers`） | yes | OpenSSL FIPS Provider 3.1.2 |
| nginx | yes | OpenSSL FIPS Provider 3.1.2 |
| PSIRT 公告引擎 | yes | OpenSSL FIPS Provider 3.1.2 |
| Connectors、Integrators、ddorch、MCP 服务器 | yes | Go Cryptographic Module v1.0.0 |
| **Sensei** | **partial** | 服务二进制文件：Go Cryptographic Module v1.0.0。捆绑的扫描器工具链：**not covered** |
| **PostgreSQL / Redis（内嵌）** | **no** | 请使用符合 FIPS 要求的外部服务 |

**Sensei 是一个值得了解的部分覆盖案例。** 它自身的二进制文件基于经过验证的 Go 模块构建，因此作业 API 的 TLS 和令牌均已被覆盖。该镜像还捆绑了一套多语言的第三方扫描器工具链——Node（自带 OpenSSL）、Rust（rustls）、Python、Ruby，以及我们并未自行编译的第三方 Go 二进制文件——其中有几个组件会使用自己的加密技术通过 TLS 获取公告数据库。该工具链无法纳入单一的经验证模块之下，因此不在覆盖范围内，也不应向评估人员将其呈现为已覆盖。

内嵌的 PostgreSQL/Redis 完全没有 FIPS 版本。在 Kubernetes 中，如果您在启用 FIPS 的同时启用 Sensei 或内嵌数据存储，chart 会拒绝渲染，因此这一权衡是一项明确的决定，而非默认假设（参见[护栏机制](#guard-rails)）。

## 启用 FIPS 模式 — Docker Compose

需要进行两处更改：使用 `-fips` 镜像，并设置 `DD_FIPS_MODE`。

**1. 将镜像标签指向 FIPS 变体。** 在您的 `.env` 或 compose 覆盖文件中：

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. 在共享环境锚点中设置 `DD_FIPS_MODE`。** compose 文件定义了每个相关服务都会合并的共享代码块，因此这是三处编辑，而不是每个服务各改一处：

```yaml
x-dojo-vars: &dojoenv
  DD_FIPS_MODE: "1"        # dojo, dojo-import-scan, celerybeat, celeryworker, init, ddorch-workers
  # ... existing settings

x-nginx-vars: &nginxenv
  DD_FIPS_MODE: "1"        # nginx
  # ... existing settings

x-psirt-vars: &psirtenv
  DD_FIPS_MODE: "1"        # psirt
  # ... existing settings
```

然后重新创建堆栈：

```bash
docker compose up -d --force-recreate
```

## 启用 FIPS 模式 — Kubernetes（Helm）

只需设置一个值。chart 会选择 `-fips` 镜像变体，并为每个 pod 设置 `DD_FIPS_MODE`：

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

由于内嵌数据存储没有 FIPS 变体，且 Sensei 仅部分覆盖，FIPS 安装应使用外部 PostgreSQL 和 Redis，并保持 Sensei 禁用，除非您接受上述附加说明：

```yaml
fips:
  enabled: true
sensei:
  enabled: false          # partial coverage — see the table above
postgresql:
  enabled: false          # use an external FIPS-compliant database
redis:
  enabled: false          # use an external FIPS-compliant cache
```

如果您需要在 FIPS 环境中使用 Sensei，请通过设置
`fips.validate: false` 有意识地启用它，并在您的系统安全计划中将捆绑的扫描器工具链记录为未经验证。

### 护栏机制

如果在启用了没有 FIPS 变体的组件的同时，`fips.enabled` 为 true，**chart 会拒绝渲染**，并指出具体的违规组件：

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

这是刻意设计的。一个大多数服务使用经验证加密技术、但有一两个服务悄悄未使用的部署，比一次明显的失败更糟糕：它看起来是合规的，能经受住随意的检查，却只会在评估期间才暴露出来。如果您已经以书面形式接受了这一风险，可以通过 `fips.validate: false` 覆盖该限制。

## 启用 FIPS 模式 — Amazon ECS / Fargate

Fargate 是 ECS 的一种启动类型，而不是一项独立的服务：您需要注册带有 `requiresCompatibilities: ["FARGATE"]` 和 `networkMode: awsvpc` 的 ECS 任务定义。

如果您已经在 ECS 上运行 DefectDojo Pro，只需更改两项内容：

**1. 镜像标签**增加 `-fips` 后缀：

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2.** 在每个运行应用代码的容器的 `environment` 代码块中设置 **`DD_FIPS_MODE=1`**——包括 uwsgi、celery worker、celery beat、初始化程序、编排工作节点、nginx 和 psirt。

本节的其余部分提供了一份完整的、启用 FIPS 的 ECS 部署说明，供从零开始的读者参考。

### 需要预先准备的资源

| Resource | Notes |
|---|---|
| 带两个子网的 VPC | 私有子网加 NAT 网关，或带有 `assignPublicIp: ENABLED` 的公有子网 |
| 适用于 PostgreSQL 的 RDS | 使用支持 FIPS 的端点，并将其记录为继承组件 |
| 适用于 Redis 的 ElastiCache | 使用两个逻辑数据库：`/0` 用于 Celery 代理，`/1` 用于缓存 |
| EFS 文件系统 | 两个目录：一个用于 `/app/media`，另一个存放 nginx TLS 证书 |
| Secrets Manager 条目 | 数据库 URL、`DD_SECRET_KEY`、`DD_CREDENTIAL_AES_256_KEY`，以及您的 Pro 许可证 |
| Application Load Balancer | HTTPS 监听器，转发到端口 **8443** 上的 **HTTPS** 目标组 |
| ECR 仓库 | 存放两个 `-fips` 镜像 |
| IAM 角色 | 一个可以从 ECR 拉取镜像、写入日志并读取这些密钥的执行角色，外加一个任务角色 |
| CloudWatch 日志组 | 每个容器的 `awslogs` 配置都会引用 |

将 TLS 证书和密钥以 `dojo.crt` / `dojo.key`，以及 `nginx_int.crt` / `nginx_int.key` 的形式放到 EFS 上。这两组文件都必须存在——原因请参见下方的[ECS 需要而 Compose 免费提供的三件事](#three-things-ecs-needs-that-compose-provides-for-free)。

### 1. 初始化程序任务（每次升级运行一次）

应用迁移并填充首次启动数据，然后退出。它是一个任务，而不是一项服务。

```json
{
  "family": "defectdojo-pro-init",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "init",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-initializer.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_INITIALIZE", "value": "true" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" },
        { "name": "DD_ADMIN_USER", "value": "admin" },
        { "name": "DD_ADMIN_MAIL", "value": "admin@example.com" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_ADMIN_PASSWORD", "valueFrom": "<SECRET_ARN_ADMIN_PASSWORD>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "init"
        }
      }
    }
  ]
}
```

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-init.json
aws ecs run-task --cluster <CLUSTER> --launch-type FARGATE \
  --task-definition defectdojo-pro-init \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}"
```

在启动其他服务之前，等待该任务达到 `STOPPED` 状态且退出码为 0。

### 2. Web 服务（nginx + uwsgi）

两个容器位于同一个任务中，因此 nginx 可以通过 `127.0.0.1` 访问 uwsgi。

```json
{
  "family": "defectdojo-pro-web",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "volumes": [
    {
      "name": "media",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/media"
      }
    },
    {
      "name": "certs",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/nginx-certs"
      }
    }
  ],
  "containerDefinitions": [
    {
      "name": "uwsgi",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_UWSGI_ENDPOINT", "value": "0.0.0.0:3031" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "mountPoints": [{ "sourceVolume": "media", "containerPath": "/app/media" }],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "uwsgi"
        }
      }
    },
    {
      "name": "nginx",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips",
      "essential": true,
      "dependsOn": [{ "containerName": "uwsgi", "condition": "START" }],
      "portMappings": [{ "containerPort": 8443, "protocol": "tcp" }],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "USE_TLS", "value": "false" },
        { "name": "GENERATE_TLS_CERTIFICATE", "value": "false" },
        { "name": "DD_UWSGI_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_PORT", "value": "3031" },
        { "name": "DD_UWSGI_IMPORT_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_IMPORT_PORT", "value": "3031" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
        { "name": "DD_MCP_PORT", "value": "9142" },
        { "name": "PSIRT_ENABLED", "value": "false" },
        { "name": "NGINX_METRICS_ENABLED", "value": "false" }
      ],
      "mountPoints": [
        { "sourceVolume": "certs", "containerPath": "/etc/nginx/certs", "readOnly": true }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "nginx"
        }
      }
    }
  ]
}
```

`USE_TLS=false` 会选择本地部署配置，该配置使用挂载的证书在 8443 端口自行终止 TLS。注册该任务定义，并创建一个附加到负载均衡器的服务：

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. Worker 服务（Celery worker 与 beat）

与 uwsgi 使用相同的镜像和相同的密钥；由入口点决定运行哪个进程。请**只**运行一个 beat 副本。

```json
{
  "family": "defectdojo-pro-worker",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "celeryworker",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-worker.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celeryworker"
        }
      }
    },
    {
      "name": "celerybeat",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-beat.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celerybeat"
        }
      }
    }
  ]
}
```

### 4. 确认部署正在使用经验证的加密技术

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

每个容器在提供服务之前都应报告其所使用的模块：

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

如果某个容器没有出现在该输出中，说明它从未启动成功，因为该检查采用失败即拒绝（fail closed）的策略——请查看其日志流以了解原因。

### ECS 需要而 Compose 免费提供的三件事

Docker Compose 为您提供了可用于绑定挂载的宿主机文件系统，以及针对容器名称的 DNS 解析。Fargate 两者都不提供，并且每一处缺口都会导致 nginx 无法启动，而不是悄悄地降级运行。

**1. TLS 证书必须在 nginx 启动之前就已存在。** nginx 会在加载配置时校验每一个 `ssl_certificate`，而本地部署配置没有无证书的路径：8080 端口只会向 HTTPS 发出 `301` 跳转，因此 8443 上的 TLS 监听器才是真正起作用的那个。请将一个 **EFS** 卷挂载到 `/etc/nginx/certs`，其中包含 `dojo.crt` / `dojo.key` 以及 `nginx_int.crt` / `nginx_int.key`。即使您只使用其中一个监听器，这两组文件也都必须存在。

或者也可以设置 `USE_TLS=true`，这会使用上游的 `nginx_TLS.conf`，并让 `GENERATE_TLS_CERTIFICATE=true` 使入口点自行生成证书。该配置会将所有路径代理到 Django，且不会从 `/ui` 提供 Vue UI，因此适合仅使用 API 或严格部署在 ALB 之后的场景。

**2. `DD_MCP_HOST` 必须能够解析。** nginx 会在加载配置时解析 `proxy_pass` 中的主机名。默认值 `mcp-server` 在 Compose（容器名称）和 Helm（Service 名称）下都能解析，但 `awsvpc` 不会为容器分配自己的 DNS 名称，也不接受 `extraHosts` 或 `dnsSearchDomains`：

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

当未部署 MCP 服务器时，将其指向回环地址会使 `/mcp` 返回 `502`，而不会阻止整个 Web 层启动。

**3. nginx 配置文件来自镜像本身。** `-fips` nginx 镜像内置了本地部署配置集，因此不需要额外挂载。Compose 会叠加自己的绑定挂载，因此 Compose 的行为不受影响。

### 其他 Fargate 特有事项

- **持久化存储必须使用 EFS。** Fargate 无法挂载 EBS，因此如果您需要保留上传的扫描文件，媒体目录（`/app/media`）需要使用 EFS 卷。
- **不需要特权容器或主机网络模式。** 镜像以非 root 用户运行，且 `awsvpc` 会为每个任务分配自己的网络接口。
- **nginx → uwsgi。** 同一个任务中的容器共享网络命名空间，因此将 nginx 与 uwsgi 部署在一起可以让 nginx 通过 `127.0.0.1` 访问它——这是最简单也最正确的方案。如果您将它们拆分为独立的 ECS 服务，请将 `DD_UWSGI_HOST` 指向一个 Cloud Map 服务发现名称，并在 uwsgi 端口上开放安全组。
- **不要覆盖 uwsgi 的入口点。** 设置
  `DD_UWSGI_ENDPOINT=0.0.0.0:3031` 并保持镜像的 ENTRYPOINT 不变；
  uwsgi 使用的是 uwsgi 协议，这正是 nginx 所期望的。如果用 `uwsgi --http` 替换入口点，会连同跳过 FIPS 启动检查。
- **初始化程序是一次性任务**，而不是一项服务。请使用
  `aws ecs run-task`（或作为部署前的步骤）运行它，并让它自行退出；不要为它设置期望的任务数量。
- **`healthCheck.retries` 不能超过 10。** 注册任务定义时，更大的数值会被拒绝。
- **将负载均衡器指向 8443**，并使用 HTTPS 目标组。本地部署配置中的 8080 监听器只会重定向到 HTTPS，因此将目标指向 8080 会形成循环。
  目标上使用自签名证书对 ALB 是可以接受的。
- **TLS 终止。** 如果 ALB 为客户端终止 TLS，请在您的 SSP 中单独记录该负载均衡器自身的 FIPS 状态。
- **密钥**应通过 `secrets` 代码块存放在 Secrets Manager 或 SSM Parameter Store 中，绝不能放在 `environment` 中。这也包括 `DD_LICENSE`。

### 在 ECS 上获取证据

启动时的证据代码块会出现在容器 `awslogs` 配置所指定的日志组中：

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

也可以在运行中的任务内按需查看（需要在服务上启用 `enableExecuteCommand`）：

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## 失败即拒绝的启动方式

设置了 `DD_FIPS_MODE` 后，每个容器在启动时都会验证经验证的提供程序已加载，并且未获批准的算法确实被拒绝。**如果该检查失败，容器会直接退出，而不会启动。**

这与 chart 的护栏机制出于同样的考虑：一个悄悄回退到未经验证加密技术的容器仍会继续处理流量，同时破坏您的合规状态，而您要到评估时才会发现这一点。

## 验证 FIPS 模式

每个容器在启动时都会打印一个证据代码块，这通常是对评估人员而言最方便的形式。在托管运行时上，它会出现在您的日志聚合系统中：

```
================================================================
[FIPS] DefectDojo Pro FIPS mode verification
Providers:
  fips
    name: OpenSSL FIPS Provider
    version: 3.1.2
    status: active
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
================================================================
```

可以通过以下方式获取：

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

您还可以在运行中的容器内按需进行验证：

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

对于 Go 服务，FIPS 模式是编译时内置的，并由 Go 运行时报告：

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## FIPS 模式下的行为差异

由于一些未获批准的算法不可用，因此会有若干行为发生变化。以下是值得提前规划的几点。

### 密码哈希

FIPS 构建版本使用 **PBKDF2-SHA256** 作为默认的密码哈希算法。Argon2、bcrypt 和 scrypt 不是 FIPS 批准的密钥派生函数，因此被禁用。

现有用户不会因此被锁定。Django 会在用户下一次成功登录时将其密码重新哈希为 PBKDF2 格式，在过渡期间 PBKDF2-SHA1 哈希值仍可用于验证。如果您希望一次性切换完成，请强制用户重设密码，而不是依赖逐步迁移。

### TLS 密码套件

ChaCha20-Poly1305 未获 FIPS 批准，已从所有终止 TLS 的 nginx 配置中移除，TLS 1.3 被固定为 `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`。TLS 1.2 和 TLS 1.3 仍可通过 AES-GCM 套件使用。仅支持 ChaCha20 的客户端将无法连接。

无论如何，经过验证的模块都会拒绝 ChaCha20；将其从配置中移除意味着服务器永远不会公布一个自己无法完成握手的套件，这也让所部署的配置对评估人员而言具有自解释性。

### 指标基本身份验证

启用 nginx 指标身份验证后，密码哈希使用 SHA-256 crypt 格式，而不是经验证模块所拒绝的 Apache MD5（`apr1`）格式。这一变化对用户是透明的，除非您自行生成 `.htpasswd` 条目，此时请使用 `openssl passwd -5`。

### 扫描解析器

部分解析器使用 MD5 来构建去重键。这属于非安全用途，并已被明确标注为此类用途，因此这些解析器在 FIPS 下仍能正常工作，不会损失任何解析器功能。

## 部署说明

- **TLS 终止。** 如果 TLS 在 DefectDojo 前端的负载均衡器上终止，该设备需自行负责其 FIPS 状态，并应在您的系统安全计划中单独记录。`-fips` nginx 镜像覆盖的是由 DefectDojo 自身终止的 TLS。
- **数据库与缓存。** PostgreSQL 和 Redis 是独立的产品。在 FIPS 环境中，请使用符合 FIPS 要求的实例——例如提供 FIPS 端点的托管数据库——并将它们记录为继承组件。
- **合规范围。** DefectDojo 本身并非加密模块，也不持有自己的证书。这些镜像所提供的，是由具备相应资质的模块以 FIPS 批准模式执行的经验证加密技术。您的评估人员会需要模块名称和证书编号，这些信息都会出现在上文的证据输出中。
