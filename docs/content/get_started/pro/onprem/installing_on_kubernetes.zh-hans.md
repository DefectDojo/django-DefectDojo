---
title: DefectDojo Pro 安装指南
description: 使用 Helm Chart 在 Kubernetes 上安装 DefectDojo Pro，涵盖基础设施、密钥以及安装过程本身
draft: false
weight: 13
audience: pro
---

<!--
  Generated from the DefectDojo Pro Helm chart repository.
  Source: docs/INSTALLATION_GUIDE.md at chart version 3.1.304.
  Edit the source guide, not this file. Local edits are overwritten
  the next time the chart is released.
-->
涵盖在 AWS EKS 和 OpenShift (ROSA) 上的部署。两种平台的工作流程相同：
搭建基础设施、创建密钥、安装 Chart。

---

## 安装前检查清单

请在开始之前收集以下信息。提前准备好这些信息可以避免安装过程中出现延误。

### 基础设施详情

| 项目 | 示例 | 获取方式 |
|------|---------|-------------------|
| **PostgreSQL 主机** | `mydb.abc123.us-east-1.rds.amazonaws.com` | AWS RDS 控制台，或使用 `aws rds describe-db-instances` |
| **PostgreSQL 端口** | `5432` | 通常为 5432，除非另行自定义 |
| **PostgreSQL 数据库名称** | `dojodb` | 您的 DBA 或 Terraform/CloudFormation 输出 — 必须在安装前创建（见下方说明） |
| **编排器数据库** | `dojodb-ddorch` | 为应用角色授予 `CREATEDB` 权限，或预先创建 `<dbname>-ddorch` — 参见[预检：编排器（ddorch）数据库](#pre-flight-orchestrator-ddorch-database) |
| **PostgreSQL 用户名** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **PostgreSQL 密码** | — | AWS Secrets Manager、Terraform 状态或您的 DBA |
| **Redis/ElastiCache 端点** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Redis 密码** | — | 如果已禁用身份验证（仅限 VPC）可省略。检查方式：`aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **EFS 文件系统 ID** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **EFS 访问点 ID**（如适用） | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **EFS 访问点 UID/GID** | UID `1001`，GID `1337` | 必须与容器安全上下文匹配（见下方说明） |
| **域名（FQDN）** | `dojo.example.com` | 您的 DNS 管理员（请参阅下方特定平台说明） |
| **ACM 证书 ARN**（EKS 搭配 HTTPS 时） | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **OpenShift 应用域名**（仅限 ROSA） | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **OpenShift 命名空间 fsGroup**（仅限 ROSA） | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'` — 使用起始值 |
| **许可证文件** | `onprem-dojopro.lic` | 由 DefectDojo 支持团队提供 |

> **请在安装前创建数据库。** Chart 不会在外部 PostgreSQL 服务器上创建数据库。
> 请在运行 `helm install` 之前，在您的数据库服务器上创建以下两个数据库，
> 并将其所有者设置为应用用户：
>
> - `dojodb` — 主 DefectDojo 数据库
> - `dojodb-ddorch` — 编排器（ddorch）数据库，其命名方式始终是在主数据库
>   名称后加上 `-ddorch` 后缀。您也可以改为为应用角色授予
>   `CREATEDB` 权限，让 ddorch 在首次启动时自行创建该数据库。
>
> 有关可直接运行的 `CREATE DATABASE` 命令，请参阅
> [预检：验证数据库连接](#pre-flight-verify-database-connectivity)
> 和[预检：编排器（ddorch）数据库](#pre-flight-orchestrator-ddorch-database)。

> **EFS 访问点 UID/GID：** 如果您的 EFS 文件系统使用了访问点，
> 其 POSIX 用户配置**必须**使用 UID `1001` 和 GID `1337`，以匹配
> DefectDojo 容器的安全上下文。配置不一致会导致容器在初始化期间尝试创建
> media 子目录时出现 `Permission denied` 错误。可通过以下命令验证：
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **OpenShift/ROSA FQDN：** 在 ROSA 上，Route 会使用
> `<release-name>-<namespace>.apps.<cluster-domain>` 模式自动生成主机名。
> 例如，如果您的 release 名为 `dojopro`，命名空间也是 `dojopro`，
> 那么该 Route 的主机名将是 `dojopro-dojopro.apps.abc123.p1.openshiftapps.com`。
> 可通过以下命令确定您集群的 apps 域名：
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```
>
> 请将得到的 FQDN 用于 `dojo.fqdn`、`dojo.url` 和 `dojo.hosts.main`。

> **OpenShift/ROSA fsGroup：** 您需要获取命名空间的 supplemental-groups
> 起始值，用于设置 `securityContext.openshift.fsGroup`。请提前查出该值，
> 以避免日后还需要编辑 values 文件：
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### 待生成的密钥

以下密钥必须为您的部署重新生成。请使用下方给出的命令来创建具有
密码学随机性的值：

| 密钥 | K8s Secret 中的键 | 生成方式 |
|--------|-------------------|---------------|
| Django 密钥 | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| AES-256 加密密钥 | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| 云门户密钥 | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| 连接器共享密钥 | `DD_CONNECTORS_SHARED_SECRET` | 与 `CLOUD_PORTAL_SECRET_KEY` 使用相同的值 |
| 管理员密码 | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| 指标密码 | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### 来自您基础设施的密钥

这些密钥来自您现有的基础设施 — 请勿自行生成：

| 密钥 | K8s Secret 中的键 | 来源 |
|--------|-------------------|--------|
| 数据库密码 | `DD_DATABASE_PASSWORD` | 您的 PostgreSQL 密码 |
| 数据库连接 URL | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Redis 密码 | `redis-password`（位于单独的 `dojopro-redis` secret 中） | 您的 Redis 密码；如无身份验证可跳过 |
| 邮件服务 URL | `DD_EMAIL_URL` | 测试时使用 `consolemail://`，或使用您的 SMTP URL |

### 可选项（留空即可禁用）

| 密钥 | K8s Secret 中的键 | 用途 |
|--------|-------------------|---------|
| EPSS 存储桶密钥 | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | EPSS 评分富化 |

> **提示：** 复制 `secrets-template.yaml` 并填入上述各项值。有关创建
> Kubernetes Secret 的详细说明，请参阅[生成密钥](#generate-secrets)。

---

## 前提条件

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

对于 OpenShift/ROSA，还需安装：
```bash
brew install rosa openshift-cli
```

### 出站连接要求

在受限网络环境中，安装前必须允许以下出站连接。防火墙规则可能需要提前提交
变更请求 — 请在继续之前确认这些规则已经就绪。

**容器镜像仓库（必需）**

所有集群节点都必须能够通过 443 端口访问 DefectDojo 容器镜像仓库：

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> 对于隔离网络环境，请参阅
> [私有镜像仓库 / 隔离网络环境](#private-registry-air-gapped-environments)。

**数据库（必需）**

集群节点至 PostgreSQL 实例，通常使用 5432 端口。

- 同一 VPC 内的 RDS：请确保 EKS 节点安全组允许 5432 端口的入站流量
- 不同 VPC 或账户中的 RDS：需要 VPC Peering 或 Transit Gateway
- 外部／本地环境：VPN 或 Direct Connect 链路必须放行 5432 端口

**EPSS 更新（建议）**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**KEV 数据源（建议）**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**AWS 服务（仅限 EKS，必需）**

EBS CSI Driver 和 ALB Controller 需要通过 443 端口访问 AWS API 端点：

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com`（如果使用 EFS）

### AWS EKS 前提条件

在部署 DefectDojo Pro 之前，必须在您的 EKS 集群中安装以下组件。
缺少这些组件将导致部署失败。

**EBS CSI Driver**（仅当使用带有内嵌 PostgreSQL 和 Redis 的 minimal profile
时才需要 — 如果您使用外部 RDS 和 ElastiCache，则不需要）：

```bash
# Associate IAM OIDC provider
eksctl utils associate-iam-oidc-provider \
  --cluster <your-cluster> --region <region> --approve

# Create IAM role for EBS CSI
eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EBS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-ebs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EBS_CSI_DriverRole \
  --force
```

**EFS CSI Driver**（使用 EFS 存储时必需 — 这是多副本 EKS 部署所推荐的
存储后端）：

```bash
# Create IAM role for EFS CSI
eksctl create iamserviceaccount \
  --name efs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EFS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-efs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EFS_CSI_DriverRole \
  --force
```

**AWS Load Balancer Controller**（ALB Ingress 所需）：

安装说明因 EKS 版本而异，请参阅
[AWS Load Balancer Controller 官方安装指南](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/)。

---

## 解压 Chart 包

该 Chart 以包含 `.tgz` Helm 包的 zip 文件形式发布。请在继续之前将两者都解压。
建议使用带版本号的解压路径，以避免日后解压更新版本的 Chart 时静默覆盖
预设文件：

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

请设置一个 `CHART` 变量，指向解压后的 Chart 目录。本指南中后续所有
`helm` 命令都会使用 `$CHART`：

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **为什么 CLI 用户需要解压：** 预设文件
> （`presets/platforms/*.yaml`、`presets/profiles/*.yaml`）被打包在
> `.tgz` 包内部。`helm install -f` 要求文件位于本地文件系统上 — 它
> 无法读取打包后的 `.tgz` 内部的文件。您必须解压 Chart 才能访问这些预设文件。
>
> **ArgoCD 用户无需解压。** ArgoCD 会直接从 Chart 包内部读取
> `valueFiles`。参见[使用 ArgoCD 部署](#deploy-with-argocd)。

---

## 准备您的 Values 文件

客户配置模板（`template.yaml`）和密钥模板（`secrets-template.yaml`）
可单独从 DefectDojo 支持门户获取，或联系 support@defectdojo.com 获取。
它们不包含在 Chart 的 `.tgz` 包中。获取模板后，请复制该文件并填入
您的详细信息：

```bash
cp template.yaml my-company.yaml
```

至少需要设置：

| 设置项 | 说明 |
|---------|-------------|
| `dojo.fqdn` | 您的域名（ROSA：参见上方的 [FQDN 说明](#infrastructure-details)） |
| `dojo.url` | 包含协议的完整 URL（例如 `https://dojo.example.com`） |
| `dojo.hosts.main` | 必须与您的 FQDN 一致 |
| `dojo.secureCookies` | 在 **OpenShift/ROSA** 上设置为 `false`（见下方警告） |
| `dojo.admin.*` | `user`、`email`、`firstName`、`lastName` — 管理员账户 |
| `database.host`、`.port`、`.name`、`.user` | PostgreSQL 连接详情（密码需放在密钥中设置） |
| `celery.broker.host` | 您的 Redis/ElastiCache 端点 |
| `redis.enabled` | 使用外部 Redis 时**必须设为 `false`**（见下方警告） |
| `storage.type` | 存储后端 — 参见特定平台说明 |
| `certificates.*` | TLS 证书配置 |
| `django.ingress.*` 或 `django.route.*` | Ingress（EKS）或 Route（OpenShift）— 预设会设置默认值 |
| `securityContext.openshift.fsGroup` | **仅限 ROSA** — 命名空间 supplemental-groups 起始值 |

> **警告 — 使用外部 Redis/ElastiCache 时，必须显式将 `redis.enabled`
> 设置为 `false`。** `standard` 和 `performance` 这两个 profile 预设默认会
> 设置 `redis.enabled: true`。如果您的 values 文件没有覆盖这一设置，
> Chart 将会在集群内部署一个 Redis，**与**您的外部 broker 同时存在，
> 从而导致配置出错。请将以下内容添加到您的 values 文件中：
>
> ```yaml
> redis:
>   enabled: false
> ```

> **警告 — 在 OpenShift/ROSA 上，`dojo.secureCookies` 必须为 `false`。**
> 当使用采用边缘 TLS 终止的 OpenShift Route 时，`secureCookies: true`
> （`template.yaml` 中的默认值）会导致重定向循环，并使登录失效。
> 这一点没有商量余地 — 采用边缘 TLS 终止的 Route 要求：
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**存储说明：**
- **EKS：** 请使用 EFS，而不是 EBS。EBS 卷无法在多个节点间共享，会导致
  `Multi-Attach` 错误。参见[已知问题](#known-issues-chart-version-2.57.1)。
  如果您的 EFS 使用了访问点，还需设置 `storage.efs.accessPointId` —
  参见 [EFS 访问点](#efs-access-points)。
- **OpenShift/ROSA：** 平台预设默认使用 `storage.type: "pvc"`，并设置
  `createNew: true`，即使用集群的默认 StorageClass。对于多节点部署，
  请通过 EFS 使用 NFS（即设置 `storage.type: "nfs"`）。

您也可以选择设置日志详细程度：
- `config.logLevel` — Django 应用日志级别（默认值：`"INFO"`）
- `celery.logLevel` — Celery worker/beat 日志级别（默认值：`"INFO"`）

排查问题时，可将其中任意一项设置为 `"DEBUG"`。有关如何在运行时切换该设置
而无需编辑 values 文件的方法，请参阅[日志详细程度](#log-verbosity)。

请勿在此文件中放置密钥或许可证内容，这些内容将在接下来的两个小节中处理。

完整的选项列表请参阅 `template.yaml`。

### 预检：验证数据库连接

请在继续之前确认数据库可以正常访问 — 这能在后续排查问题时节省大量时间。
使用 `psql` 启动一个临时 Pod：

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

成功连接后的输出类似如下：

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

如果失败并提示 `database "dojodb" does not exist`，说明您的 RDS 实例
可以访问，但数据库尚未创建。请创建该数据库：

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

然后重新运行上面的连接检查以确认。

如果因其他原因失败，请检查：
- **安全组／防火墙规则** — 必须放行从集群到数据库主机的 5432 端口
- **数据库用户权限** — 该用户必须对目标数据库拥有 CREATE、ALTER 和 SELECT
  权限，并且拥有 `CREATEDB` 权限或已预先创建编排器数据库（见下一小节）

> Chart 还内置了检查机制：一个等待数据库 TCP 连接就绪的 init container，
> 以及部署完成后通过 `helm test` 验证完整的 PostgreSQL 连接。这一预检步骤
> 可以在您投入时间创建密钥并运行 `helm install` 之前，提前发现问题。

### 预检：编排器（ddorch）数据库

编排器（`ddorch`，默认启用）会将其工作流状态存储在与主 DefectDojo 数据库
并存的**第二个数据库**中。启动时，它会从 `DD_DATABASE_URL` 中获取数据库
名称，附加上 `-ddorch` 后缀，并在该数据库不存在时创建它 — 如果主数据库为
`dojodb`，编排器就会使用 `dojodb-ddorch`。

如果应用角色没有创建数据库的权限，ddorch 的 Pod 会在启动时失败，并报错：

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

安装前请满足以下**其中一项**条件：

**选项 A — 为应用角色授予 `CREATEDB` 权限**，让 ddorch 在首次启动时
自行创建其数据库：

```sql
ALTER ROLE defectdojo CREATEDB;
```

**选项 B — 预先创建编排器数据库**，命名方式为在主数据库名称后加上
`-ddorch` 后缀，所有者为同一应用用户。由于名称中包含连字符，
在 SQL 中需要使用双引号：

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

使用与上面连接检查相同的临时 Pod 方式：

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## 生成密钥

这里有两种方式可选。

### 选项 A：外部 Secret（推荐用于 GitOps）

在安装 Chart 之前，创建一个包含所需 12 个键的 Kubernetes Secret。
可以使用 DefectDojo 支持团队提供的 `secrets-template.yaml` 作为起点
（获取方式请参阅[准备您的 Values 文件](#prepare-your-values-file)）：

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

编辑该文件，替换所有占位值，然后应用：
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

该 Secret 也可以由 External Secrets Operator、Sealed Secrets 或任何其他
能够创建 Kubernetes Secret 的工具来管理。Chart 并不关心 Secret 是如何
创建的 — 只需将 `dojo.existingSecret` 设置为其名称即可。

在安装时：
```bash
--set dojo.existingSecret=dojopro-secrets
```

当设置了 `dojo.existingSecret` 时，Chart 会自动跳过渲染其内置的
Secret — 无需额外的标志。

如果您的外部 Redis 需要身份验证，`secrets-template.yaml` 中还包含一个
单独的 `dojopro-redis` Secret。Chart 会从 `redis.auth.existingSecret`
（默认值：`dojopro-redis`）中读取 Redis 凭据。如果您的 Redis 没有设置密码
（例如仅限 VPC 访问的 ElastiCache），则可以跳过此项。

### 选项 B：内联密钥（更简单，但不利于 GitOps）

直接在 values 文件中传入密钥值：

```yaml
dojo:
  secretKey: ""                    # openssl rand -hex 25
  credentialAES256Key: ""          # openssl rand -hex 16
  cloudPortalSecretKey: ""         # openssl rand -hex 25
  connectorsSharedSecret: ""       # openssl rand -hex 25 (or reuse cloudPortalSecretKey)
  admin:
    password: ""                   # openssl rand -base64 16
  emailUrl: "consolemail://"
  proEnhancementsEpssBucketKey: "" # leave empty if not using EPSS

database:
  password: ""                     # your PostgreSQL password

redis:
  auth:
    password: ""                   # your Redis password (omit if Redis has no auth)

monitoring:
  password: ""                     # openssl rand -hex 16
```

将其保存为 `my-secrets.yaml`，并在安装时通过 `-f` 传入。

> 请勿将密钥文件提交到版本控制系统中。

---

## 创建内部 TLS 证书

Chart 需要内部 TLS 证书以实现服务间通信。

安装前，请在您的命名空间中创建两个 Kubernetes TLS Secret：

1. `dojopro-internal-tls` — 一个包含 `tls.crt` 和 `tls.key` 的 TLS Secret，
   用于服务间加密（nginx ↔ connectors 等）
2. `dojopro-internal-ca` — 一个在 `ca.crt` 键下存放 CA 证书的 Secret，
   供 connectors 用来验证内部 TLS 证书

您可以使用 `openssl` 生成自签名 CA 和服务器证书，也可以使用贵组织的
内部 CA。服务器证书的 CN/SAN **必须**覆盖 Helm release 所使用的内部
nginx 服务名称。默认情况下，该名称为 `<release-name>-nginx`（例如，
如果您的 release 名为 `dojopro`，则为 `dojopro-nginx`）。

生成自签名 CA 和服务器证书的示例：
```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# Generate CA
# basicConstraints + keyUsage MUST be set explicitly. Without them the CA may
# be rejected as not a valid CA (e.g. "x509: certificate signed by unknown
# authority" / missing keyUsage) depending on your local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-internal-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# Generate server cert with correct SANs and usage extensions
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes \
  -subj "/CN=${RELEASE_NAME}-nginx" \
  -addext "subjectAltName=DNS:${RELEASE_NAME}-nginx,DNS:${RELEASE_NAME}-nginx.${NAMESPACE}.svc.cluster.local" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -copy_extensions copyall

# Create the Kubernetes secrets
kubectl create secret tls dojopro-internal-tls \
  --cert=server.crt --key=server.key \
  -n $NAMESPACE

kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=ca.crt \
  -n $NAMESPACE
```

> **常见错误：** 将 `nginx-internal` 用作 CN/SAN，而不是
> `<release-name>-nginx`。connectors 这个 Pod 会将 TLS 证书与实际的服务
> 名称（`<release-name>-nginx.<namespace>.svc.cluster.local`）进行比对，
> 如果 SAN 不匹配，就会出现 `x509: certificate is valid for ... not ...` 错误。

然后在您的 values 文件中设置：
```yaml
certificates:
  generation:
    enabled: false
  internal:
    source: "secret"
    secretName: "dojopro-internal-tls"
    caBundle:
      secretName: "dojopro-internal-ca"
      key: "ca.crt"
```

### ddorch mTLS 证书

除了上述内部 TLS Secret 之外，`ddorch` 编排器还需要一套单独的、由三份
文件组成的 mTLS 证书，供 ddorch 服务器以及每一个与其通信的 worker
（`ddorch-workers`、`integrators`）使用。这些文件是在安装时通过
`--set-file` 传递给 Chart 的（**不是**从已存在的 Kubernetes secret 中
读取的）：

- `orch_tls_root.ca` — CA 证书
- `orch_tls.crt` — 服务器证书
- `orch_tls.key` — 服务器私钥

如果缺少这三个文件，`helm install` 会失败，并提示
`ddorch.tls.rootCa is required`。

服务器证书的 SAN **必须**包含 worker 用来访问 ddorch 的所有主机名：

- `ddorch` — 集群内服务的短名称
- `<release-name>-ddorch` — 完全限定服务名称（例如 `dojopro-ddorch`）
- `<release-name>-ddorch.<namespace>.svc.cluster.local` — 集群 FQDN
- `nginx` — hatchet 风格 worker 所使用的默认 `SERVER_TLS_SERVER_NAME`
- `localhost`、`127.0.0.1` — 同一 Pod 内的 worker 通过 hostAlias 环回地址
  访问 ddorch 时使用

生成这一组证书的示例：

```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# ddorch CA
# As with the internal CA, set basicConstraints + keyUsage explicitly so the
# generated cert is a valid signing CA regardless of local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout orch_ca.key -out orch_ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-ddorch-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# ddorch server cert
openssl req -newkey rsa:2048 -keyout orch_server.key -out orch_server.csr -nodes \
  -subj "/CN=ddorch" \
  -addext "subjectAltName=DNS:ddorch,DNS:${RELEASE_NAME}-ddorch,DNS:${RELEASE_NAME}-ddorch.${NAMESPACE}.svc.cluster.local,DNS:nginx,DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in orch_server.csr -CA orch_ca.crt -CAkey orch_ca.key \
  -CAcreateserial -out orch_server.crt -days 365 -copy_extensions copyall
```

将它们传递给 `helm install` / `helm template`：

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> `scripts/bootstrap-aws-eks.sh` 这个辅助脚本会通过
> `dojopro-orch-certs-configmap` 自动生成并复用这些证书 — 如果您使用
> 该脚本，就无需手动创建它们。

---

## 许可证

Chart 需要一个 DefectDojo Pro 许可证。

### 检查您的许可证

在部署之前，请确认您的许可证有效且尚未过期：

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

这会显示许可证的元数据，包括：
- `not_after` — 许可证到期日期
- `license_package` — 确认您的套餐级别

> **镜像拉取密钥：** 当设置了 `images.pullSecrets.extractFromLicense: true`
> （平台预设中的默认值）时，Chart 会自动从您的许可证文件中提取内嵌的
> GCP 服务账号，并创建从容器镜像仓库拉取 DefectDojo 镜像所需的镜像拉取
> 密钥，无需手动提取或解码。如果您改用私有镜像仓库，请设置
> `extractFromLicense: false`，并提供您自己的拉取密钥 — 参见
> [私有镜像仓库 / 隔离网络环境](#private-registry-air-gapped-environments)。

### 选项 1：--set-file（标准 Helm 安装）

在安装时传入许可证文件：
```bash
--set-file license.contents=/path/to/license.lic
```

### 选项 2：现有 Secret（GitOps / ArgoCD）

创建一个包含许可证的 Kubernetes Secret，然后告诉 Chart 使用它。
这样就无需使用 `--set-file`，也无需将许可证存储在 git 中。

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

然后在您的 values 文件或 helm 参数中：
```yaml
license:
  existingSecret: "dojopro-license"
```

该 Secret 可以由 External Secrets Operator、Sealed Secrets 或普通的
kubectl 命令来管理。

> **重要提示：** `license.existingSecret` 与默认设置
> `images.pullSecrets.extractFromLicense: true` **不兼容**。Chart 需要在
> 渲染时获取许可证内容，才能提取其中内嵌的容器镜像仓库凭据。如果您使用
> `license.existingSecret`，则必须同时禁用自动拉取密钥提取功能，
> 并提供您自己的拉取密钥：
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```
>
> 如果您希望 Chart 自动从许可证中提取拉取密钥（默认行为），请改用
> **选项 1**（`--set-file license.contents=`）。


---

## FIPS 140-3 模式（可选）

对于需要满足 FedRAMP **SC-13** 或类似要求的环境，Chart 可以部署
`-fips` 镜像变体，其加密操作由 **OpenSSL FIPS Provider 3.1.2**
（NIST CMVP 认证编号 **#4985**）执行；对于 Go 编写的服务，
则由 **Go Cryptographic Module v1.0.0**（CMVP **#5247**）执行。

这一强制机制在容器内部完成，因此不需要支持 FIPS 的主机内核 — 这也正是
该方案能够在您无法控制主机操作系统的托管运行时环境中可行的原因。

默认处于禁用状态；关闭时，渲染输出不受影响。

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

带有 `-fips` 标签的镜像必须存在于您的镜像仓库中。如需获取，请联系
hello@defectdojo.com。

### 没有 FIPS 变体的组件

Sensei 以及**内嵌**的 PostgreSQL/Redis 都没有 FIPS 构建版本 — 内置的
valkey 镜像基于 Alpine，其中没有经过 FIPS 验证的 OpenSSL。因此，
启用 FIPS 的安装必须使用外部数据存储，并禁用 Sensei：

```yaml
fips:
  enabled: true
sensei:
  enabled: false
postgresql:
  enabled: false    # point at an external FIPS-compliant database
redis:
  enabled: false    # point at an external FIPS-compliant cache
```

当 `fips.validate: true`（默认值）时，如果您在启用 FIPS 的同时启用了
其中任何一项，Chart 将会**渲染失败**，并指出具体是哪些组件引发了问题：

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

这是有意为之的设计。如果一次部署中大多数服务都使用了经过验证的加密方式，
只有一两个服务悄悄没有做到，这种情况比明显的失败更糟糕：它表面上看起来
合规，却只会在评估时才暴露出问题。只有在您已经明确接受这一风险的情况下，
才应设置 `fips.validate: false`。

### 部署后验证

每个 Pod 都会运行一次失败即拒绝（fail-closed）的启动检查 — 如果经过验证的
加密提供程序未处于激活状态，容器会直接退出，而不会继续对外提供服务。
它打印出的证据通常正是评估人员所需要的：

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

需要提前规划的行为变化（密码哈希算法改为 PBKDF2，ChaCha20 从 TLS 密码
套件列表中移除）已在产品文档的 FIPS 140-3 模式页面中说明。

---

## 预检：验证模板

在安装之前，运行 `helm template` 以渲染并验证所有清单，而不实际接触
集群。这样可以在您提交 `helm install` 之前，发现 values 错误、缺失的
必填字段以及 YAML 问题：

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  > /dev/null
```

使用您计划传递给 `helm install` 的相同参数。如果此命令顺利退出，说明
您的 values 是有效的。如果失败，错误消息将指出缺失或无效的字段——
请修复您的 values 文件，然后重新运行直到通过为止。

---

## 部署

将您的平台 overlay、资源 profile、客户 values，以及您在上文中选择的
密钥和许可证组合在一起。

### AWS EKS

> **强烈建议在 EKS 上为浏览器访问启用 HTTPS。**
> 当 ingress TLS 处于启用状态时，Chart 会自动启用
> `SECURE_SSL_REDIRECT`，并将 CSRF/会话 cookie 设置为 `Secure`，这
> 意味着如果 ALB 上没有 HTTPS 监听器，浏览器登录将会失败。为获得
> 最佳体验，请在部署前配置 ACM 证书。
>
> 如果您需要在不使用 HTTPS 的情况下运行，请参阅下文的
> [不使用 HTTPS 部署（不推荐）](#deploying-without-https-not-recommended)。

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **命名空间一致性：** 命名空间的值必须在所有资源中保持一致：您的
> 密钥 YAML（`metadata.namespace`）、`kubectl create namespace`，
> 以及 `helm install -n`。如果您使用自定义命名空间而非 `dojopro`，
> 请在所有命令和密钥清单中一致地替换它。

**外部密钥 + 许可证密钥（GitOps）：**

如果尚未应用密钥，请先应用（参阅[生成密钥](#generate-secrets)），
然后再安装：

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**内联密钥 + 许可证文件（更简单）：**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

#### 不使用 HTTPS 部署（不推荐）

> **警告：** 在不使用 HTTPS 的情况下运行，意味着会话 cookie 将以明文
> 发送，并且通过安全 cookie 实现的 CSRF 保护将被禁用。请勿在生产
> 环境中使用此配置。

如果您需要暂时在不使用 HTTPS 的情况下部署（例如，在没有 ACM 证书的
情况下进行初始测试），请在您的 values 文件中应用**以下所有**更改：

```yaml
dojo:
  url: "http://dojo.example.com"       # must be http://, not https://
  secureCookies: false                  # disable Secure flag on session/CSRF cookies

django:
  ingress:
    tls:
      enabled: false
    annotations:
      # HTTP-only listener — remove the HTTPS listener entirely
      alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}]'
      # Do NOT include the ssl-redirect annotation — it causes a redirect
      # loop when no HTTPS listener exists (see BUG-17 in Known Issues)
      # alb.ingress.kubernetes.io/ssl-redirect: "443"   # REMOVE this line
```

所有四项更改都是必需的。遗漏任何一项都将导致重定向循环或登录失败。
当您准备好启用 HTTPS 时，请恢复这些更改并配置 ACM 证书。

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **提醒：** 您应该已经从[安装前检查清单](#infrastructure-details)中
> 获得了命名空间的 `fsGroup` 值。如果没有，请立即查询：
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**外部密钥 + 许可证密钥（GitOps）：**

如果尚未应用密钥，请先应用（参阅[生成密钥](#generate-secrets)），
然后再安装：

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**内联密钥 + 许可证文件（更简单）：**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

---

## 使用 ArgoCD 部署

DefectDojo Pro 与 ArgoCD 完全兼容。该 Chart 包含平台和 profile 预设，
ArgoCD 可以直接将其作为 `valueFiles` 引用。

### 前提条件

在创建 ArgoCD Application 之前，以下 Kubernetes 资源必须已存在于
目标命名空间中：

- 应用程序密钥（参阅[生成密钥](#generate-secrets)）
- 许可证密钥（参阅[许可证](#license)）
- 内部 TLS 密钥，如果未使用自动生成（参阅[创建内部 TLS 证书](#create-internal-tls-certificates)）
- ddorch mTLS 材料（参阅 [ddorch mTLS 证书](#ddorch-mtls-certificates)）。ArgoCD 没有与 `--set-file` 等效的功能，因此需要通过 Application 参数（`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`）传递这三份 PEM 内容。请使用 ArgoCD 的密钥管理插件（Sealed Secrets、External Secrets 或 ConfigMap 插件），而不要以明文提交密钥。

### 工作原理

ArgoCD 相对于 Chart 根目录引用预设文件。您的 Application 规范需要
三样东西：

1. 作为 `valueFiles` 的平台和 profile 预设
2. 您特定于环境的配置（通过 `valueFiles`、内联 `values`，或两者兼用）
3. 作为 `parameters` 的密钥和许可证引用

```yaml
helm:
  valueFiles:
    - presets/platforms/aws-eks.yaml       # or openshift
    - presets/profiles/standard.yaml       # or minimal, performance
  values: |
    # Your environment-specific configuration goes here.
    # This is applied last and overrides the presets above.
    dojo:
      fqdn: dojo.example.com
      admin:
        user: admin
        email: admin@example.com
    database:
      host: your-db-host.example.com
    # ... see template.yaml for all options
  parameters:
    - name: dojo.existingSecret
      value: dojopro-secrets
    - name: license.existingSecret
      value: dojopro-license
```

### 提供您的配置

有几种方式可以向 ArgoCD 提供特定于环境的 values：

- 在 Application 规范中使用内联 `values`——最简单的方法，不需要额外
  的文件或代码库。当您的配置比较简单时，这种方式效果很好。
- 在单独的 git 代码库中使用 values 文件——使用 ArgoCD 的多源功能
  （v2.6 及以上版本），通过 `$ref` 变量将您的 values 文件与 Chart
  一同拉取。在使用 OCI 发布的 Chart 时推荐此方式。
- 在与 Chart 相同的 git 代码库中使用 values 文件——在 `valueFiles`
  中通过相对于 Chart 目录的路径引用它
  （例如 `../../overrides/customers/my-company.yaml`）。

这三种方法都遵循相同的分层方式：平台预设 → profile 预设 → 您的
配置。后面的 values 会覆盖前面的。

### 升级

当 Chart 发布到 OCI 注册表后，升级只需在您的 Application 规范中
更改 `targetRevision` 这一处。平台和 profile 预设与 Chart 一起
进行版本管理，因此会自动更新。

有关 ArgoCD 的 Helm 支持的完整详情，请参阅
[ArgoCD Helm 文档](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/)。

---

## 验证

```bash
# Check the initializer job completed successfully (required for first install)
kubectl get jobs -n $NAMESPACE
# The initializer job must show 1/1 COMPLETIONS. If it shows 0/1, the
# database migrations did not run and the application will not work.
# Check its logs:
#   kubectl logs -n $NAMESPACE -l app.kubernetes.io/component=initializer
# To retry: delete the failed job and run helm upgrade with the same flags:
#   kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
#   helm upgrade dojopro <chart> ... (same flags as install)

# Check all pods are running
kubectl get pods -n $NAMESPACE
# Expected components (chart 2.57+): django, celery-worker, celery-beat,
# connectors, nginx, ddorch, ddorch-workers, integrators, mcp-server, plus
# redis and postgresql if you are using the bundled copies, plus psirt and
# sensei if you enabled them (psirt.enabled, sensei.enabled).
# Note: ddorch-workers replaces the legacy kairos, rulesengine, and
# hatchet-integrators workers.

# Check ingress (EKS) or route (OpenShift)
kubectl get ingress -n $NAMESPACE    # EKS
oc get route -n $NAMESPACE           # OpenShift

# Run built-in helm tests
helm test dojopro -n $NAMESPACE --logs --timeout 5m

# Health check
# EKS (use https:// if TLS is configured, http:// otherwise):
ALB=$(kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}')
curl -sk "https://${ALB}/api/v2/health_check/light/"
# or for HTTP-only deployments:
# curl -s "http://${ALB}/api/v2/health_check/light/"

# OpenShift:
ROUTE=$(oc get route -n $NAMESPACE -o jsonpath='{.items[0].spec.host}')
curl -sk "https://${ROUTE}/api/v2/health_check/light/"
```

### 内置 Helm 测试

该 Chart 附带四个测试，会在您执行 `helm test` 时以 Kubernetes Pod 的
形式运行。它们验证 DefectDojo 与其后端服务之间的关键集成点：

| 测试 | 检查内容 |
|------|----------------|
| `test-database` | 使用配置的凭据连接到 PostgreSQL，运行 `SELECT version()`，并确认数据库正在接受查询。最多重试 60 秒。 |
| `test-redis-broker` | 连接到 Redis/Valkey 代理，发送 `PING`，然后执行一次 set/get/delete 循环以验证读写访问权限。 |
| `test-django-health` | 访问内部 nginx 服务上的 `/api/v2/health_check/light/` 端点，并确认返回 HTTP 2xx/3xx 响应。在数据库和代理测试之后运行（hook-weight 为 10）。 |
| `test-storage` | 挂载媒体卷并执行一次写/读/删除循环，以确认存储后端可被应用程序访问并写入。最后运行（hook-weight 为 15）。 |

测试按 hook-weight 顺序运行——基础设施测试（数据库、代理）在前，
应用层测试（健康检查、存储）在后。如果较早的测试失败，后续测试
可能仍会运行，但也很可能会失败。

要在部署失败或配置更改后重新运行测试：
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

测试 Pod 会在每次运行前自动清理（`before-hook-creation` 删除策略）。
要手动检查失败的测试 Pod 的日志：
```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### 获取管理员密码

初始管理员密码存储在应用程序密钥中。使用以下命令获取：

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

如果您使用的是内联密钥而非外部密钥，则密码位于 Chart 管理的密钥中：

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

使用管理员用户名（默认：`admin`）和此密码，在您配置的 URL 处登录。
首次登录后请更改密码。

---

## 运维

### 日志详细程度

该 Chart 提供两个日志级别设置，两者默认均为 `INFO`：

| 设置 | 控制内容 | 环境变量 |
|---------|----------|---------|
| `config.logLevel` | Django 应用程序日志记录 | `DD_LOG_LEVEL` |
| `celery.logLevel` | Celery worker 和 beat 日志记录 | `DD_CELERY_LOG_LEVEL` |

要提高详细程度以进行故障排查，请在您的 values 文件中将其中一个或
两个都设置为 `DEBUG`，然后运行 `helm upgrade`：

```yaml
config:
  logLevel: "DEBUG"
celery:
  logLevel: "DEBUG"
```

```bash
helm upgrade dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set config.logLevel=DEBUG \
  --set celery.logLevel=DEBUG \
  --wait --timeout 15m
```

`--set` 参数会覆盖 values 文件中的设置，因此您可以在不编辑文件的
情况下切换调试日志。问题解决后，再次运行 `helm upgrade`（不带
`--set` 参数）即可恢复到您配置的默认值。

Django 部署还支持 `django.uwsgi.enableDebug: true`，此设置会将
`DD_DEBUG=True` 用于更底层的框架调试。这会产生明显更多的输出，
应仅用于短时间的排查。

### 扫描导入隔离

扫描导入（`/api/v2/import-scan/` 和 `/api/v2/reimport-scan/`）是
同步解析的，可能会消耗大量 worker 内存。默认情况下，该 Chart 运行
一个专用的 `django-import` 部署（uwsgi 运行在端口 3032，位于其自己
的 Service 之后），Django Pod 的 nginx 会将导入端点路由到该部署。
大型导入不会耗尽（或 OOM）交互式 Web worker，并且导入器池（写入方）
可以独立于 Web Pod（读取方）进行扩缩。

`django.uwsgiImport` 下的可调参数：

```yaml
django:
  uwsgiImport:
    enabled: true          # false routes imports back to the main uwsgi pool
    replicas: 2            # importer pods (ignored when autoscaling is on)
    maxBodySizeMb: null    # client_max_body_size on the import routes; null
                           # derives dojo.scanMaxFileSize + 5 (multipart
                           # overhead), so raising scanMaxFileSize just works.
                           # Set an integer to override.
    performance:
      processes: 2         # concurrent imports per pod = processes x threads
      threads: 4
    resources:
      requests:
        cpu: "100m"
        memory: "512Mi"
      limits:
        memory: "4Gi"
    terminationGracePeriodSeconds: 60   # raise toward 1800 to let in-flight
                                        # imports finish on rollouts/drains
    autoscaling:
      enabled: false       # scale importers on their own CPU signal
    horizontalpodautoscaler:
      minReplicas: 2
      maxReplicas: 5
      averageUtilization: 60
```

运维说明：

- 导入器 Pod 挂载共享媒体卷，因此需要具备 ReadWriteMany 能力的存储，
  才能在各节点间自由调度。该 Chart 的存储后端（`efs`、`filestore`、
  `gcsfuse`、`nfs`，以及默认的 RWX 媒体 PVC）均符合条件；
  ReadWriteOnce PVC 则不符合。
- 导入器自动扩缩默认处于关闭状态，因为一旦
  `terminationGracePeriodSeconds` 到期，缩容操作会驱逐该 Pod 当时
  正在运行的任何导入任务。如果您启用它，请延长宽限期，以便正在
  进行中的导入任务能够完成。
- 只要运行的导入器数量超过一个，PodDisruptionBudget
  （`podDisruptionBudget.djangoImport`）就会在自愿性中断期间保护
  导入器池。

`minimal` profile 会禁用导入器部署以保持占用规模小；此时导入将像
以前一样共享同一个 uwsgi 池。

### PSIRT 公告引擎（可选）

该 Chart 可以部署 PSIRT 公告引擎，这是一项用于根据 DefectDojo 发现项
编写和发布安全公告的服务。默认情况下处于关闭状态。启用后，它会出现
在您主 DefectDojo 主机的 `/psirt/` 路径下——nginx sidecar 会对其
进行代理，因此不需要额外的 ingress 或 DNS 条目。

```yaml
psirt:
  enabled: true
  # REQUIRED: full async connection URL. Use a dedicated database (its
  # migrations must not share DefectDojo's database).
  databaseUrl: "postgresql+asyncpg://pae:<password>@<host>:5432/pae"
  # Pre-shared secret for autonomous advisory publishing. The scheduler sends
  # it to DefectDojo as an X-Psirt-Secret header (no minted token, no UI step);
  # the chart injects the SAME value into the DefectDojo pods so they accept it.
  # Optional — omit to disable autonomous publishing (the pod still boots).
  psirtSharedSecret: "<high-entropy secret>"
  # Strongly recommended: pin both secrets. Left empty they are re-generated
  # on every helm upgrade, which logs out active sessions and invalidates
  # stored DefectDojo tokens.
  sessionSecretKey: ""   # any 64-character string
  fernetSaltB64: ""      # python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`psirtSharedSecret` 是您自行选择的一个普通值——不涉及任何 DefectDojo
用户或颁发的令牌。请设置一个高熵字符串（例如
`python -c "import secrets; print(secrets.token_urlsafe(48))"`）。
该 Chart 会将其同时接入 psirt 引擎的 Secret 和 DefectDojo 的 Pod，
因此单个值即可在全新安装时实现无需人工干预的发布，无需任何启动后
步骤。轮换方法：更改该值并执行 `helm upgrade`。

数据库设置：将 `databaseUrl` 指向 DefectDojo 使用的同一个 PostgreSQL
主机（或任何其他可访问的主机），并使用您选择的数据库名称。如果该
数据库不存在，Pod 会在首次启动时创建它，这需要以 postgres 超级
用户身份进行一次性授权：

```sql
ALTER ROLE pae CREATEDB;
```

运维说明：

- 将 `psirt.replicas` 保持为 1。该服务运行其自己的内部任务调度器，
  第二个副本会导致每个计划任务都执行两次。
- 该 Pod 挂载共享媒体卷（公告附件位于 `<media>/pae/uploads` 下），
  因此适用与导入器池相同的 ReadWriteMany 存储指导。
- 公告源和 NVD 查询需要出站 HTTPS。当
  `networkPolicy.profile=aggressive` 时，允许的 CIDR 列表
  （`networkPolicy.externalAPIs.allowedCidrs`）必须覆盖这些端点。
- 可选的 `psirt.nvdApiKey` 可将 NVD 速率限制从每 30 秒 5 次请求
  提高到每 30 秒 50 次请求。

### Sensei 扫描/修复引擎（可选）

该 Chart 可以部署 Sensei 引擎，这是服务端扫描和自动修复（fix）
任务背后的服务。默认情况下处于关闭状态，且启动无需额外配置：

```yaml
sensei:
  enabled: true
```

该引擎不持有任何长期存在的密钥。扫描/修复凭据和端点 URL 随每个
任务一起传递，由 DefectDojo 的加密 worker 配置分发。django 和
celery 在集群内部访问该引擎（`SENSEI_ENGINE_URL` 会自动接入共享的
configmap），因此不需要 ingress 或 DNS 条目。

运维说明：

- 默认情况下，引擎会通过您的公开站点 URL（`dojo.url`）回调
  DefectDojo。设置 `sensei.ddCallbackUrl` 可覆盖此行为——对于纯粹
  的集群内部流量，可将其指向内部 nginx 监听器，但此时引擎必须信任
  DefectDojo 的内部 CA。
- 用于修复任务的 LLM 凭据通常在应用内设置（AI Model Settings），
  并随每个任务一起传递。仅当引擎必须从自身环境中读取密钥时，才
  需要设置 `sensei.llm.*`；相比明文的 `sensei.llm.apiKey`，更推荐
  使用 `sensei.llm.existingSecret`。
- 若要让引擎针对 Google Vertex AI 运行，而不是使用提供商 API
  密钥，请将 `sensei.llm.provider` 设置为 `vertex`，并将
  `sensei.llm.vertexProject` 设置为托管 Vertex 的 GCP 项目
  （`sensei.llm.vertexRegion` 通常为 `global`）。该 Pod 使用
  Application Default Credentials 进行身份验证，因此请通过
  `sensei.serviceAccountName` 加 Workload Identity 为其提供 GCP
  服务账号，或者使用 `sensei.extraVolumesRaw` 和
  `sensei.extraVolumeMounts` 挂载密钥文件，然后通过
  `sensei.extraEnv` 将 `GOOGLE_APPLICATION_CREDENTIALS` 指向该文件。
- `sensei.llm.fallbackChain` 接受一个以逗号分隔的 `provider` 或
  `provider:model` 条目列表，当主要提供商返回可重试的失败时，引擎
  会依次回退到这些条目。将链的末尾设置为不同的供应商（例如
  `vertex-gemini:gemini-2.5-pro`）可以让修复任务在主要提供商发生
  中断期间持续运行。
- 扫描器镜像较为庞大。`sensei.maxConcurrentJobs`（默认值为 3）
  限制了每个 Pod 的并行任务数量，默认资源配置（请求 1Gi / 限制
  4Gi）就是按此上限设定的——如需提高上限，请将两者一并提高。
- 默认启用基于 CPU 的 HPA（1 到 4 个副本）。将
  `sensei.hpa.maxReplicas` 设置为与 `sensei.hpa.minReplicas` 相等，
  可以改为将副本数量固定为 `sensei.replicas`。
- 仓库克隆、git 托管 API 和 LLM 提供商 API 需要出站 HTTPS。当
  `networkPolicy.profile=aggressive` 时，允许的 CIDR 列表
  （`networkPolicy.externalAPIs.allowedCidrs`）必须覆盖这些端点。

### 轮换 TLS 证书

该 Chart 使用两类 TLS 证书，每一类都有不同的轮换流程。

#### 内部 TLS（服务间）

这些是 `dojopro-internal-tls` 和 `dojopro-internal-ca` 密钥，用于
nginx、connectors 以及其他内部服务之间的通信。

```bash
# Replace the existing secret with new cert/key
kubectl create secret tls dojopro-internal-tls \
  --cert=new-server.crt \
  --key=new-server.key \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Replace the CA bundle
kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=new-ca.crt \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart affected pods to pick up new certs
kubectl rollout restart deployment -n $NAMESPACE
```

#### Ingress TLS（面向外部/浏览器）

轮换方式取决于您如何配置 TLS：

- **ACM 托管（EKS）：** 自动续期——无需任何操作。
- **cert-manager：** 根据 `duration` 和 `renewBefore` 设置自动续期
  （默认值：2160h / 720h）。
- **GKE 托管证书：** 自动续期——无需任何操作。
- **通过 Kubernetes 密钥手动管理的证书：** 使用与上文相同的
  `kubectl create secret tls ... --dry-run=client` 模式，更新
  ingress 所引用的密钥。
- **自动生成的内部证书：** 如果 `certificates.generation.enabled: true`，
  该 Chart 可以通过 `helm upgrade` 重新生成这些证书。

> 在 Kubernetes 中，权威来源是 Secret 对象——更新密钥并滚动更新
> 部署，就是证书轮换的工作方式。

> 如果您使用 External Secrets Operator 或 Sealed Secrets 来管理
> TLS 密钥，轮换操作会在该层处理，Kubernetes 密钥会自动更新——
> 无需手动执行 `kubectl` 步骤。

---

## Values 文件分层

该 Chart 会堆叠多个 values 文件。后面的文件优先：

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

平台预设和 profile 预设内置于 Chart 中（`dojopro/presets/`）。它们
包含在打包的 `.tgz` 中，并与 Chart 一起进行版本管理。客户不需要
修改它们。

当从解压后的 Chart 使用 `helm install` 时，请使用在
[解压](#extract-the-chart-package)过程中设置的 `$CHART` 变量来
引用它们：
```
-f $CHART/presets/platforms/aws-eks.yaml
```

当使用 ArgoCD 时，请相对于 Chart 根目录引用它们：
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

不要将资源限制放在客户文件中，也不要将平台配置放在 profile 文件中。
让每一层都只专注于一件事。

> **预设版本管理——ArgoCD 与 CLI 的区别：** ArgoCD 从 Chart 包内部
> 引用预设，因此当您更改 `targetRevision` 时，它们会自动更新。
> CLI 用户在升级到新的 Chart 版本时，必须重新解压预设，才能获取
> 平台或 profile 默认值的任何更改。请使用带版本号的解压路径
> （例如 `dojopro-2.55.4/`），以避免在不同 Chart 版本之间产生
> 混淆——参阅[解压 Chart 包](#extract-the-chart-package)。

---

## 定制与可扩展性

除了平台/profile/客户 values 文件之外，该 Chart 还提供了一流的
扩展点，用于接入您自己的基础设施——sidecar、init 容器、环境变量、
卷、服务账号、调度约束，以及任意的额外清单——而无需分叉（fork）
该 Chart：

- **各组件级钩子（hooks）**——`extraEnv`、`extraEnvFrom`、
  `extraVolumesRaw`、`extraVolumeMounts`、`extraInitContainers`、
  `extraContainers`、`hostAliases`、`priorityClassName`、
  `topologySpreadConstraints`、`dnsConfig`，以及 `serviceAccountName`，
  适用于每一个工作负载（django、celery worker/beat、connectors、
  ddorch、ddorch-workers、integrators、mcp-server、psirt）。
- **顶级 `extraManifests`**——渲染任意用户提供的 YAML（ConfigMap、
  Secret、NetworkPolicy 等），与 Chart 一同呈现，并通过 Helm 的
  `tpl` 函数结合 Chart 的根上下文进行处理。
- **作为总括 Chart（umbrella chart）使用**——`dojopro` 可以通过
  `file://` 或 OCI 依赖作为子 Chart（subchart）嵌入，适用于在
  Chart 周围分层附加资源的客户捆绑包发布场景。
- **模式感知（schema-aware）验证**——`values.schema.json` 覆盖了
  每一个钩子，因此编辑器可以获得自动补全，`helm lint`/`helm install`
  也会验证您的覆盖设置。

有关模式、示例以及升级稳定性保证，请参阅 BYO 可扩展性指南——在
PDF 版本中作为**附录：自带基础设施（Bring Your Own Infrastructure，
BYO）**收录。

---

## 网络策略

该 Chart 为每个组件都提供 NetworkPolicy，默认启用
（`networkPolicy.enabled: true`）。默认拒绝（default-deny）基线的
作用范围限定于本次发布（release）的 Pod（通过
`app.kubernetes.io/name` + `app.kubernetes.io/instance` 标签），
因此不会影响共享同一命名空间的其他工作负载。

规则的严格程度由 **`networkPolicy.profile`** 控制：

| Profile | Egress | Pod-to-pod ingress | External ingress |
|---------|--------|--------------------|------------------|
| `standard`（默认） | 允许所有出站流量（`0.0.0.0/0`） | 允许本次发布自身 Pod 之间的所有流量 | 仅限于 Ingress 控制器/负载均衡器 |
| `aggressive` | 细粒度的按组件允许列表（仅限 DNS、数据库/代理、特定的集群内服务、明确允许的外部 API） | 细粒度的按组件允许列表 | 仅限于 Ingress 控制器/负载均衡器 |

- **`standard`** 推荐用于大多数集群。它可以避免因集群特定的出站
  依赖（GKE 元数据服务器、NodeLocal DNSCache、云存储/API 端点）
  以及应用内服务调用而导致的问题，同时仍将外部入站流量锁定在
  ingress 路径上：本次发布信任自己的 Pod，但外部流量仍必须经过
  前门进入。
- **`aggressive`** 在两个方向上都强制执行严格的允许列表。如果您
  使用此模式，可能需要针对您的集群调整 `networkPolicy` 下的例外
  配置：
  - `nodeLocalDns`——允许 NodeLocal DNSCache 解析器（默认使用
    link-local 地址 `169.254.20.10`，端口 53）。在运行 NodeLocal
    DNSCache 的集群（例如 GKE 附加组件）上是必需的，否则 DNS
    解析会失败。
  - `dnsSelectors`——为自定义 DNS 配置覆盖 DNS 出站目标。
  - `allowExternalAPIs` / `externalAPIs`——控制到外部 HTTPS API
    的出站流量，以及哪些 CIDR 被阻止（例如云元数据）。

在任意 values 文件中设置该 profile，例如：

```yaml
networkPolicy:
  profile: aggressive
```

> **GKE 健康检查**在两种 profile 下都会得到处理——GCE 负载均衡器的
> 探测地址段（`130.211.0.0/22`、`35.191.0.0/16`）始终被允许在 GKE
> 上访问 django 后端。参阅 [GCP GKE](#gcp-gke)。

### Ingress 控制器访问（502 Bad Gateway）

在非 GKE/非 OpenShift 集群上，django 的 NetworkPolicy 通过选择
Kubernetes 自动应用于每个命名空间的 `kubernetes.io/metadata.name`
标签所在的命名空间，来允许 Ingress 控制器进入。默认情况下，这期望
控制器位于名为 **`ingress-nginx`** 的命名空间中，且控制器 Pod 带有
`app.kubernetes.io/name: ingress-nginx` 标签（ingress-nginx Chart
的默认值）。

如果您的 Ingress 控制器位于名称不同的命名空间中、使用不同的 Pod
标签，或者是完全不同的控制器（Traefik、ALB 等），该策略会静默丢弃
其流量，请求将返回 **502 Bad Gateway**（控制器日志中显示
`connect() failed (110: Operation timed out)`）。请使用
`networkPolicy.ingressSource` 将策略指向您真实的 Ingress 来源：

```yaml
networkPolicy:
  ingressSource:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: <ingress-namespace>
      podSelector:
        matchLabels:
          app.kubernetes.io/name: <controller-label>
```

如果只是名称不同，也可以调整 `networkPolicy.ingressNamespace` /
`networkPolicy.ingressControllerLabel`。更多 `ingressSource` 示例
（Traefik、OpenShift router、AWS ALB）请参阅 `values.yaml` 中
`networkPolicy` 下的注释。

---

## 升级

推荐的升级路径是直接从 DefectDojo OCI 注册表拉取 Chart——无需解压
zip 文件：

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

典型的 OCI 升级如下所示（使用与最初安装时相同的 values 文件和
`--set` 参数）：

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --wait --timeout 15m
```

安装时使用的打包 zip 工作流同样适用于升级——只需针对解压后的
`$CHART` 路径，将 `helm install` 替换为 `helm upgrade` 即可。

有关身份验证、ArgoCD 升级、验证、回滚和故障排查的内容，请参阅
[升级指南](/get_started/pro/onprem/upgrading_on_kubernetes/)——在
PDF 版本中作为**附录：升级 DefectDojo Pro**收录。

---

## 卸载

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> 系统不会删除 PVC、外部数据库和外部 Secret。
> 请单独清理这些资源。

### 清理 PersistentVolume

回收策略为 `Retain` 的 PersistentVolume 是**集群范围**的资源 — 它们不会因 `helm uninstall` 或删除命名空间而被移除。如果您将 DefectDojo 重新安装到另一个命名空间，遗留 PV 的所有权元数据会与新安装发生冲突，并导致 `helm install` 被阻止执行。

卸载后检查是否有遗留的 PV：

```bash
kubectl get pv | grep dojopro
```

如果仍有残留，将其删除：

```bash
kubectl delete pv dojopro-media-pv
```

> **注意：** 删除 PV 只会移除 Kubernetes 卷引用，底层数据仍会保留在存储后端（例如 EFS 文件系统）中。如果您打算重新安装，这样做是安全的，但应当是有意为之的操作。

---

## 使用内嵌 PostgreSQL 和 Redis 进行本地测试

> **此配置仅适用于本地测试和评估。请勿在生产环境中使用内嵌 PostgreSQL 或 Redis。** 生产环境部署应使用托管服务（例如 RDS、ElastiCache），以获得可靠性、备份和扩展能力。DefectDojo 的支持服务不涵盖生产环境中内嵌数据库出现的问题。

该 chart 可以使用 `minimal` profile 部署自己的 PostgreSQL 和 Redis，以便快速进行本地测试，这样就无需外部数据库和消息代理基础设施。

将以下内容添加到您的 values 文件中：

```yaml
# Enable embedded PostgreSQL (instead of external RDS)
postgresql:
  enabled: true
  database:
    password: "your-password"   # required — must match DD_DATABASE_PASSWORD in your secrets

database:
  external: false

# Enable embedded Redis (instead of external ElastiCache)
redis:
  enabled: true

celery:
  broker:
    external: false
```

> **重要提示：当 `postgresql.enabled` 为 true 且未设置 `database.existingSecret` 时，必须提供 `postgresql.database.password`。** 否则该 chart 将无法渲染。此密码必须与应用程序 Secret 中的 `DD_DATABASE_PASSWORD` 值一致。

> **内嵌 PostgreSQL 的默认凭据：** 该 chart 中内嵌 PostgreSQL 的默认值为用户名 `dojodbusr`、数据库名 `dojodb`（在 chart 的 `values.yaml` 中定义）。应用程序 Secret 中的 `DD_DATABASE_URL` 必须使用这些值，而不是 `secrets-template.yaml` 中面向外部数据库的占位符。例如：
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

`minimal` profile（`dojopro/presets/profiles/minimal.yaml`）会设置适合单节点测试集群的较低资源请求，但不会自动切换这些数据库/消息代理开关 — 您必须自行设置。

> **关于容器权限的说明：** 内嵌的 PostgreSQL 和 Redis 容器**不会**以 root 身份运行 — PostgreSQL 以 UID 999 运行，Redis 以 UID 1001 运行。唯一的例外是 PostgreSQL 的 **init 容器**（`init-chmod-data`），它会以 root 身份（UID 0）运行，以便在主进程启动前设置数据卷的目录属主。这是带持久化存储的 StatefulSet 的常见模式。如果您的集群强制实施禁止 root init 容器的 `restricted` Pod Security Standard 或 OpenShift SCC，请通过 `postgresql.initContainer.enabled: false` 禁用它（参见[已知问题](#known-issues-chart-version-2.57.1)）。

在 EKS 上使用内嵌 PostgreSQL 时，您还需要 EBS CSI 驱动程序（参见 [AWS EKS 前提条件](#aws-eks-prerequisites)），并可能需要调整存储默认值（参见[已知问题](#known-issues-chart-version-2.57.1)）。

安装前请先验证您的 values — 该最小化路径需要更多覆盖项，也更容易遇到渲染错误：

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/minimal.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  > /dev/null
```

如果执行成功且没有报错，即可使用相同的参数继续执行 `helm install`。

> **对于最小化/全新数据库的安装，请使用 `--timeout 30m`。** 内嵌 PostgreSQL 的资源较少，初始化程序必须在新数据库上从头运行所有数据库迁移。测试中这一过程耗时约 23 分钟，超过了标准安装示例中使用的 `--timeout 15m`。超时会导致 `helm install` 报告 `INSTALLATION FAILED`，尽管部署实际上会在后台顺利完成。使用 `--timeout 30m` 可以避免这种误报失败，以及由此产生的 `failed` 发布状态。

---

## 私有镜像仓库 / 物理隔离（Air-Gapped）环境

如果您的集群无法从默认的 DefectDojo 镜像仓库拉取镜像，请将镜像同步到您自己的镜像仓库，并配置该 chart 使用该仓库。

### 选项 1：全局镜像仓库覆盖

设置 `global.imageRegistry` 可重定向所有镜像拉取请求。该 chart 会从 `images.prefix` 中去掉原始镜像仓库地址，并加上您指定的地址：

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

这会影响所有镜像（django、nginx、celery、connectors、redis 等）。

### 选项 2：按镜像单独覆盖

如需更精细的控制，可设置 `images.registry`（影响主应用镜像），并单独覆盖各个镜像：

```yaml
images:
  registry: "my-registry.example.com"
  prefix: "defectdojo/"          # path within your registry
  tag: "2.53.0"
  connectors:
    registry: "my-registry.example.com"
    repository: "defectdojo/connectors"
    tag: "2.53.0"
  redis:
    registry: "my-registry.example.com"
    repository: "defectdojo/redis"
    tag: "7.2.4"
```

### 私有镜像仓库的镜像拉取 Secret

如果您的镜像仓库需要身份验证，请创建一个拉取 Secret 并引用它：

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

或者让该 chart 根据显式提供的凭据自动创建一个：

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

默认行为（`extractFromLicense: true`）会从许可证文件中提取 GCP 服务账号凭据，用于从 DefectDojo 的镜像仓库拉取镜像。使用您自己的镜像仓库时，请禁用此行为：

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## 覆盖平台注解

该 chart 会根据 `cloudProvider` 自动在 Ingress 和 Service 上注入特定于平台的注解（例如，EKS 使用 ALB 注解，GKE 使用 GCE 注解）。如果您需要完全控制注解 — 例如在 EKS 上使用 nginx ingress 控制器而非 ALB — 请设置 `platformAnnotations.enabled: false`，并提供您自己的注解：

```yaml
django:
  ingress:
    platformAnnotations:
      enabled: false
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "500m"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
  service:
    platformAnnotations:
      enabled: false
    annotations: {}
```

当 `platformAnnotations.enabled` 为 `true`（默认值）时，该 chart 会将平台注解与您的自定义注解合并。当键发生冲突时，您的注解优先，但如果不使用此开关，您就无法移除某个平台注解。

### Ingress 上传大小限制

默认情况下，该 chart 会在 Ingress 上设置 `nginx.ingress.kubernetes.io/proxy-body-size: "2400m"`，以便较大的扫描结果上传和 PDF 报告可以顺利通过 nginx-ingress，而不会出现 `413 Request Entity Too Large` 错误。可通过以下方式覆盖：

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

只要控制器是 nginx-ingress，此设置就会生效 — 无论 nginx-ingress 运行在 EKS、GKE 还是 AKS 之上。非 nginx 控制器会忽略此注解，必须通过各自的机制进行调整（AWS WAF 的请求体检测限制、AppGW 的 request-body-limit、OpenShift Route HAProxy 的 `tuningOptions`）。

---

## 各平台专属说明

### AWS EKS

- ALB ingress 需要 AWS Load Balancer Controller
- 如果使用 EFS 存储，需要 EFS CSI 驱动程序
- TLS 通过 ACM 证书在 ALB 终止
- 设置 `certificates.ingress.source: "acm"` 并提供 `acmCertArn`
- 由于 HTTPS 由 ALB 处理，`dojo.secureCookies: true` 可以正常工作

#### EFS 访问点（Access Point）

如果您的 EFS 文件系统配置了**访问点**（推荐用于强制挂载点的 UID/GID 属主），则**必须**在 values 文件中设置 `storage.efs.accessPointId`。否则，PV 会以 root 属主挂载 EFS 根目录，导致 DefectDojo 容器（以 UID 1001 运行）无法创建媒体子目录 — 从而使初始化程序因 `Permission denied` 错误而失败。

检查您的 EFS 访问点：

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

如果访问点已存在，请将其添加到您的 values 文件中：

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **重要提示：** PersistentVolume 上的 `volumeHandle` 字段在创建后是**不可变的**。如果您最初安装时未使用访问点，之后需要添加，则必须先删除现有的 PV 和 PVC，然后再运行 `helm upgrade`：
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> 这样做是安全的 — 删除 PV 只会移除 Kubernetes 引用，EFS 文件系统上的数据不会受到影响。

#### 加固集群 / GitOps 管控集群上的 StorageClass

有两个与 StorageClass 相关的假设，会在使用自定义 StorageClass 命名、或集群范围资源由应用 chart 之外的方式管理的集群上导致问题。

**在 EKS 上，动态制备的 PVC 默认使用 `gp3`。** 该 chart 动态制备的任何 PVC — 包括内嵌 Redis 卷（`redis.enabled: true`）和 `storage.type: "pvc"` 媒体卷 — 都会将其 StorageClass 解析为平台默认值，即 EKS 上的 `gp3`。如果您的集群中不存在名为 `gp3` 的 StorageClass（在使用自定义命名的加固集群上很常见），该 PVC 会停留在 `Pending` 状态，并出现 `storageclass.storage.k8s.io "gp3" not found` 事件，Pod 也永远不会启动。

可以通过以下两种方式之一进行覆盖：

- **全局设置（推荐）** — 一个开关即可控制该 chart 制备的所有 PVC：

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- **按组件设置**，适用于需要使用不同 StorageClass 的情况：

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  解析顺序为：按组件设置的值 → `storage.defaultStorageClass` → 平台默认值（`gp3`）。将某个值设为 `""` 可回退使用集群的默认 StorageClass。此规则**不**适用于默认的 EFS 媒体路径（见下文），该路径不使用任何 StorageClass。

**默认的 EFS 媒体卷不需要 StorageClass。** 当 `storage.type: "efs"` 时，该 chart 会通过 EFS 文件系统的 `volumeHandle` 和 `claimRef` 静态绑定媒体 PV — PV 和 PVC 均使用空的 `storageClassName`。媒体 PVC 的绑定**不**需要存在 `efs-sc` 这个 StorageClass。

只有当您通过 `storageClasses.efs.enabled: true`（默认值为 `false`）显式启用**动态** EFS 制备时，该 chart 才会创建集群范围的 `efs-sc` StorageClass。在集群范围资源由应用 chart 之外的方式（GitOps）管控的集群上，请保持默认值 `false` — 上述静态 EFS 路径不需要任何 StorageClass，也不需要该 chart 提供任何集群范围对象。如果您确实希望在 GitOps 环境下使用动态 EFS 制备，请在带外（out of band）创建该 StorageClass，并保持 `storageClasses.efs.enabled: false`。

### GCP GKE

- 使用 GCE ingress 控制器（`className: "gce"`），TLS 在 Google Cloud 负载均衡器上终止
- `gcp-gke.yaml` preset 会自动为 ingress 附加一个 `FrontendConfig`（HTTP→HTTPS 重定向 + SSL 策略）和一个 `BackendConfig`
- GCE 负载均衡器会直接从 Google 的地址段（`130.211.0.0/22`、`35.191.0.0/16`）对 django 后端进行健康检查。在 GKE 上，无论 `networkPolicy.profile` 取哪个值，该 chart 的 NetworkPolicy 都会自动放行这些请求，因此 `/nginx_health` 探针会成功，后端也会报告健康状态 — 参见[网络策略](#network-policies)

#### Google 托管证书与自备（BYO）TLS 证书

`gcp-gke.yaml` preset 默认使用**Google 托管证书**。请从以下两种方式中选择一种：

- **Google 托管（默认）：** 由 GCP 负责签发和续期证书。只需列出您的域名 — 无需 Kubernetes TLS Secret：

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **自备证书（BYO）：** 在发布所在的命名空间中提供一个已有的 Kubernetes TLS Secret，并让 ingress 指向它：

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  这会在 ingress 上渲染 `spec.tls[].secretName`，并省略 `networking.gke.io/managed-certificates` 注解。

> **引导脚本支持范围：** `scripts/bootstrap/bootstrap-gcp-gke.sh` 仅覆盖 GCP 原生的证书流程（`google-managed` 和 `pre-shared`）。对于自备 `secret` 的方式，请直接使用 `helm` 安装（先创建 TLS Secret，然后传入 `certificates.ingress.source=secret` 和 `certificates.ingress.secretName=<your-secret>`）。

> Google 托管证书会自动续期 — 参见[轮换 TLS 证书](#rotating-tls-certificates)。

### OpenShift / ROSA

- 默认使用 Route（`django.route.enabled: true`），但也支持 Ingress
- 若要改用 Ingress：设置 `django.ingress.enabled: true` 并设置 `django.route.enabled: false`
- 两者同一时间只能启用一个（该 chart 会校验两者互斥）
- 使用（默认的）边缘终止（edge-terminated）Route 时，**`dojo.secureCookies` 必须为 `false`**。这是强制要求，并非可选项。参见[准备 values 文件中的警告](#prepare-your-values-file)。
- `securityContext.openshift.fsGroup` 必须匹配您命名空间的 supplemental-groups 范围（关于如何查询，请参见[安装前检查清单](#infrastructure-details)）
- 通过 EFS 使用 NFS 效果良好 — 将 `storage.type: "nfs"` 与作为服务器的 EFS DNS 名称配合使用

#### 在 OpenShift 上使用 Ingress 而非 Route

OpenShift 自带一个基于 HAProxy 的默认 ingress 控制器。如果您更倾向于使用 Ingress 而非 Route（例如为了与其他集群保持一致，或使用自定义 ingress 控制器），请按如下方式配置您的 values：

```yaml
django:
  ingress:
    enabled: true
    className: "openshift-default"   # or your custom ingress class
    platformAnnotations:
      enabled: false                 # recommended — provide your own annotations
    pathType: "Prefix"
    path: "/"
    tls:
      enabled: true
    annotations: {}                  # add your ingress controller annotations here
  route:
    enabled: false
  nginx:
    tls:
      enabled: false
      generateCertificate: false
```

无论您选择哪种暴露方式，该 chart 的平台辅助逻辑仍会为 OpenShift 正确处理安全上下文、DNS 解析器和存储默认值。

---

## 已知问题（Chart 版本 2.57.1）

以下是当前 chart 中已确认的缺陷。在修复版本发布之前，这里记录了相应的临时解决方法。

### 仅使用本地 PostgreSQL 或 Redis 的最小化安装

以下问题仅适用于使用该 chart 内置 PostgreSQL 或 Redis（`postgresql.enabled: true` 或 `broker.external: false`）的情况，不会影响使用外部数据库和消息代理的生产环境部署。

**请勿将 EBS 用于媒体卷（BUG-14、BUG-15）**

EBS 卷仅支持 `ReadWriteOnce` — 同一时间只能挂载到单个节点。DefectDojo 要求媒体卷能够在多个 Pod（django、celery-worker、initializer、connectors）之间共享，而这些 Pod 可能被调度到不同的节点上。发生这种情况时，由于 EBS 无法同时挂载到多个节点，Pod 会卡在 `ContainerCreating` 状态并出现 `Multi-Attach error`。这个问题也会影响 `helm test`，因为 test-storage Pod 可能被调度到与应用 Pod 不同的节点上。

**媒体卷请使用 EFS（或其他支持 `ReadWriteMany` 的存储后端）而非 EBS。** EFS 支持集群中所有节点的并发访问，是 EKS 部署推荐使用的存储后端。

如果您必须在单节点集群上使用 EBS 进行测试，请覆盖以下默认值：

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

请注意，即使进行了这项覆盖，一旦 Pod 被调度到多个节点上（例如在扩容、节点替换或 `helm test` 期间），EBS 仍然会出现问题。使用 EFS 可以完全避免这一情况。

**PostgreSQL init 容器与非 root 安全上下文冲突（BUG-16）**

如果遇到 `CreateContainerConfigError`，请禁用它：

```yaml
postgresql:
  initContainer:
    enabled: false
```

### 所有部署场景

**initializer 运行期间 connectors Pod 出现崩溃循环（预期行为）**

在首次安装期间，当 initializer 任务正在执行数据库迁移时，connectors Pod 会进入 `CrashLoopBackOff` 状态。这是预期行为 — connectors Pod 会尝试调用 Django API（`/api/connectors/v1/config/`），由于数据库结构尚未完全迁移完毕，该调用会返回 500。一旦 initializer 任务成功完成（在 `kubectl get jobs` 中显示 `1/1 COMPLETIONS`），connectors Pod 会在下一次重启周期中恢复正常，无需人工干预。

**迁移完成后 initializer 崩溃会导致数据库状态无法恢复（BUG-18）**

如果 initializer 任务在运行数据库迁移**之后**、但在写入初始数据**之前**崩溃（例如由于存储权限错误或资源限制），数据库就会处于部分初始化的状态 — 表已经存在，但 `dojo_system_settings` 表是空的。在随后的重启中，initializer 会立即出现如下失败：

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

这会形成一个无法自动恢复的崩溃循环。**临时解决方法：** 重置数据库 schema，并重新运行 initializer：

```bash
# Drop and recreate the public schema
kubectl run psql-reset --rm -i --tty=false --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d <your-db-name> -U <your-db-user> \
     -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO <your-db-user>;"

# Delete the failed initializer job and trigger a new one
kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
helm upgrade dojopro $CHART ... (same flags as install)
```

> **预防措施：** 请在首次安装**之前**确保存储权限（尤其是 EFS 访问点 — 参见 [EFS 访问点](#efs-access-points)）和资源限制均已正确配置。运行 `helm template` 验证您的 values，如有条件，可使用测试 Pod 验证 EFS 挂载权限。

**日志中的 Hatchet token 警告（提示信息）**

当 `hatchet.enabled: false`（默认值）时，Pod 会在启动时记录如下警告：

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

这是**预期行为，并无害处**。从 chart 2.57 版本起，后台工作流的执行已整合为 `ddorch` + `ddorch-workers`，取代了原有基于 Hatchet 的 worker（`kairos`、`rulesengine`、`hatchet-integrators`）。Hatchet 客户端代码仍会在启动时初始化，因此在禁用 Hatchet 时该警告仍会出现，但不会影响任何功能。可以放心忽略此警告。

### 未配置 HTTPS

**ALB 的 ssl-redirect 注解需要 HTTPS 监听器（BUG-17）**

EKS preset 中包含一个 `ssl-redirect` 注解，该注解假定 ALB 上已存在 HTTPS 监听器。如果您尚未配置 ACM 证书和 HTTPS 监听器，此注解会导致重定向循环。请配置 HTTPS（推荐做法），或参见[不使用 HTTPS 进行部署（不推荐）](#deploying-without-https-not-recommended)以了解所需的完整变更内容。

---

## 故障排查

### Pod 卡在 CrashLoopBackOff 状态

检查日志：
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

通常是以下原因之一：Secret 缺失或有误（请检查全部 12 个键）、数据库无法访问（请检查 `database.host` 和安全组），或内部 TLS 证书缺失（请检查 `dojopro-internal-tls` 这个 Secret 是否存在）。

### 混用外部 Secret 与内联 Secret

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

请选择其中一种方式。如果您使用的是 `dojo.existingSecret`，请从您的 values 文件中移除所有内联 Secret 值（`dojo.secretKey`、`dojo.admin.password`、`monitoring.password` 等）。

### Schema 提示需要 admin.password

请设置 `dojo.existingSecret` — 配置了外部 Secret 后，schema 就会取消对密码的强制要求。

### OpenShift fsGroup 权限错误

如果 Pod 因 NFS 卷出现权限错误而失败，请检查 `securityContext.openshift.fsGroup` 是否落在您命名空间的 supplemental-groups 范围内。fsGroup 的查询方法参见[部署 → OpenShift / ROSA](#openshift-rosa)。

### ALB 未出现（EKS）

验证 AWS Load Balancer Controller 是否正在运行：
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

检查 ingress 事件：
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## 附录：客户配置模板

完整模板（`template.yaml`）可从 DefectDojo 支持门户获取，或联系 support@defectdojo.com 索取。请复制该模板，替换其中的 `REPLACE_*` 占位符，并删除不适用于您所在平台的部分。该模板针对以下内容提供了带注释的示例：

- 平台标识（`cloudProvider`）
- 镜像拉取 Secret 配置
- Ingress 与 Route 配置（EKS/GKE/OpenShift 使用 Ingress，OpenShift 使用 Route）
- EFS 和 NFS 存储选项
- 证书与 TLS 配置
- 安全上下文（uwsgi、nginx、OpenShift fsGroup）
- 网络策略
- 许可证下发方式（文件、Secret、内联）

---

## 修订历史

| 日期       | 版本    | 变更内容                                                              |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | 新增可选的 PSIRT Advisory Engine（`psirt.enabled`）：通过 nginx sidecar 在 `/psirt/` 下提供服务，通过 `psirt.databaseUrl` 使用专用数据库，并提供 Secret 固定（pinning）指南、网络策略规则、自备（BYO）钩子 |
| 2026-04-17 | 2.57.1  | 记录 `ddorch` + `ddorch-workers`（取代 kairos/rulesengine/hatchet-integrators 的新编排器组合）；为预检和部署命令新增 `ddorch.tls.rootCa/cert/key` 的 `--set-file` 参数；新增包含 SAN 要求的 ddorch mTLS 证书章节；预期 Pod 列表中列出 mcp-server；为 ddorch（单例）和 ddorch-workers 新增 PDB；新增关于 ddorch 证书下发的 ArgoCD 前提条件说明；更新 Hatchet 警告说明以反映 worker 整合情况 |
| 2026-03-25 | 2.55.4  | 新增 EFS 访问点文档和模板字段；记录 initializer 崩溃恢复方法（BUG-18）；说明 init 期间 connectors 崩溃循环属于预期行为；澄清 Hatchet token 警告无害；修复失效的已知问题锚点；chart 解压路径按版本区分；整合无 HTTPS 场景的指导；卸载时清理 PV；命名空间一致性说明；ArgoCD 与 CLI 的 preset 版本管理对比提示 |
| 2026-03-11 | 2.53.0  | 修复 helm 命令路径；新增 chart 解压说明、EKS 前提条件、预检数据库检查、HTTPS 提示、TLS 轮换、已知问题章节 |
