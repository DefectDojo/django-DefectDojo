---
title: 在 Docker Compose 上安装
description: 使用 dojo-compose-cli 在单台主机上安装自托管的 DefectDojo Pro，并将 PostgreSQL 部署在单独的服务器上
draft: false
weight: 15
audience: pro
---

本页介绍如何在 Docker Compose 上安装 DefectDojo Pro，这是两种自托管模式中较为简单的一种，如果您尚未运行 Kubernetes，这是正确的选择。

最终会得到两台主机。一台在 Docker Compose 下运行应用程序及其支持服务，另一台运行 PostgreSQL。您可以指向一个托管数据库，而不必自行运行数据库；出于评估目的，您也可以在应用程序主机上以容器形式运行数据库，但这并不适合用于生产数据。

几乎所有工作都由 `dojo-compose-cli` 完成，DefectDojo 会在您获得许可证的同时提供该工具。它的 `first-install` 命令是一个交互式向导，用于配置部署、拉取镜像、启动所有组件，并注册一个 systemd 服务。

## 开始之前

首先确定部署的规模。本节中的硬件规格指南涵盖了应用程序主机和数据库两方面应配置的内容。

Ubuntu 24.04 LTS 是此安装所支持的操作系统。请在开始之前将其完全更新。安装过程中的命令以 root 身份运行，因此您需要在两台主机上都拥有 `sudo` 权限或 root shell。

您需要来自 DefectDojo 的两个文件，它们会随您的订阅一起提供：`dojo-compose-cli` 压缩包和您的许可证文件（通常命名为 `dojopro.lic`）。如果您没有这些文件，请联系您的客户代表或发送邮件至 [support@defectdojo.com](mailto:support@defectdojo.com)。

## 设置数据库

DefectDojo Pro 需要 PostgreSQL 16 或更高版本。

### 使用托管数据库

如果您使用的是托管 PostgreSQL 服务，请按照该服务提供商的文档创建实例，然后创建以下内容：

- 一个名为 `dojodb` 的数据库
- 一个名为 `dojodbusr` 的数据库用户，拥有 `dojodb` 的所有权限，并设置为其所有者

请记下主机名、端口（如果不是默认的 5432）以及凭据。安装过程中需要用到这些信息。

### 自行运行 PostgreSQL

在 Ubuntu 24.04 上，PostgreSQL 16 位于默认软件源中：

```bash
apt update
apt -y install postgresql postgresql-contrib
```

创建数据库和应用程序用户。DefectDojo 的编排服务使用第二个数据库，因此两个都要创建：

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

请使用字母数字组合的密码。稍后当密码被放入连接字符串时，特殊字符需要进行 URL 编码，这一步很容易出错。

然后让数据库监听来自应用程序主机的连接。在 `/etc/postgresql/16/main/postgresql.conf` 中，将 `listen_addresses` 设置为数据库服务器自身的地址，如果您不想固定地址，也可以设置为 `*`：

```bash
listen_addresses = '<db-server-address>'
```

然后在 `/etc/postgresql/16/main/pg_hba.conf` 中添加三行，授权应用程序主机访问。将访问范围限制为应用程序主机的地址，比对所有地址开放更为妥当：

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

重启数据库以使两处更改生效：

```bash
systemctl restart postgresql
```

## 准备应用程序主机

### 出站连接

在受限网络中，应用程序主机需要对以下目标具有出站访问权限。除非另有说明，均为 443 端口上的 HTTPS。

| 目标 | 用途 | 是否必需 |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | DefectDojo Pro 容器镜像仓库 | 是 |
| 您的数据库主机，通常为 5432 端口 | 应用程序到数据库 | 是 |
| 您所用发行版的软件包仓库 | 安装过程中的操作系统依赖 | 是 |
| `download.docker.com` | 安装过程中的 Docker Engine 软件包 | 是 |
| `api.first.org` | EPSS 漏洞利用预测评分 | 可选 |
| `www.cisa.gov` | 已知被利用漏洞（KEV）目录 | 可选 |

请按主机名而非地址加入允许列表。镜像仓库位于内容分发网络之后，因此其地址会因地理位置而异，并且会随时间变化。

如果该主机通过出站代理访问互联网，请参阅[在正向 HTTPS 代理后运行 DefectDojo](/onprem_deployment/forward_proxy/)。如果该主机完全无法访问互联网，请改为遵循本节中的离线（air-gapped）安装流程。

### 确认数据库可访问

在继续之前，先安装客户端工具并进行连接测试。现在诊断数据库问题要比安装过程中容易得多：

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### 安装 Docker Engine

请按照 [Ubuntu 版 Docker Engine 安装说明](https://docs.docker.com/engine/install/ubuntu/) 进行操作。请使用 Docker 官方文档而不是副本，因为安装步骤会随时间变化。请将 `docker-compose-plugin` 软件包与引擎一起安装，该说明默认已包含此软件包。

然后将您的用户添加到 `docker` 组，并使新的组成员关系生效：

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## 安装 DefectDojo

将 CLI 压缩包和许可证文件复制到应用程序主机的同一个目录中，然后解压 CLI：

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

然后从该目录运行安装程序：

```bash
sudo ./dojo-compose-cli first-install
```

该向导会提示您输入以下内容。

| 提示项 | 说明 |
| --- | --- |
| `DOJO_CLI_KEY` | 用于加密 CLI 存储在磁盘上的配置的密钥。请现在选定并妥善保存，因为后续命令需要用到它。 |
| DefectDojo Version | 要安装的版本。 |
| Deploy Version | 要使用的部署文件版本。请将其设置为与版本相同的值。 |
| Deploy Type | 数据库位于独立主机时选择 `separate-db`，在容器中运行 PostgreSQL 时选择 `containerized-db`。 |
| Database Connection Type | 选择 Single Line，并提供完整的连接字符串。 |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`。必须以 `postgres://` 开头，而不是 `postgresql://`。 |
| `DD_ALLOWED_HOSTS` | 应用程序将响应的 Host 请求头。 |
| `DD_SITE_URL` | 用户访问 DefectDojo 的完整 URL，例如 `https://defectdojo.internal.example.com`。 |

在这些提示中，有两点值得注意。请以单行形式提供数据库连接，而不要逐项分别输入，因为逐项输入的方式目前不会询问用户名。此外，如果密码中包含 `!`、`@` 或 `#` 之类的字符，需要在连接字符串中对其进行 URL 编码。

随后安装程序会拉取镜像、启动整套服务、创建 systemd 服务，并打印生成的管理员凭据。**请在关闭终端之前保存这些凭据，它们不会再次显示。**

完成后，您可以通过所提供的站点 URL 访问 DefectDojo。

## 安装过程创建的内容

| 项目 | 位置 |
| --- | --- |
| CLI 可执行文件 | `/usr/bin/dojo-compose-cli` |
| 应用程序文件、compose 文件、nginx 配置、媒体文件 | `/opt/dojo/` |
| 许可证文件 | `/etc/defectdojo/dojopro.lic` |
| 加密的 CLI 配置 | `/etc/defectdojo/compose.config` |
| TLS 证书 | `/opt/dojo/certs/` |
| 您的自定义配置 | `/opt/dojo/customizations/` |
| Systemd 服务 | `/etc/systemd/system/defectdojo-compose.service` |

安装过程还会创建一个 `dojosrv` 用户和用户组，作为应用程序文件的所有者。

运行中的服务栈包括 Django 应用程序、一个单独处理扫描导入的容器、nginx、一个 Celery 工作进程和调度器、用于缓存和队列的 Valkey、连接器服务，以及 MCP 服务器。可以通过 `docker ps` 列出这些容器。

日常使用中，您需要用到以下命令：

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

更改任何配置后，请使用 `app restart`，因为它会重新创建容器，从而使新值生效。

## 替换 TLS 证书

安装过程会附带一个自签名证书，以便站点能够立即使用。您可以通过覆盖以下两个文件来替换为您自己的证书，文件名需保持完全不变：

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

然后运行 `dojo-compose-cli app restart` 以使其生效。

## 重置管理员密码

如果您丢失了生成的密码，可以从应用程序主机上重置它。此操作要求 DefectDojo 正在运行：

```bash
dojo-compose-cli app change-password
```

## 升级

请先备份您的数据库，并阅读从当前版本到目标版本之间每一个版本的发行说明，而不要只看目标版本的说明。请参阅[升级说明](/releases/os_upgrading/upgrading_guide/)。

CLI 可以完成整个升级过程，并会提示您输入版本：

```bash
dojo-compose-cli app upgrade
```

如果您希望分步执行，可以先停止应用程序，设置新版本，下载匹配的部署文件，然后重新启动：

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

下载步骤会将新版本的 `docker-compose.yml`、nginx 配置和 `local_settings.py` 与您现有的版本进行比较，并在出现差异时告知您，以便您协调这些更改。添加 `--overwrite` 会接受这些文件的新版本，并丢弃对它们所做的本地修改，因此请谨慎使用该选项。

请将您自己的设置保存在 `/opt/dojo/customizations/local_settings.py` 中。该文件归您所有，并且在升级后仍会保留。

## 命令参考

`dojo-compose-cli --help` 会列出所有命令，每个子命令也都支持 `--help`。以下是您最有可能用到的命令：

| 命令 | 作用 |
| --- | --- |
| `first-install` | 交互式首次安装 |
| `app start`、`app stop`、`app restart` | 控制服务栈 |
| `app upgrade` | 升级到更新的版本 |
| `app pull-images`、`app purge-images` | 拉取或移除已配置的镜像 |
| `app change-password` | 在应用运行状态下重置管理员密码 |
| `config print` | 显示当前配置 |
| `config set` | 设置版本、部署版本、部署类型或离线模式 |
| `config rotate-secret` | 轮换用于加密已存储配置的密钥 |
| `environment print`、`environment add`、`environment remove` | 管理环境变量 |
| `deploy download` | 获取所配置版本对应的部署文件 |
| `license print`、`license status`、`license update` | 查看和更新您的许可证 |
| `validate db-connection` | 检查数据库连接字符串 |
| `validate deploy-version` | 检查部署文件是否与所配置的版本匹配 |
| `diagnostics collect` | 收集用于支持请求的诊断信息包 |
| `register` | 对容器镜像仓库进行身份验证 |
| `update-binary` | 更新 CLI 本身 |

大多数命令都需要 `DOJO_CLI_KEY`，因为配置在静态存储时是加密的。请为您的会话导出该变量，或使用 `sudo -E` 将其传递给 `sudo`：

```bash
export DOJO_CLI_KEY="your-key"
```

## 问题咨询或支持

如果安装未能完成，`dojo-compose-cli diagnostics collect` 会收集一份报告包，这是让我们提供帮助的最快方式。请将该报告包连同安装失败时您正在运行的操作一起发送至 [support@defectdojo.com](mailto:support@defectdojo.com)。
