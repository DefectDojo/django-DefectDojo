---
title: 从开源版迁移到自托管 DefectDojo Pro
description: 将您的开源 DefectDojo 数据库和媒体文件迁移到自托管的 DefectDojo Pro 部署中
draft: false
weight: 6
audience: pro
---

本页介绍如何将开源 DefectDojo 实例中的数据迁移到自托管的 DefectDojo Pro 部署中。

示例使用 Amazon Web Services,采用 EC2 上的 Docker Compose 或 EKS 上的 Kubernetes,数据库使用 Amazon RDS for PostgreSQL。此流程正是针对这一组合验证过的。对于提供托管 PostgreSQL 和同等计算资源的其他云服务商,以及本地硬件环境,同样适用这一流程,只需将特定于服务商的命令替换为相应的命令即可。

由于部署由您自行托管,整个迁移过程中您的数据始终留在您自己的环境内。导出和恢复操作均由您执行,DefectDojo 支持团队可以在任何步骤提供协助。如果您的 DefectDojo Pro 实例是由 DefectDojo 云托管而非自托管,请改为联系 [support@defectdojo.com](mailto:support@defectdojo.com),因为恢复工作将由 DefectDojo 团队为您完成。

整体流程是:从开源实例中导出数据库和媒体文件,将其恢复到 Pro 部署所使用的数据库和存储中,让 Pro 指向恢复后的数据库,然后验证结果。

## 开始之前

在导出任何内容之前,请先确认以下事项。

您的数据库引擎。DefectDojo 支持 PostgreSQL。对 MySQL 的支持已被弃用,并在 [2.37.0 版本中移除](/releases/os_upgrading/2.37/),因此仍在使用 MySQL 的旧实例必须先转换为 PostgreSQL 才能进行迁移。如果您的情况属于这种,请联系支持团队。

数据库的运行位置。它可能是默认 Docker Compose 配置中的一个容器,也可能是同一主机上的独立服务、另一台虚拟机上的服务,或是 Amazon RDS、Cloud SQL 等托管服务。导出命令会因数据库所处位置的不同而有所差异。

您的开源版本。可在 UI 页脚,或通过部署标签和镜像版本查找。所有 2.x 版本均可使用此流程迁移。如果您运行的是 3.0.0、3.0.1、3.0.2 或 3.0.100,请先升级到 [3.0.200](/releases/os_upgrading/3.0.200/) 或更高版本,然后再开始迁移。请查看从当前版本到目标版本之间每个版本的[升级说明](/releases/os_upgrading/upgrading_guide/)。

版本对齐。您的开源版本应尽可能与要迁移到的 DefectDojo Pro 版本一致或接近。首次启动时,Pro 会运行数据库迁移,将架构升级到自身版本,因此版本差距过大会增加迁移耗时过长或失败的风险。请在导出转储之前先对齐版本。

目标数据库。请配置当前受支持的 PostgreSQL 主版本(16 或更高),且不得低于开源实例所运行的版本,因为转储无法恢复到更低的主版本中。在 AWS 上,应将 RDS 实例置于与 Pro 计算资源相同的 VPC 中,并允许来自恢复主机的 5432 端口入站流量。

恢复主机。您需要一台与数据库处于同一网络中的机器,并安装 PostgreSQL 客户端工具 `pg_restore` 和 `psql`。在 AWS 上,应使用与 RDS 实例位于同一 VPC 中的 EC2 实例,最好还在同一可用区内。

可用磁盘空间。在转移数据之前,源服务器需要有足够的空间容纳数据库转储文件和压缩后的媒体归档文件。

## 第 1 步:导出数据库

默认的 Docker Compose 配置使用 `defectdojo` 同时作为数据库用户名和数据库名。这些值可以被覆盖,因此请检查 `docker-compose.yml` 或 `.env` 文件中的 `DD_DATABASE_URL` 值。默认连接字符串为:

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

在以下命令中,请将 `<db_username>`、`<database_name>` 和 `<postgres_container_name>` 替换为您自己的值。可使用 `docker ps` 查找容器名称。

建议使用压缩后的自定义格式转储。`pg_restore` 可以直接加载该格式,并且能够避免恢复到托管数据库时出现的大多数所有权和角色问题。

对于容器化的 PostgreSQL(即默认的 Docker Compose 设置):

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

如果数据库需要密码,请通过环境变量传递:

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

对于外部或远程 PostgreSQL,例如独立虚拟机、Amazon RDS 或 Cloud SQL:

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

省略 `-Fc` 生成的纯文本 SQL 转储同样可用。但它往往会内嵌 `CREATE ROLE`、`ALTER ROLE` 和 `CREATE DATABASE` 语句,而托管数据库会拒绝这些语句,如果您使用这种格式,请参阅第 4 步中的说明。

## 第 2 步:导出媒体文件

DefectDojo 会将上传的文件(如截图、威胁模型和风险接受文档)存储在媒体目录中。用于导入和重新导入的扫描文件不会被开源 DefectDojo 保存在磁盘上,因为它们在解析后即被丢弃,因此媒体目录中只包含用户上传的文件。

该目录的位置取决于您的部署方式:

| Deployment method | Typical media path |
| --- | --- |
| Docker Compose | Named volume `defectdojo_media`, mounted at `/app/media` |
| Bare metal | `/opt/dojo/media`, or the path set in `DD_MEDIA_ROOT` |
| Kubernetes | Persistent volume mounted at `/app/media` |

将该目录压缩为单个归档文件。从命名卷压缩:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

从磁盘路径压缩:

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## 第 3 步:命名文件

请在两个文件名中都加入开源版本号,以便在恢复过程中明确所涉及的版本。以运行 2.38.1 版本的实例为例:

| File | Renamed to |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

将这两个文件移动到您的恢复主机上。您可以使用 `scp` 等工具直接复制它们,也可以先将其暂存到您自己账户下的私有对象存储中,再下载到恢复主机。在 AWS 上,这意味着使用私有 S3 存储桶和 `aws s3 cp`。无论采用哪种方式,数据都始终留在您自己的环境内。

## 第 4 步:恢复数据库

在恢复主机上运行恢复操作,指向数据库端点。不同的托管 PostgreSQL 服务在这方面的支持有所不同。Amazon RDS 不支持从存储桶一步导入转储文件,因此受支持的方式是通过客户端执行 `pg_restore`。

1. 创建数据库和应用角色。以主用户身份连接,创建目标数据库以及转储文件所期望的角色。两者的默认值均为 `defectdojo`,如果您已覆盖过默认值,请使用您自己的值。

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. 恢复转储文件。对于自定义格式的转储,请使用 `--no-owner` 和 `--no-privileges`,以避免恢复过程尝试将所有权重新分配给目标环境中不存在的角色。托管数据库不会授予真正的超级用户权限,因此尝试执行此操作的恢复将会失败。

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

对于纯文本 SQL 转储,请先注释掉或删除其中所有的 `CREATE ROLE`、`ALTER ROLE`、`CREATE DATABASE` 和 `ALTER DATABASE ... OWNER` 语句,然后再加载:

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

如果恢复过程报告错误,请先保存输出内容并联系支持团队,再考虑从转储文件中进一步删减内容。删减过多可能会使数据库处于不一致的状态,而这种状态比原始错误更难诊断。

## 第 5 步:恢复媒体文件

将媒体归档中的内容放置到 Pro 部署读取上传文件的位置。应用程序会在 `/app/media` 中查找这些文件,而该路径由您部署环境中的绑定挂载或持久卷提供支持。请查阅随许可证提供的安装文档,了解您的部署所使用的主机路径或卷。

对于以命名卷为支撑的 Docker Compose 部署:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

对于 Kubernetes 部署,请先在本地解压归档文件,然后将其复制到 Django Pod 中,该 Pod 会写入挂载于 `/app/media` 的持久卷声明:

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## 第 6 步:让 DefectDojo Pro 指向恢复后的数据库

更新数据库连接,使 Pro 使用您刚刚恢复的数据库,然后启动应用程序。首次启动时,Pro 会运行数据库迁移,将架构从您的开源版本升级到 Pro 版本。根据数据库大小和版本差距的大小,这可能需要一段时间,在迁移完成之前应用程序将不可用。

对于 Docker Compose 部署,请在部署配置中设置数据库 URL,然后重启整个技术栈。具体的配置键和命令取决于您所获得的 `dojo-compose-cli` 版本,因此请遵循随许可证提供的安装文档。连接字符串的格式如下:

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

对于 Kubernetes 部署,请在 Helm values 中设置数据库 URL,然后重新部署:

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

您的部署可使用哪些 Pro 功能取决于您的许可证以及部署方式,因为其中部分功能并不适用于自托管安装。DefectDojo 会在迁移过程中确认适用于您的功能集合。

## 第 7 步:验证数据

应用程序针对恢复后的数据库运行起来之后:

1. 登录您的 DefectDojo Pro 部署。
2. 检查您的资产(Assets)、组织(Organizations)、测试活动、测试和发现项是否均已存在。资产和组织在开源版本中分别称为产品(Products)和产品类型(Product Types)。
3. 从 UI 中下载一个具有代表性的已上传文件,例如某个发现项、测试或测试活动的附件,以确认媒体文件恢复成功。
4. 检查用户账户和组是否完整。SSO 及其他身份验证设置通常需要针对新部署重新配置。
5. 如发现任何差异,请报告给您的 DefectDojo 联系人。

## 规划切换

转储文件是某一时刻的快照,因此在导出之后在开源实例中创建的任何内容都不会出现在 Pro 部署中。为避免数据丢失,请在进行最终转储和切换时冻结开源实例,或在业务低峰期进行迁移。

进行一次演练是值得的。先迁移一份近期的副本并验证,然后再针对正式切换重复该流程。第二次运行速度会更快,并且能让您了解第 6 步中的架构迁移大致需要多长时间。

## 迁移检查清单

- 已确认数据库引擎、数据库位置和开源版本
- 开源版本已与目标 Pro 版本对齐
- 已配置目标 PostgreSQL,并可从安装了 PostgreSQL 客户端工具的恢复主机访问
- 已导出数据库,尽可能使用自定义格式转储
- 已定位并压缩媒体目录
- 两个文件均已按开源版本命名
- 已在目标环境中创建数据库和应用角色
- 已恢复转储文件,并检查恢复输出中是否存在错误
- 已将媒体文件恢复到部署所使用的路径或卷中
- Pro 已指向恢复后的数据库并启动,架构迁移已完成
- 已在新部署中验证数据

## 问题或支持

DefectDojo 全程为此次迁移提供支持。如需在任何步骤获得帮助,请联系您的客户代表或 [support@defectdojo.com](mailto:support@defectdojo.com)。
