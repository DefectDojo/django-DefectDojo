---
title: 备份自托管部署
description: 需要备份的四项内容、它们在 Compose 和 Kubernetes 部署中各自的位置，以及如何确认备份确实可以恢复
draft: false
weight: 12
audience: pro
---

一个部署所包含的内容不仅仅是其数据库。如果备份只涵盖数据库，恢复后得到的系统虽然能够运行，却会缺少已上传的文件，并且无法解密其中保存的、用于连接其他工具的凭证。本页将介绍需要备份哪些内容、每部分内容分别位于何处，以及如何确认恢复结果是可用的。

## The four things to capture

数据库中保存着您的组织、资产、测试活动（Engagements）、测试（Tests）、发现项（Findings）、用户以及各项配置。

已上传的文件保存在数据库之外。屏幕截图、威胁模型、风险接受（Risk Acceptance）文档等附件存储在文件系统中，数据库中只保存指向它们的路径。

部署配置决定了应用程序能否以相同方式重新启动，其中包括您自己的定制内容和 TLS 证书。

加密密钥是最容易被遗漏的一项内容。凭证加密密钥（credential encryption key）决定了您所连接工具的已存储凭证是否可读。如果在恢复数据库时缺少该密钥，这些凭证虽然完好无损，但无法解密，这意味着每一项集成都必须手动重新录入。

## The database

大多数自托管部署都会指向一个托管型 PostgreSQL 服务，这也是 chart 的默认设置和推荐配置。在这种情况下，应使用服务提供方自带的自动备份和时间点恢复（point-in-time recovery）功能，而不是自行搭建备份方案。有两点值得实际核查，而不是想当然地假定：一是该实例是否确实已启用自动备份，因为如果托管数据库关闭了备份功能，就完全没有备份；二是备份保留期限是否符合您所在组织的要求。

如果您自行运行 PostgreSQL，请生成一份压缩的自定义格式转储（dump）：

```bash
pg_dump -h <db_host> -U <db_user> -Fc <db_name> > defectdojo-$(date +%F).dump
```

使用 `pg_restore` 进行恢复；如果目标环境的角色（roles）与源环境不同，请加上 `--no-owner` 和 `--no-privileges` 参数：

```bash
pg_restore -v --no-owner --no-privileges -h <db_host> -U <db_user> -d <db_name> defectdojo-<date>.dump
```

请按计划定期生成转储文件，将其存储在生成该文件的机器之外，并保留足够多个历史版本，以应对未能及时察觉的问题。

## Uploaded files

在 Docker Compose 部署中，已上传的文件位于主机上部署目录内的 `media` 目录中。请使用您常规的文件系统备份方式对该路径进行备份。如果您已将其迁移到独立的存储上，请对该文件系统本身进行备份，而不是仅备份挂载点。

在 Kubernetes 中，media 卷是根据您所配置的存储后端进行分配的，数据的实际物理存储位置决定了应采用何种方式对其进行保护：

| Storage backend | Where the data lives | How to protect it |
| --- | --- | --- |
| `efs` | Amazon EFS 文件系统 | AWS Backup |
| `filestore` | Google Filestore 实例 | Filestore 备份 |
| `gcsfuse` | Cloud Storage 存储桶 | 存储桶版本控制，或定期复制到另一个存储桶 |
| `nfs` | 您的 NFS 服务器 | 保护该服务器所采用的任何方式 |
| `pvc` | 来自您存储类（storage class）的卷 | 若您的驱动程序支持，可使用 CSI 卷快照 |

chart 负责分配该卷，但并不负责保护其中的内容。其中并未内置快照计划，因此备份必须来自平台本身或您自己的工具。

## Configuration and keys

在 Compose 中，请备份您的 `customizations` 目录、`certs` 目录，以及 CLI 所存储的配置和环境变量值。`config print` 和 `environment print` 命令可以显示当前所设置的内容。

在 Kubernetes 中，请备份您的 values 文件，以及您的 release 所引用的 secrets 内容。

无论哪种情况，都应将凭证加密密钥和 secret key 存放在持久且独立的位置，例如密钥管理器（secret manager）中，而不要与备份放在一起。任何同时掌握数据库和凭证密钥的人，都能够读取您所连接的每一项工具的凭证，因此两者不应一同保存或传输。

## What is not a backup

该 chart 会对其持久卷声明（persistent volume claims）添加注解，使其在执行 `helm uninstall` 时得以保留，这一行为默认处于开启状态。这只是针对意外卸载的一种防护措施，而不是备份。它对数据损坏、应用程序内部的删除操作，或是进展不顺利的升级都毫无帮助，因为在上述每一种情况下，卷本身都会保留下来，而损坏也同样存在于其中。

仅保留在与部署相同的账户或项目中的快照，同样也没有看上去那么可靠。凡是能够删除该部署的因素，通常也能够删除这些快照。

## Confirming a backup is restorable

一份从未有人真正恢复过的备份，终究只是一种假设。请将其恢复到一个临时测试环境中进行验证，而不是直接覆盖生产环境，并检查以下几点：

1. 登录系统，确认您的组织、资产、测试活动、测试和发现项的数量均符合预期。
2. 打开一个带有附件的发现项并下载该附件。这一步可以证明 media 内容的恢复是成功的，因为如果仅恢复了数据库，附件虽然会显示在列表中，却无法被实际提供下载。
3. 打开一个已配置的工具连接，确认其凭证完好无损。这一步可以证明您正确恢复了凭证加密密钥，也是最有可能发现问题的一项检查。
4. 确认用户和组均已正确迁移过来。诸如 SSO 之类的身份验证设置通常需要针对不同的环境重新配置，因此在这方面出现差异属于正常现象，不应视为恢复失败。

请按计划定期进行这项演练，而不是仅在需要时才去做。备份方案往往正是在事故发生时第一次尝试恢复才暴露出问题。

## Questions or support

如需帮助规划您部署环境的备份方案，或者恢复结果未能达到预期，请联系 [support@defectdojo.com](mailto:support@defectdojo.com)。
