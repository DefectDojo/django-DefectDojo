---
title: 升级 DefectDojo Pro(本地部署)
description: 使用 Helm chart 的自托管 DefectDojo Pro 部署所支持的升级流程
draft: false
weight: 7
audience: pro
---

本页介绍使用 DefectDojo Pro Helm chart 的自托管 DefectDojo Pro 部署所支持的升级流程。

## 将所有内容作为一个整体升级

每个 DefectDojo Pro 发行版都由 Helm chart 版本、容器镜像版本以及 Pro 设置文件组成。这些内容是一起构建和测试的,因此必须作为一个整体一起升级。

仅升级镜像标签是不受支持的,这样做会破坏您的部署。

## 设置文件与升级

DefectDojo Pro 的每个发行版都会附带一个 `pro_settings.py` 文件,并且该文件几乎每个版本都会发生变化。请不要在升级时沿用旧版本的 `pro_settings.py` 副本,也不要手动修补旧版本的副本。应用程序必须始终运行与其版本相匹配的 `pro_settings.py`。

请将您自己的自定义设置放在 `local_settings.py` 中,切勿放在 `pro_settings.py` 中。您的 `local_settings.py` 会在升级过程中保留下来。

Helm chart 会自动附带并挂载与之匹配的 `pro_settings.py` 以及您的 `local_settings.py`。使用该 chart 进行升级时,无需手动复制或迁移任何内容。

## 受支持的升级流程

1. 查看从当前版本到目标版本之间每个版本的发行说明,而不仅仅是目标版本的说明。请参阅 [DefectDojo Pro 更新日志](/releases/pro/changelog/)以及各版本对应的[升级说明](/releases/os_upgrading/upgrading_guide/)。
2. 备份您的数据库。
3. 升级到与目标应用版本相匹配的 Helm chart 发行版,并复用您现有的 values 文件。请勿脱离 chart 版本单独更改镜像标签。

如果您对本地部署的升级有任何疑问,请联系 [support@defectdojo.com](mailto:support@defectdojo.com)。
