---
title: 位置概览
description: 位置是什么,以及它们为何取代端点
audience: pro
weight: 1
---

**位置(Locations)** 是 DefectDojo Pro 中一项全新的资产建模工具。它们取代了旧有的 **端点(Endpoints)** 模型,并吸收了此前的 **组件(Components)**(库)数据,使 DefectDojo 拥有了一种统一的多态方式来描述发现项 *位于何处* ——无论是一个 URL、来自 **SBOM** 的软件依赖项,还是未来可能支持的 **云资源 ID**、**容器镜像** 或 **代码仓库**。

在使用位置功能之前,必须先在您的实例上启用它。您可以自行通过[功能开关页面](/admin/feature_flags/pro__feature_flags/)启用位置功能——无需提交支持请求。请注意,位置功能一旦启用,便无法再关闭。

## 为什么要取代端点?

最初的端点模型是围绕 URL 和 IP 地址构建的——它包含 `protocol`、`host`、`port`、`path` 等 Web 应用字段,以及一个与发现项紧密耦合的固定状态表。由此产生了三个问题:

1. **保真度有限。** 端点无法清晰地描述非 URL 类资产,例如第三方库、容器镜像或云资源,即便扫描器越来越多地针对这些内容生成发现项。
2. **性能上限。** 每个发现项对应的 Endpoint_Status 行,以及 URL 形态的模式设计,在大型客户体量下的扩展性不佳。
3. **组件处于次等地位。** 软件库仅作为发现项上的非规范化字段存在,因此一个库无法独立于漏洞而存在——这使得真正的 SBOM 管理无法实现。

位置功能通过引入一个带有类型化载荷的 **基础 `Location` 对象**,以及针对每种资产形态的专用 **子类型**,解决了这三个问题:

- **URL 位置** — 在功能上等同于旧有的端点,拥有相同的 protocol/host/port/path/query/fragment 字段。
- **依赖项位置** — 由 [Package URL(pURL)](https://github.com/package-url/purl-spec) 标识的软件库,用于建模 SBOM 内容。
- **[源代码位置](/asset_modelling/locations/pro__source_code_locations/)** — 静态分析发现项在源代码中的所在位置,通过文件路径和行号标识。由扫描管理,并作为[随代码变动跟踪发现项](/triage_findings/finding_deduplication/pro__location_drift_matching/)的基础。

正在考虑中的未来位置类型包括云提供商资源 ID(AWS ARN、Azure 资源 ID、GCP 完整资源名称)和容器镜像(registry/repository:tag 及 SHA256 指纹)。

## 关键概念

### 位置与子类型

**位置(Location)** 是共享的父对象,它包含:

- 一个 `Location Type`(例如 `"url"`、`"dependency"`)
- 一个用于显示、搜索和去重的规范化 `Location Value` 字符串
- `Tags`,以及从父资产继承的标签
- 元数据(自定义键/值对)

**子类型**(URL 或依赖项)保存该类位置特有的结构化字段。URL 和依赖项始终与一个父位置对象共存;子类型的 `Location Value` 是根据其结构化字段生成的。

### 引用

位置不会直接关联到产品或发现项,而是通过两种 **引用(Reference)** 对象进行关联:

- **资产引用(Asset References)** — 位置与资产之间的关系(例如,`libFoo` *归属于(owned by)* 资产 6,*被使用于(used by)* 资产 9)。每个引用都带有一个状态(`Active` 或 `Mitigated`),以及一个可选的 **关系(relationship)**(“Used By” 或 “Owned By”)。
- **发现项引用(Finding References)** — 位置与发现项之间的关系。每个引用都带有更丰富的状态(`Active`、`Mitigated`、`False Positive`、`Risk Accepted`、`Out of Scope`),以及审核人和审核时间。

正是这种分离,使得一个库可以存在于某个产品上而 *无需* 依赖发现项——这是旧有组件模型所缺失的能力。

### 导入时的自动关联

当解析器生成一个引用了 URL 或库的发现项时,导入程序会:

1. 查找与该 URL 或 pURL 匹配的现有位置;如果不存在,则创建一个新位置。
2. 创建一个发现项引用,将该发现项与位置以 `Active` 状态关联。
3. 创建(或复用)一个资产引用,使该位置也存在于父资产上。

现有的解析器已经过更新,在功能开关开启时会生成位置数据,在功能开关关闭时则会回退到旧有的端点模型。启用位置功能后无需进行任何重新配置——下一次导入将自动经由位置处理流程进行路由。

## MVP 中包含的内容

| Capability | Status |
| --- | --- |
| 基础 `Location`、`URL`、`Dependency` 模型 | 已发布 |
| 面向位置和引用的 REST API | 已发布(`Location` 只读,引用支持完整 CRUD) |
| 端点 API 只读兼容层 | 已发布 |
| 端点 → URL 单向迁移命令 | 已发布 |
| 解析器更新(URL 和依赖项) | 已针对主要解析器发布 |
| SBOM 上传(CycloneDX、SPDX v2/v3) | 已通过 `/api/v2/sbom-import/` 发布 |
| 面向位置、URL、依赖项的 Pro 界面 | 已发布 |
| pURL 搜索/筛选 | 已发布 |
| 依赖项许可证跟踪 | 部分支持(`license_expression` 字段) |
| SWID Tag SBOM 格式 | 未纳入 MVP |

## 后续步骤

- **启用该功能** — 联系 [support@defectdojo.com](mailto:support@defectdojo.com) 为您的实例开启位置功能。
- **从端点迁移** — 请参阅[从端点迁移](../pro__migrating_from_endpoints),了解迁移会保留哪些内容,以及迁移后旧有端点 API 的行为方式。
- **日常 URL 工作流程** — 请参阅[使用 URL](../pro__working_with_urls)。
- **SBOM 与依赖项** — 请参阅[使用 SBOM](../pro__working_with_sboms)。
