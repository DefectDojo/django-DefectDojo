---
title: 使用 SBOM
description: 以位置的形式管理软件依赖项和 SBOM
audience: pro
weight: 5
---

DefectDojo Pro 将软件库建模为**依赖位置**。依赖项是一种位置子类型，通过[软件包 URL（pURL）](https://github.com/package-url/purl-spec)进行标识，用于表示单个库或软件包——例如 `org.apache.logging.log4j:log4j-core@2.17.0`、`pypi/django@5.0.2`、`npm/react@18.2.0` 等。

依赖项取代了此前仅能附加在发现项上的**组件**模型。借助位置功能，库可以独立于任何漏洞而存在——您可以向某个资产上传 SBOM，随后在扫描结果不断导入时，让发现项自动关联到它们所引用的依赖项。

## 依赖项包含哪些内容

每个依赖项都由一个 pURL 唯一标识，并分解为若干可供搜索和筛选的原子字段：

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `purl_type` | 库生态系统 | `npm`、`pypi`、`maven`、`cargo`、`nuget`、`gem` |
| `namespace` | 供应商或组织 | `org.apache.logging` |
| `name` | 库名称 | `log4j-core` |
| `version` | 具体版本 | `2.17.0` |
| `qualifiers` *(可选)* | 实现细节 | `arch=amd64` |
| `subpath` *(可选)* | 归档文件或 monorepo 内的路径 | `src/lib/foo` |
| `artifact_hashes` *(可选)* | 指纹 | SHA256 校验和 |
| `license_expression` *(可选)* | SPDX 许可证表达式 | `Apache-2.0`、`MIT` |
| `file_path` *(可选)* | 在项目中发现该库的位置 | `package-lock.json` |

正是这种原子化的拆分，使得基于 pURL 的搜索变得实用：您可以询问*“`django` 命名空间下所有版本为 4.x 的 `pypi` 软件包”*，DefectDojo 无需解析自由文本字符串即可给出答案。

## 归属方（Owned-By）与使用方（Used-By）

当某个依赖项与某个资产关联时，资产引用会携带一个可选的**关系**字段，用于描述该库*以何种方式*归属于该资产：

- **`owned_by`** —— *“该库归属于此资产”*。适用于某资产发布或维护的自有库。
- **`used_by`** —— *“该库被此资产使用”*。适用于某资产所使用的第三方依赖项。

同一个库可以对一个资产是 `owned_by`，同时对其他多个资产是 `used_by`，这正是在漏洞分诊过程中回答*“谁在使用我们团队发布的软件包？”*所需要的关系。

## 上传 SBOM

要批量填充依赖项，请针对某个产品上传 SBOM 文件。该端点为：

```
POST /api/v2/sbom-import/
```

| 字段 | 说明 |
| --- | --- |
| `product` | 目标产品（资产）ID |
| `file` | SBOM 文件 |
| `scan_type` | SBOM 格式——见下方支持的格式 |
| `replace` *(可选)* | 若为 `true`，则会移除没有现有发现项引用支撑的过期产品关联。默认值：`false`（累加模式） |

导入器会解析该文件、提取 `Dependency` 记录、将其与现有位置进行去重（按需创建新记录），并创建资产引用，将每个依赖项关联到该产品。Pro 版界面提供了相同的上传流程——参见产品位置标签页中的**上传 SBOM**操作。

### 支持的格式

该 MVP 版本提供了针对两种主流 SBOM 格式的解析器：

- **CycloneDX** —— JSON 和 XML
- **SPDX** —— JSON（v2 和 v3）、XML 和 tag-value

目前尚不支持 SWID Tag 格式。

### 替换与追加

默认情况下，重复上传是**累加式**的：资产上已存在的依赖项会被保留，新的依赖项会被添加，不会移除任何内容。这与典型的增量 SBOM 更新流程相符。

将 `replace` 设置为 `true` 可进行清理。启用替换模式后，导入成功后，导入器会移除新 SBOM 中不存在**且**当前未被任何活动发现项引用的产品关联。即使在替换模式下，与活动发现项相关联的引用也会被保留，因此不会因为新的 SBOM 遗漏了某个软件包而丢失漏洞上下文。

## 引用库的发现项

当解析器摄取与某个库相关联的漏洞时——例如某个 SCA 工具针对 `log4j-core@2.14.1` 报告了 `CVE-2021-44228`——导入器会：

1. 按 pURL 查找现有的依赖位置，若不存在则创建一个新的。
2. 创建一个 `LocationFindingReference`，将该发现项与该依赖项关联，状态为**活动**。
3. 创建一个 `LocationProductReference`，使该依赖项也出现在其所属的父级产品下（如果尚未出现）。

由于发现项和 SBOM 上传共用同一套底层依赖项对象，*先于* SBOM 上传而摄取的发现项会追溯性地出现在 SBOM 视图中，反之亦然。

## REST API

| 任务 | 端点 |
| --- | --- |
| 上传 SBOM | `POST /api/v2/sbom-import/` |
| 列出依赖项 | `GET /api/v2/dependencies/` |
| 手动创建依赖项 | `POST /api/v2/dependencies/` |
| 列出依赖位置 | `GET /api/v2/location/?location_type=dependency` |
| 将依赖项关联到发现项 | `POST /api/v2/location_findings/` |
| 将依赖项关联到产品（使用 `owned_by` / `used_by`） | `POST /api/v2/location_products/` |

`/api/v2/dependencies/` 上的筛选条件包括 pURL 的各组成字段、标签，以及按 `name`、`version` 和活动发现项数量进行排序。

## 在 Pro 版界面中

启用位置功能后，导航栏会提供以下选项：

- **位置 / 依赖项** —— 该实例中所有依赖项的全局列表，支持 pURL 筛选。
- **产品/资产上的位置** —— 按资产划分的视图，同时显示 URL 和依赖项，**上传 SBOM** 操作显示在依赖项标签页上。
- **新建依赖项** —— 通过手动输入 pURL 各组成部分来创建单个库的表单。
- **发现项详情** —— 涉及某个库的发现项会将其依赖位置与任何 URL 位置一并显示，因此您可以在同一个地方看到“该 CVE 影响资产 6 和资产 9 上的 `log4j-core@2.14.1`”。

## MVP 中尚未包含的内容

- **SWID Tag SBOM 格式** —— 尚未支持解析，需使用 CycloneDX 或 SPDX。
- **许可证风险评分** —— 当 SBOM 中存在 `license_expression` 字段时会被采集，但 DefectDojo 尚不会针对许可证不兼容标记发现项。基于许可证的报告功能已列入路线图，作为位置 MVP 的后续功能。
- **容器镜像与云资源位置** —— 属于未来的位置子类型。目前，在容器镜像中发现的库会被记录为依赖项；容器镜像本身尚未成为一等公民的位置类型。
