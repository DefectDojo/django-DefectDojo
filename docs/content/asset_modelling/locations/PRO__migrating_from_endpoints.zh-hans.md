---
title: 从端点迁移
description: 将现有端点数据迁移到位置时会发生什么
audience: pro
weight: 3
---

当您在现有的 DefectDojo Pro 实例上启用位置功能后，已存储为端点的数据需要迁移到新的位置模型中。本页介绍迁移过程、迁移会保留哪些内容，以及迁移完成后旧版端点 API 的行为方式。

请注意，迁移是**单向的**。目前没有自动化的回滚路径可以从位置反向重新创建端点。

## 迁移会执行哪些操作

对于每个现有端点，迁移会：

1. **创建一个 URL 位置**（或复用已有的），使用该端点的 `protocol`、`userinfo`、`host`、`port`、`path`、`query` 和 `fragment` 字段。新的 URL 会自动关联到一个父级 `Location` 对象。
2. **保留标签。** 端点上的每个标签都会添加到该位置的标签集合中。
3. **保留元数据。** 附加在端点上的每条 `DojoMeta` 记录都会重新指向新的位置。
4. **创建一个 `LocationProductReference`**，使该 URL 出现在正确的资产（产品）下。
5. **为每个 `Endpoint_Status` 创建一个 `LocationFindingReference`**：

   | Endpoint_Status 标志 | 生成的位置状态 |
   | --- | --- |
   | `risk_accepted=True` | **风险已接受** |
   | `false_positive=True` | **误报** |
   | `out_of_scope=True` | **超出范围** |
   | `mitigated=True` | **已缓解** |
   | （以上均不满足） | **活动** |

   该映射关系与顺序相关：*首个*匹配的标志将生效。这是有意为之的设计，用于将旧版的多标志组合归并为位置所使用的单一规范状态。


## 迁移不会执行哪些操作

- 迁移**不会**创建依赖位置。SBOM 和库数据从未以端点的形式存在过，因此迁移没有可转换的内容。要填充依赖项，请上传 SBOM（参见[使用 SBOM](../pro__working_with_sboms)），或使用能够输出依赖数据的解析器重新运行扫描。
- 迁移**不会**删除原始的端点或 Endpoint_Status 记录。这些记录会保留在数据库中，用于支撑只读的旧版 API。启用该功能后，新版界面和导入流程不会再使用这些记录。

## 迁移后的端点 API

启用位置功能后，旧版端点 API 会进入**只读兼容**模式，旨在让现有的自动化流程无需修改代码即可继续运行——但仅限于读取流量。

### 仍然可用的功能

- `GET /api/v2/endpoints/` — 返回的记录*看起来像*端点，但实际上是由 Location Product Reference 记录与 URL 位置连接映射而成的。熟悉的字段（`protocol`、`host`、`port`、`path`、`query`、`fragment`、`tags`、`product`、`active_finding_count`）都会保留。
- `GET /api/v2/endpoints/{id}/` — 单个端点的获取方式相同。`id` 为原始端点 ID，会通过资产引用映射在迁移过程中得以保留。
- `GET /api/v2/endpoint_status/` 和 `GET /api/v2/endpoint_status/{id}/` — 返回由 `LocationFindingReference` 映射而成的记录。旧版的 `mitigated`、`false_positive`、`out_of_scope` 和 `risk_accepted` 布尔字段会被重新构建。
- 按 `protocol`、`host`、`port`、`path`、`query`、`fragment`、`product` 和 `tag(s)` 进行筛选的功能仍可正常使用。
- 单个端点上的 `generate_report` 操作仍可正常使用。

### 会返回 403 的操作

- 对 `/api/v2/endpoints/` 和 `/api/v2/endpoint_status/` 执行 `POST`、`PUT`、`PATCH` 和 `DELETE` 操作，都会返回 `HTTP 403`，响应内容为：

  > Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled

  需要写入端点数据的客户端必须迁移到新的引用端点（`POST /api/v2/location_findings/`、`POST /api/v2/location_products/`）以及 URL 端点（`POST /api/v2/urls/`）。

### 需要注意的行为差异

以下几点与原始端点 API 的行为有所不同：

- **单一状态取代多个标志。** 位置在同一时刻只有一个状态。如果您的代码依赖于某个发现项在 Endpoint_Status 上*同时*为 `mitigated=True` *和* `false_positive=True`，这种情况将无法再表示——迁移会选取优先级最高的标志（顺序如上表所示）。
- **Endpoint_Status 上的 `endpoint` 字段。** 旧版的 `endpoint` 字段是通过查找匹配的资产引用重新构建的。在极少数情况下，如果发现项的资产与其位置的资产引用不再匹配，该字段可能为空。
- **分页与排序。** 只读兼容层上可用的排序字段为 `host`、`product`、`id` 和 `active_finding_count`。如果您的客户端按其他字段排序，请改用上述字段之一，或迁移到新的位置端点。

## 标签与元数据

应用于端点的标签会成为位置对象上的标签（而非 URL 子类型上的标签）。旧版 API 中基于标签的筛选功能仍可正常匹配。

迁移过程中，端点元数据会重新指向对应的位置。通过 `/api/v2/endpoint_meta/` 读取元数据的现有自动化流程应能继续正常工作；新的元数据应通过位置端点写入。
