---
title: 去重调优（开源版）
description: 在 DefectDojo 开源版中配置去重：算法、哈希字段、端点和服务
weight: 5
audience: opensource
aliases:
- /zh-hans/en/working_with_findings/finding_deduplication/deduplication_tuning_os
- /zh-hans/en/working_with_findings/finding_deduplication/deduplication_algorithms
---

DefectDojo 开源版使用配置文件和环境变量来调整去重设置。

另请参阅：[开源版配置](/get_started/open_source/configuration/)，了解环境变量和 `local_settings.py` 覆盖设置的详细信息。

## What you can configure

- **按解析器设置算法**：可选择工具唯一 ID、哈希代码、工具唯一 ID 或哈希代码，或传统算法（仅限开源版）中的一种。
- **按扫描器设置哈希字段**：决定每个解析器中哪些字段参与哈希计算。
- **允许空 CWE**：控制在哈希计算时是否接受缺失/为零的 CWE。
- **端点纳入考量**：当端点未包含在哈希中时，可选择将端点用于去重。
- **始终包含的字段**：无论每个扫描器的设置如何，都会将字段（例如 `service`）添加到所有哈希中。

## Key settings (defaults shown)

所有默认值均在 `dojo/settings/settings.dist.py` 中定义，可通过环境变量或 `local_settings.py` 进行覆盖。

### Algorithm per parser

- 设置项：`DEDUPLICATION_ALGORITHM_PER_PARSER`
- 每个解析器的取值：`unique_id_from_tool`、`hash_code`、`unique_id_from_tool_or_hash_code`、`legacy` 之一。
- 示例（环境变量 JSON 字符串）：

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### Hash fields per scanner

- 设置项：`HASHCODE_FIELDS_PER_SCANNER`
- 开源版中 Trivy 的默认值示例：

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- 覆盖示例（环境变量 JSON 字符串）：

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### Allow null CWE per scanner

- 设置项：`HASHCODE_ALLOWS_NULL_CWE`
- 按解析器控制哈希计算中是否接受空/为零的 CWE。如果设为 False 且发现项的 `cwe = 0`，则该发现项的哈希将回退为传统计算方式。

### Always-included fields in hash

- 设置项：`HASH_CODE_FIELDS_ALWAYS`
- 默认值：`["service"]`
- 影响：会附加到每个扫描器的哈希中。从此处移除 `service` 会使其不再对整体哈希产生影响。

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### Optional endpoint-based dedupe

- 设置项：`DEDUPE_ALGO_ENDPOINT_FIELDS`
- 默认值：`["host", "path"]`
- 用途：如果端点未包含在哈希字段中，您仍可以要求最低限度的端点匹配来进行去重。如果列表为空 `[]`，则去重过程中会忽略端点。

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## Endpoints: how to tune

端点可以通过两种机制影响去重：

1) 在某个解析器的 `HASHCODE_FIELDS_PER_SCANNER` 中包含 `endpoints`。这样端点就会成为哈希的一部分，并且必须根据该解析器的哈希规则完全匹配。
2) 如果端点不在哈希字段中，可以使用 `DEDUPLE_ALGO_ENDPOINT_FIELDS` 来指定要比较的属性。示例：
   - `[]`：去重时忽略端点。
   - `["host"]`：如果任意一对端点在 host 上匹配，则发现项去重。
   - `["host", "port"]`：如果任意一对端点同时在 host 和 port 上匹配，则发现项去重。

说明：

- 对于传统算法，静态发现项与动态发现项具有不同的端点匹配规则（参见算法页面）。`DEDUPLE_ALGO_ENDPOINT_FIELDS` 设置适用于哈希代码路径，而非传统算法自身的固有逻辑。
- 对于基于 `unique_id_from_tool`（基于 ID）的匹配，端点不参与去重决定。

## Service field: dedupe and reimport

- 在默认设置 `HASH_CODE_FIELDS_ALWAYS = ["service"]` 下，`service` 字段会附加到哈希中。两个原本相同但 `service` 值不同的发现项，在基于哈希的路径上不会被去重。
- 通过界面/API 导入时，`Service` 输入字段可以覆盖解析器提供的服务值。更改此值会改变哈希，并可能影响去重行为和重新导入匹配。
- 如果希望去重不受 service 影响，请从 `HASH_CODE_FIELDS_ALWAYS` 中移除 `service`，或在导入时将 `Service` 字段留空。

## After changing deduplication settings

更改算法或哈希计算方式后，您需要为受影响的解析器/测试类型**重新计算哈希**，新的匹配行为才会在现有数据中一致地生效。

注意：在大型实例上重新计算哈希可能会导致较长的等待时间。请相应地规划维护窗口。

- 对去重配置的更改（例如 `HASHCODE_FIELDS_PER_SCANNER`、`HASH_CODE_FIELDS_ALWAYS`、`DEDUPLICATION_ALGORITHM_PER_PARSER`）不会自动追溯应用。要重新评估现有发现项，您必须运行下方的管理命令。

### Running dedup on a backlog of pre-existing data

当您首次配置去重设置（或之后更改设置）时，在更改之前导入的发现项会保留其旧哈希，直到您显式重新运行去重为止。使用 `dedupe` 管理命令可以重新计算哈希和/或重新评估现有发现项。

在 uwsgi 容器内运行。示例（仅计算哈希代码，不进行去重）：

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

要为所有解析器**重新计算哈希并运行去重**（典型的“刚启用去重、想要清理存量数据”场景）：

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe"
```

仅针对特定解析器：

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --parser 'Trivy Scan'"
```

帮助/用法：
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

如果您将去重任务提交给 Celery（未使用 `--dedupe_sync`），请留出时间让任务完成后再评估结果。在大型实例上，这可能需要相当长的时间——请监控 Celery 工作进程日志以跟踪进度。

## Where to configure

- 在部署环境中，优先使用环境变量。对于本地开发或高级覆盖设置，请使用 `local_settings.py`。
- 有关如何设置环境变量和配置本地覆盖设置的详细信息，请参阅 `configuration.md`。

### Troubleshooting

为帮助排查去重问题，可使用以下工具：

- 查看 `dojo.specific-loggers.deduplication` 类别下的日志输出。这是一个独立于类的日志记录器，会在处理发现项时输出有关去重流程和设置的详细信息。
- 将鼠标悬停在 `ID` 字段或 `Status` 列上，即可查看 `unique_id_from_tool` 和 `hash_code` 的值：

![查看发现项页面上的工具唯一 ID 和哈希代码](images/hash_code_id_field.png)

![发现项列表状态列上的工具唯一 ID 和哈希代码](images/hash_code_status_column.png)
