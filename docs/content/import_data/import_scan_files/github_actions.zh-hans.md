---
title: 从 GitHub Actions 导入
description: 使用官方 DefectDojo Action 从 GitHub Actions 工作流导入扫描结果
weight: 3
---

官方 [DefectDojo Action](https://github.com/DefectDojo/defectdojo-action) 可在 GitHub Actions 工作流中将扫描报告导入 DefectDojo。它同时适用于 DefectDojo Pro 和开源版，并可读取 DefectDojo 支持的所有报告格式，包括 SARIF。

每次运行都会重新导入到同一个测试中，因此扫描器不再报告的发现项会被关闭，且每个发现项都会保留其历史记录。该 Action 会在测试上记录构建、分支、提交和仓库信息，并且当所选严重程度的发现项仍处于活动状态时，可以让工作流步骤失败。

## 开始之前

1. 为有权导入到该资产（如果您允许 Action 创建资产，则还需有权创建资产）的用户创建 API v2 密钥。该密钥位于用户菜单中的 **API v2 Token** 下（在开源版界面中为 **API v2 Key**）。
2. 在 GitHub 仓库中，将该密钥添加为名为 `DEFECTDOJO_API_TOKEN` 的 secret，位置为 **Settings > Secrets and variables > Actions**。

## 将 Action 添加到工作流

先运行您的扫描器，然后将其报告传递给该 Action：

```yaml
name: Security scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` 是 DefectDojo 所列出的报告格式名称，例如 `SARIF`、`Trivy Scan` 或 `Semgrep JSON Report`。所有名称请参阅[支持的工具](/supported_tools/)。

## 发现项的去向

除非您自行设置，否则该 Action 会使用来自仓库的名称，并创建尚不存在的对象：

| DefectDojo 对象 | 默认值 | 输入项 |
| --- | --- | --- |
| 组织（产品类型） | 仓库所有者 | `organization-name` 或 `product-type-name` |
| 资产（产品） | 仓库名称 | `asset-name` 或 `product-name` |
| Engagement | 分支名称 | `engagement-name` |
| 测试 | 扫描类型 | `test-title` |

当同一个 Engagement 收到多份相同扫描类型的报告时，请为每份报告指定各自的 `test-title`，以便每次重新导入都能找到对应的测试。

### 分支、拉取请求和标签

每个分支都有各自的 Engagement，因此拉取请求的扫描永远不会关闭或重新打开默认分支上的发现项。拉取请求使用其源分支，标签使用标签名称，合并队列则为每个基础分支使用一个 Engagement。

该 Action 为默认分支以外的任何内容创建的 Engagement 只在其自身范围内去重（**仅在此测试活动内去重**）。否则，在某个分支上首次出现的发现项会把默认分支上的对应发现项标记为重复项。如果您自行设置 `engagement-name` 或 `deduplication-on-engagement`，此行为将被关闭，因此您命名的 Engagement 会像往常一样在整个资产范围内去重。分支 Engagement 在分支合并后仍会保留在 DefectDojo 中，因此，如果您希望它们不计入资产的统计数据，请仅在默认分支上运行导入。

## 让构建失败

将 `fail-on` 设置为 `low`、`medium`、`high` 或 `critical`，当导入之后测试中存在该严重程度或更高严重程度的活动发现项时，该步骤即会失败。重复项不计入。作业摘要会显示按严重程度统计的数量以及指向该测试的链接。

## Pro 功能

在 DefectDojo Pro 上，该 Action 还可以：

- 将新的发现项推送到为该资产设置的连接器（`push-to-connector: true`）。
- 在后台导入大型报告（`background-import: true`）。该 Action 会等到测试处理完成后，才报告数量或应用 `fail-on`。
- 在资产被重命名或移动时发出警告，以便您更新工作流中的名称。

在开源版上，`push-to-connector` 和 `background-import` 会被跳过并给出警告，导入仍会照常运行。设置 `strict: true` 则会让该步骤失败。

## 来自复刻仓库的拉取请求

GitHub 不会向由复刻仓库发起的拉取请求所触发的工作流提供 secret，因此该 Action 无法在此类情况下完成身份验证，步骤会失败。请在 `push` 时运行导入，或对来自复刻仓库的拉取请求跳过该步骤：

```yaml
      - name: Import into DefectDojo
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: DefectDojo/defectdojo-action@v1
```

请勿使用 `pull_request_target` 来绕过此限制：它会在检出您无法控制的代码的同时使用您的 secret 运行。

## 所有输入项和输出项

[该 Action 的 README](https://github.com/DefectDojo/defectdojo-action#inputs) 列出了所有输入项和输出项。大多数输入项与 **/reimport** 端点的字段一一对应，该端点在[通过 API 导入](/import_data/import_scan_files/api_pipeline_modelling/)中有详细说明。
