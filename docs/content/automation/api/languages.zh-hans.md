---
title: 语言与代码行数
description: 使用 cloc 工具导入产品的语言组成数据
weight: 3
audience: opensource
aliases:
- /zh-hans/en/open_source/languages
---

DefectDojo 可以显示某个产品的编程语言构成和代码行数明细，这些数据通过 API 导入 [cloc](https://github.com/AlDanial/cloc)（Count Lines of Code）工具生成的报告来填充。

## Generating the cloc Report

对您的代码库运行 `cloc`，并使用 `--json` 标志以生成格式正确的 JSON 文件：

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Importing via the API

通过 API 将该 JSON 报告上传到 DefectDojo。导入时，该产品现有的所有语言数据都会被新文件的内容替换。

该导入端点的文档参见 [DefectDojo API v2 文档](../api-v2-docs/)。

## Viewing Results

导入完成后，语言构成明细会显示在产品详情页面的左侧，展示每种语言及其代码行数。每种语言的颜色由 `Language_Type` 表中的条目定义，该表预先填充了来自 GitHub 的数据。

## Updating Language Colors

随着新语言的出现，GitHub 会定期更新语言颜色。要拉取最新的颜色数据，请运行以下管理命令：

```bash
./manage.py import_github_languages
```

该命令会从 [ozh/github-colors](https://github.com/ozh/github-colors) 读取数据，并添加新语言或更新现有颜色。
