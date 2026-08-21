---
title: 报告构建器
description: 性能指标与洞察
summary: ''
date: 2026-01-20 17:33:00+00:00
lastmod: 2026-01-20 17:33:00+00:00
draft: false
weight: 2
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

报告构建器可以让您将 DefectDojo 数据转化为精美、可分享的报告——包括执行摘要、合规快照、POA&M 文档包、工程详情等——面向安全团队内外的各类受众。

## 开源版与 DefectDojo Pro 版对比

报告的构建方式取决于您使用的版本：

| | 开源版 | DefectDojo Pro |
|---|---|---|
| **构建报告** | 支持——通过小组件组装 | 支持——通过可复用的内容块组合 |
| **运行并获取输出** | 支持（HTML、打印为 PDF） | 支持（保存为 PDF 或 HTML） |
| **保存可复用的主题/内容块/模板** | 不支持——每次都需重新构建 | 支持 |
| **保留已生成报告的历史记录** | 不支持 | 支持——可列出、下载、重新运行 |
| **REST API + LLM 自动化** | — | 支持——完整的创建 → 运行 → 下载流程 |

简而言之：**开源版** 让您可以构建报告、运行报告并导出结果，但不会保存模板或保留报告历史记录。**DefectDojo Pro** 则将报告功能变成可复用、可定制品牌的构建模块，您可以通过界面、REST API 或 LLM 来驱动。

## 后续参考

**DefectDojo Pro**

- **[报告构建器](report-builder/)** — 核心概念（主题、内容块、模板、生成的报告）及完整的界面操作演示。
- **[通过 API 自动化报告](report-builder-api/)** — 通过 REST API 创建、运行、轮询并下载报告，附完整脚本示例。
- **[使用 LLM 构建报告](report-builder-llm/)** — 让 LLM 为您设计、创建、运行并下载报告。

**开源版**

- **[使用报告构建器](using-the-report-builder/)** — 使用基于小组件的构建器来构建、运行并导出报告。
