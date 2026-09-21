---
title: 关于连接器
description: Pro UI 中上游连接器和下游连接器的统一入口
summary: ''
date: 2026-07-14 00:00:00+00:00
lastmod: 2026-07-14 00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：连接器是 DefectDojo Pro 专属功能。</span>

**连接器（Connectors）** 是 DefectDojo Pro UI 中的统一入口，用于管理 DefectDojo 与之通信的所有工具（无论数据流向哪个方向）。它合并了此前在不同位置分别配置的两项功能：

* **上游连接器（Upstream Connectors）**（原名 **API Connectors**）从您的扫描器和安全工具中拉取发现项和资产清单。
* **下游连接器（Downstream Connectors）**（原名 **Integrations**）将发现项推送到您的问题跟踪系统和工单系统。

如果将 DefectDojo 视为您安全数据的枢纽，那么上游连接器就是数据流入的方式，下游连接器则是修复工作流出的方式。

## 在哪里找到连接器

在 Pro UI 侧边栏中，展开 **Import（导入）** 分组下的 **Connectors（连接器）** 分组：

* **Connectors > Upstream Connectors（连接器 > 上游连接器）**——取代了原来的 **API Connectors** 条目（此前位于 Import 下）。
* **Connectors > Downstream Connectors（连接器 > 下游连接器）**——取代了原来的 **Integrations** 条目（此前位于 Settings 下）。该方向目前处于 **Beta** 阶段。

旧的书签和深层链接仍然有效：原有的 **API Connectors** 和 **Integrations** 网址会自动重定向到新的 **Upstream Connectors** 和 **Downstream Connectors** 页面。

## 谁可以看到哪些内容

* **上游连接器** 对全局角色为 Reader 或更高的用户可见。
* **下游连接器** 仅超级用户可见，目前针对云托管的 DefectDojo Pro 实例处于 **Beta** 阶段。

只要这两个页面中至少有一个对您可见，侧边栏中就会显示 **Connectors（连接器）** 分组。

## 连接器页面

两个方向共享同一套全新布局：

* 每个工具都以全宽 **磁贴（tile）** 的形式显示——左侧是徽标，中间是工具名称和简短描述，右侧是操作按钮。
* 每个部分都有一个 **搜索框**，可在您输入时按工具名称筛选磁贴。

在 **Upstream Connectors（上游连接器）** 页面上：

* **Configured Connectors（已配置的连接器）** 列出您已经设置好的连接器。每个磁贴都会显示运行状况摘要（健康状态、最近一次操作，以及记录总数/已映射数量），并提供一个 **Manage Configuration（管理配置）** 菜单，其中包含 **Manage Records & Operations（管理记录和操作）**、**Edit Configuration（编辑配置）** 和 **Delete Configuration（删除配置）** 操作。
* **Available Connectors（可用连接器）** 列出您尚未配置的受支持工具，每个工具都带有 **Add Configuration（添加配置）** 按钮。
* 页面顶部的筛选器可按连接器类型缩小两个部分的范围：**All（全部）**、**Asset（资产，或 Product，具体取决于您实例的术语设置）** 用于导入资产清单的连接器，以及 **Finding（发现项）** 用于导入漏洞数据的连接器。

在 **Downstream Connectors（下游连接器）** 页面上：

* **Available Integrations（可用集成）** 列出所有受支持的问题跟踪系统。已配置集成的磁贴会显示现有 Integration Instances（集成实例）的数量。

## 后续步骤

* 阅读[关于上游连接器](/connectors/upstream/about/)并[添加您的第一个上游连接器](/connectors/upstream/add_edit/)，开始自动导入发现项。
* 阅读[下游连接器指南](/connectors/downstream/about/)，将发现项推送到您的问题跟踪系统。
