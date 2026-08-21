---
title: 仪表板
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 1
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

仪表板是 DefectDojo 的首页——概览团队的工作表现，也是监控您所关注领域的启动面板。

## 开源版与 DefectDojo Pro 版对比

仪表板的工作方式取决于您运行的版本：

| | Open Source | DefectDojo Pro |
|---|---|---|
| **主页仪表板** | 所有用户共用一个固定的主仪表板 | 每位用户可**自定义**仪表板 |
| **选择显示内容** | 超级用户可开关一组固定的图表 | 每位用户可添加、配置和排列**小组件** |
| **多个命名仪表板** | 不支持 | 支持——可创建任意数量的**布局**并在其间切换 |
| **共享/克隆/设为默认** | — | 支持——可将布局发布给团队、克隆模板、设置默认布局 |
| **REST API + LLM 自动化** | — | 支持——可发现目录、创建布局、渲染小组件数据 |

简而言之：**开源版**为每位用户提供相同的内置主仪表板，包含一组固定的组件。**DefectDojo Pro** 允许每位用户使用小组件搭建自己的仪表板、进行共享，并可通过 UI、REST API 或 LLM 驱动整个系统。

## 后续步骤

**开源版**

- **[DefectDojo 主仪表板](introduction_dashboard/)**——内置首页：概览卡片、严重程度图表，以及超级用户如何配置它们。

**DefectDojo Pro**

- **[可自定义仪表板](custom-dashboards/)**——相关概念（布局、小组件、目录、共享）及完整的 UI 操作演示。
- **[通过 API 自动化仪表板](custom-dashboards-api/)**——通过 REST API 发现小组件目录、创建和更新布局、渲染小组件数据，并附有完整脚本。
- **[使用 LLM 构建仪表板](custom-dashboards-llm/)**——让 LLM 为您设计并构建仪表板。
