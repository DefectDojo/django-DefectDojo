---
title: 菜单徽章
description: DefectDojo Pro 侧边栏中 BETA、NEW、LEGACY 和 DEPRECATED 标签的含义,以及每种标签要求您采取的行动
weight: 7
audience: pro
---

DefectDojo Pro 侧边栏中的条目可能带有一个彩色小标签。每种标签都回答了关于其旁边功能的不同问题,其中两种标签是可点击的链接。

| Badge | Colour | Means | What it asks of you |
| --- | --- | --- | --- |
| `NEW` | 绿色 | 近期发布 | 无需操作——它的作用只是让您注意到该功能 |
| `BETA` | 橙色 | 功能可用,但仍在完善中;行为可能在版本之间发生变化 | 尝试使用,并预期会有一些粗糙之处 |
| `LEGACY` | 红色 | 已被更新的功能取代,尚未宣布移除日期 | 新工作请优先使用替代功能 |
| `DEPRECATED` | 红色 | 计划在指定版本中移除 | 请在该版本发布前完成迁移 |

![Jira 菜单条目上的 LEGACY 徽章](images/menu_badge_legacy.png)

## LEGACY 和 DEPRECATED 并不是一回事

这种区分是刻意为之的,因为这两种状态需要不同的应对方式。

**`DEPRECATED`** 表示已宣布该功能将被移除。将鼠标悬停在徽章上会显示其移除的版本,点击徽章则会打开弃用通知:

> \<Feature\> is deprecated and will be removed by \<release\>. Click for the deprecation notice.

**`LEGACY`** 表示该功能已被取代,但尚未安排移除计划。悬停文字中刻意不包含日期,因为编造一个日期比什么都不说更糟糕。取而代之的是,它会指明替代功能并链接到其文档:

> \<Feature\> is superseded by \<replacement\> and will not receive new development. Click for its documentation.

标记为 `LEGACY` 的功能会继续正常运行并持续获得修复,只是不会再获得新能力,因此您现在构建的任何内容最好基于替代功能来实现。

这两种徽章都是链接,因为工具提示会在指针移开的瞬间关闭,因此无法承载可点击的链接。点击任一徽章都会在新标签页中打开其通知,而不会导航到下方的菜单条目。

## 当前带有徽章的功能

**`LEGACY`**

* **Connect > Jira** —— 原始的按产品配置的 Jira 集成,已被 Jira 下游连接器取代。参见 [Pro Integrations](/connectors/downstream/about/)。

**`DEPRECATED`**

* **Settings > Configuration > Tool Types**
* **Settings > Configuration > Tool Configurations**

这两者将在 **3.5.0** 中一并移除,与之相关的、用于配置基于 API 的(拉取式)解析器也将一同移除。[3.2 升级说明](/releases/os_upgrading/3.2/)解释了应迁移到什么以及截止时间。

![Settings > Configuration 下的 DEPRECATED 徽章](images/menu_badge_deprecated.png)

当标签及其徽章在侧边栏中无法并排显示时,徽章会换行显示在标签下方,而不会被截断。

## 相关内容

* [3.2 升级说明](/releases/os_upgrading/3.2/) —— 当前的弃用项及其移除版本
* [功能开关](/admin/feature_flags/pro__feature_flags/) —— 开启或关闭可选功能,包括测试版功能
