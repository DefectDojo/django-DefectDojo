---
title: 设置菜单
description: DefectDojo Pro 侧边栏中设置部分的组织方式、“所有设置”目录页面,以及如何在当前布局和先前布局之间切换
weight: 6
audience: pro
---

侧边栏中的设置部分汇集了 DefectDojo Pro 中的所有管理页面。您看到的布局取决于您的实例创建时间:

- **新安装的实例**默认使用下文所述的重新组织后的布局。
- **现有实例**将保留先前的布局,直到管理员启用 **Menu 2.0**(参见[切换布局](#switching-layouts))。

无论哪种情况,**每个设置页面的 URL 都保持不变**。无论当前使用哪种布局,书签、已保存的链接以及您自己运行手册中的任何内容都能继续正常使用。

## 重新组织后的布局

设置被划分为七个分组,分组名称依据您想要完成的任务命名,而不是依据所涉及的系统部分命名。

| Group | What it holds |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, E-mail, Feature Flags |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | 三个去重页面(Deduplication)、Finding Enrichment、Service Level Agreements、Prioritization Engines、Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status,以及在 DefectDojo Cloud 上还包括 Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

您只会看到自己账户有权限打开的条目,当某个分组中的所有页面您都无权访问时,该分组会完全消失。

有两条约定值得了解:

- **不存在单独的“新建”条目。** 每个列表页面都有一个 **New** 按钮用于打开创建表单,因此菜单中每个类别只对应一个条目,而不是两个。如果您的账户可以创建记录但不能查看列表,该菜单条目会直接带您进入创建表单。
- **分组下最多只有一层嵌套。** 到达某个页面最多只需 Settings → group → page 三步。

## 所有设置

该部分的第一个条目 **All Settings**,会打开一个目录,列出您的账户可以访问的所有设置页面,按与菜单相同的分组排列,并可按名称或页面功能进行搜索。搜索 `deduplication` 会同时找到三个去重页面*以及* System Settings,因为 System Settings 中也包含去重选项。

最后一个类别 **Elsewhere in the app** 列出了那些用于配置 DefectDojo、但位于侧边栏其他部分的页面——包括授权提供商、Login 和 MFA 设置、Jira 实例、上游和下游连接器,以及通用解析器。每个磁贴上都标有其所属的部分。

## 有哪些内容发生了变动

如果您习惯了先前的布局:

| Previously | Now |
| --- | --- |
| Settings → *(top level)* → Feature Flags | Settings → System → Feature Flags |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → E-mail Settings | Settings → System → E-mail |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(three pages)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(reference-data catalogs)* | Settings → Configuration → *(unchanged)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(cloud pages)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

以您的许可证套餐命名的分组——在 Pro 实例上为 **Pro Settings**,在 Enterprise 实例上为 **Enterprise Settings**——已不复存在。其中的页面已分散到 System、Finding Workflow、Notifications 和 Operations 各分组中。

## 切换布局

[Feature Flags](/admin/feature_flags/pro__feature_flags/) 页面上的 **Menu 2.0** 控制当前生效的布局。开启或关闭该开关会立即重塑侧边栏;无需重启,您实例的其他任何内容都不会发生变化。

新安装的实例默认开启该开关。现有实例默认关闭,因此升级过程不会在团队毫无准备的情况下重新排列菜单——请在管理员准备就绪后再开启该开关。

该开关关闭期间,**All Settings** 页面不可用,其 URL 会返回 Not Found。
