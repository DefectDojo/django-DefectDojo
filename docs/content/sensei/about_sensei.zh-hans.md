---
title: 关于 Sensei
description: Sensei 是什么，以及 DefectDojo 托管的扫描与修复如何运作
draft: false
audience: pro
weight: 1
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：Sensei 是 DefectDojo Pro 专属功能，目前处于 BETA（测试）阶段。</span>

**Sensei** 是 DefectDojo 面向源代码仓库的 AI 驱动**扫描与修复**能力。连接一个仓库（通过 **GitHub App**、**GitLab**、**Bitbucket** 或 **Azure DevOps**），Sensei 便会对其进行扫描，将结果作为 DefectDojo 发现项导入，然后使用大语言模型**通过发起拉取/合并请求来修复这些发现项**，整个过程无需离开 DefectDojo。

> **🔀 多种提供方：** Sensei 支持 **GitHub**（github.com 和 GitHub Enterprise Server）、**GitLab**（gitlab.com 和自托管）、**Bitbucket**（Cloud 和 Server/Data Center）以及 **Azure DevOps**，均采用相同的扫描与修复流程。本指南中提到 *pull request（拉取请求）* 的地方，GitLab 使用的是**合并请求（merge request）**；PR 的 *状态检查* 在 GitLab/Azure 上以**提交状态（commit status）**形式发布，在 Bitbucket 上则以**构建状态（build status）**形式发布。不同提供方的连接方式不同（参见[设置 Sensei](/sensei/setup_sensei/)）；接入完成后的一切操作都相同。

- **集中式扫描与修复：** 仓库的扫描和修复均在 Sensei 页面及您的发现项中完成，使用与 DefectDojo 其他部分相同的标准化、去重后的发现项数据。
- **预览优先：** Sensei 会将修复*候选项*暂存以供审核。在您批准之前，不会向任何 LLM 发送内容，也不会发起任何拉取请求，因此不会产生意外费用或意外的 PR。
- **短期凭证：** Sensei 完全通过 GitHub App 运行，使用的是短期安装令牌。无需粘贴任何内容，也无需轮换任何密钥。
- **计量与许可限制：** Sensei 是一项 Pro 功能，按实例对修复次数和已接入仓库数量设有配额。

> **🧠 在代码存在之前：** Sensei 还可以根据功能*设计*生成威胁模型、攻击路径和安全需求，无需涉及任何仓库——参见[威胁建模](/sensei/threat_modeling/)。

> **🔎 BETA：** Sensei 正在积极开发中，界面中会标注为 **BETA**。行为和界面可能会在版本之间发生变化。

> **📍 在哪里找到它：** 从左侧导航栏打开 **Sensei**。

![Sensei hub](images/hub_overview.png)

## DefectDojo 托管扫描的工作原理

DefectDojo 托管扫描是运行 Sensei 的推荐方式。扫描在 **DefectDojo 内部**运行，不会向您的仓库添加任何内容：

1. **连接 GitHub App**，并将其安装到拥有您仓库的组织（或账户）上。
2. **接入一个仓库**以启用托管扫描，并选择发现项的报告方式以及（可选的）自动修复方式。
3. **Sensei 扫描该仓库**（按需触发，或在拉取请求发起时自动触发），并将结果导入以分支命名的测试活动中。
4. **Sensei 修复发现项**，方法是生成修复方案，并针对仓库的默认分支发起拉取请求。

每个接入的仓库都会关联到一个 DefectDojo **资产**（产品），因此其发现项、测试活动和修复记录都会与您其他数据一同保存。

## 触发修复的三种方式

Sensei 可以通过三种方式修复发现项：

- **发现项上的 Fix 按钮：** 直接从发现项表格或发现项详情页触发一次性修复。参见[使用 Sensei 修复发现项](/sensei/fixing_findings/)。
- **自动修复候选项：** 每次扫描后，Sensei 会将符合您条件的发现项暂存为候选项。您可以审核并批准要修复的项（或让 Sensei 自动修复它们）。参见[自动修复候选项](/sensei/fixing_findings/#auto-fix-candidate-triage)。
- **在拉取请求中评论 `/fix`：** 在拉取请求上评论 `/fix`，Sensei 就会向该 PR 推送一次修复。

## 前提条件

- 一个包含 **Sensei** 功能的 **DefectDojo Pro** 许可证。
- 一个已连接的源代码控制提供方（参见[设置 Sensei](/sensei/setup_sensei/)）：**GitHub App**（github.com 或 Enterprise Server）、**GitLab** 项目/组访问令牌（gitlab.com 或自托管）、**Bitbucket** 连接（Cloud 或 Server/Data Center——OAuth、API 令牌或访问令牌），或 **Azure DevOps** 个人访问令牌。
- 要**配置** Sensei（连接应用、接入仓库）：需要全局 **Maintainer** 或 **Owner** 角色。
- 要对某个发现项**触发修复**：至少需要对该发现项所属产品的 **Writer** 权限。

## 配额

Sensei 会按照您的许可证进行计量。Sensei 中心页面顶部显示两个使用量指标：

- **修复次数：** 已使用的修复数量，相对于您预付的限额。批准候选项或触发修复都会消耗此配额。
- **已接入仓库数：** 已接入的仓库数量，相对于您的仓库数量限额。

当配额用尽时，Sensei 会阻止进一步的修复（或接入），直到限额被提高。详情参见[参考](/sensei/sensei_reference/#quotas-and-metering)。
