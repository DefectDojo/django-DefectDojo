---
title: Sensei 参考
description: 状态、行操作、配额与故障排查
draft: false
audience: pro
weight: 5
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：Sensei 是 DefectDojo Pro 专属功能，目前处于 BETA（测试）阶段。</span>

以下是您在使用 Sensei 时会遇到的状态、操作和限制的快速参考。

## 仓库状态

Sensei 中心页面上，已接入仓库显示的状态：

| 状态 | 含义 |
|--------|---------|
| **Active** | 已接入，可以开始扫描。 |
| **Pull Request Open** | Sensei 针对该仓库有一个开启中的拉取请求。 |
| **Pull Request Closed** | 一个 Sensei 拉取请求已被关闭。 |
| **Error** | 上一次操作失败：请查看扫描活动以确定根本原因。 |
| **Not Configured** | 该仓库已连接，但尚未配置。 |

## 候选项与修复状态

自动修复候选项和修复记录会经历以下状态：

| 状态 | 含义 |
|--------|---------|
| **Candidate** | 由某次扫描的自动修复条件暂存。在您批准之前不会执行任何操作。 |
| **In Progress** | 已批准：Sensei 正在生成修复方案，即将发起拉取请求。 |
| **PR Open** | 修复拉取请求已开启；徽章会链接到该请求。 |
| **Failed** | 该修复未能完成；仍会保留在列表中，不会悄无声息地消失。 |

## 仓库行操作

Sensei 中心页面上，每个已接入的仓库都有一个行操作菜单：

![Repository row actions](images/repo_row_menu.png)

- **Scan now：** 启动一次按需扫描（打开分支选择器）。
- **Scan history：** 查看该仓库的历史扫描记录。
- **Configure：** 重新打开配置表单（PR 报告方式、自动修复、产品关联）。
- **Re-stage candidates：** 依据自动修复条件重新评估该仓库的发现项，并暂存新的候选项。
- **Delete：** 将该仓库从 Sensei 中移除。这会停止对其扫描；不会删除底层的资产或发现项。

## 配额与计量

Sensei 会按照您的 DefectDojo Pro 许可证进行计量，以中心页面顶部的指标形式显示：

- **Fixes（修复次数）：** 相对于您预付限额已应用的修复数量。批准候选项或触发修复都会消耗此配额；配额耗尽后，进一步的修复会被阻止（并出现警告横幅），直到限额被提高。
- **Onboarded Repositories（已接入仓库数）：** 相对于您的仓库限额已接入的仓库数量。达到限额后，将无法接入新仓库。

如需提高限额，请联系您的 DefectDojo 客户团队。

## GitLab 相关说明

GitLab 与 GitHub 一样受支持（gitlab.com 和自托管）。扫描与修复的行为完全相同；以下是 GitLab 特有的细节：

- **连接方式：** 使用**项目或组访问令牌**（角色为 **Developer**，若推送规则要求则需 **Maintainer**），并具备 **`api`** 和 **`write_repository`** 作用域，而非 GitHub App。参见[设置 Sensei](/sensei/setup_sensei/#connect-gitlab)。
- **Webhook：** 每个已接入的项目都需要一个指向 `…/sensei/gitlab/webhooks` 的 webhook（带有该连接的密钥），并订阅 **Push**、**Merge request** 和 **Comment** 事件。添加 webhook 需要该项目的 **Maintainer**/**Owner** 权限。
- **是合并请求，不是拉取请求：** 修复会针对默认分支发起**合并请求（merge request）**；`/fix` 评论在合并请求的备注中同样有效。
- **提交状态门控：** PR 状态检查是合并请求头部提交上的 GitLab **提交状态（commit status）**：扫描期间为 `running`，随后变为 `success` 或 `failed`（fail-on-new，即发现新问题即失败）。GitLab 没有*中性*状态，因此仍有发现项的**非阻断型**扫描会显示为**绿色**状态；详细信息则记录在摘要备注中。
- **自托管：** 将 **GitLab Base URL** 指向您的实例；DefectDojo 会针对该主机进行克隆并调用其 API。

## Bitbucket 相关说明

支持 Bitbucket **Cloud** 和 **Server/Data Center**。扫描与修复的行为完全相同；以下是 Bitbucket 特有的细节：

- **连接方式：** **OAuth**（推荐）、Atlassian **API 令牌**（配合您的账户邮箱使用），或仓库/工作区**访问令牌**。参见[设置 Sensei](/sensei/setup_sensei/#connect-bitbucket)。App 密码已弃用，不受支持。
- **工作区范围（Cloud）：** API/访问令牌绑定于工作区，因此 Cloud 版本必须指定**工作区**；OAuth 属于用户上下文，会自动发现可访问的工作区。
- **Webhook：** 每个已接入的仓库都需要一个指向 `…/sensei/bitbucket/webhooks` 的 webhook（带有该连接的密钥，通过 HMAC-SHA256 的 `X-Hub-Signature` 验证），并订阅 **Push**、**Pull request**（created/updated/merged/declined）和 **Pull request comment** 事件。
- **构建状态门控：** PR 状态检查以 Bitbucket **构建状态（build status）**的形式发布在头部提交上（`INPROGRESS` → `SUCCESSFUL`/`FAILED`）。Bitbucket 没有*中性*状态，因此非阻断型扫描会映射为 `SUCCESSFUL`，详细信息记录在摘要评论中。构建状态链接必须是公开可访问的 URL，因此会使用您的 DefectDojo 主机地址。
- **仓库名称：** `workspace/repo`（Cloud）或 `PROJECTKEY/repo`（Server/Data Center）。
- **Server/Data Center：** 将 **Base URL** 设置为您的主机地址；DefectDojo 使用 v1.0 REST API 和 `/scm/…` git 路径。

## Azure DevOps 相关说明

Azure DevOps Repos 通过**个人访问令牌**受支持。扫描与修复的行为完全相同；以下是 Azure 特有的细节：

- **连接方式：** 具备 **Code (Read, Write, & Manage)** 作用域的 **PAT**，以及所属的**组织**。Azure DevOps OAuth 应用正在被淘汰，因此推荐使用 PAT 作为凭证。参见[设置 Sensei](/sensei/setup_sensei/#connect-azure-devops)。
- **Webhook：** Azure **Service Hooks** 使用 HTTP **Basic**（而非 HMAC）进行身份验证，且**每个事件需要单独订阅**。请为 **Code pushed** 和 **Pull request created/updated/merged** 分别创建指向 `…/sensei/azure/webhooks` 的订阅，并提供该连接的 Basic 用户名/密码。
- **提交状态门控：** PR 状态检查以 Git **提交状态（commit status）**的形式发布在头部提交上。
- **仓库名称：** `project/repo`（组织信息保存在连接中）。
- **Azure DevOps Server：** 将 **Base URL** 设置为您本地部署的 collection URL。

## GitHub Enterprise Server 相关说明

GitHub Enterprise Server 使用与 github.com **相同的 GitHub App** 模型；仅主机地址不同：

- **连接方式：** 由于 App 清单自动创建流程仅适用于 github.com，您需要在 GHES 主机上**手动**创建该 App，并通过**手动设置**输入其凭证以及 **Enterprise 主机**。参见[连接 GitHub Enterprise Server](/sensei/setup_sensei/#connect-github-enterprise-server)。DefectDojo 会根据该主机推导出 API（`/api/v3`）和 Web 源。
- **共存：** 同一实例上可以同时配置一个 github.com App 连接和一个 GHES App 连接；每个仓库都会解析到其接入时所使用的连接。
- **可达性：** DefectDojo 必须能够访问 GHES 的 API 主机，GHES 也必须能够访问 DefectDojo 的 `…/sensei/webhooks` 端点（只要双方能够互通，内部主机也可以）。

## 故障排查

- **发现项上的 Sensei 按钮显示“Configure Product”。** 该发现项所属的产品尚未接入。点击它，为该产品接入一个仓库，然后返回该发现项。
- **在 Auto-fix Candidates 或 Scan Activity 中，某次修复显示为“Failed”。** 打开**扫描活动**，查看该次运行的 **Root Cause** / **Details**。失败的修复会保留在列表中，不会在产生 PR 之前消失；您可以重新暂存并重试。
- **接入时列表中没有某个仓库。** 只会显示该连接能够访问的仓库。在 **GitHub** 上，请确认该 App 已安装到正确的组织，且其仓库访问权限包含该仓库。在 **GitLab** 上，请确认访问令牌的作用域覆盖了该项目。在 **Bitbucket Cloud** 上，请确认已设置**工作区**（令牌是按工作区限定作用域的）。在 **Azure DevOps** 上，请确认 PAT 所属的组织匹配，且已授予其 **Code** 作用域。
- **配置 webhook 后，扫描或修复始终不会启动。** 请确认该仓库的 webhook 指向对应提供方的接收端点（`…/sensei/{gitlab,bitbucket,azure}/webhooks`，GitHub 则为 `…/sensei/webhooks`），密钥/凭证正确，并订阅了 push 及 pull-request（+ comment）事件。提供方的**最近投递记录**应显示 `HTTP 200`。由 webhook 触发的运行仅适用于以**托管**模式接入的仓库；对非默认分支的推送会通过其拉取请求进行扫描，而不会单独触发。
- **扫描完成后没有任何反应。** 请检查该仓库配置中是否已启用自动修复（且您的严重程度/风险阈值与发现项相匹配），以及您的 **Fixes** 配额是否已耗尽。

> **🔎 仍处于 BETA：** Sensei 正在快速演进。如果实际行为与本指南不符，请查看 [Pro 更新日志](/releases/pro/changelog/) 以了解近期变化。
