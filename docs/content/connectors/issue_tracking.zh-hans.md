---
title: 问题跟踪集成
description: 将 DefectDojo 发现项与您的问题跟踪系统同步，简化修复流程并明确责任归属。
weight: 5
aliases:
- /zh-hans/issue_tracking/
- /zh-hans/issue_tracking/intro/
- /zh-hans/issue_tracking/intro/intro/
---

## 概述

DefectDojo 的问题跟踪集成将您的漏洞管理工作流与现有的问题跟踪系统连接起来。通过根据安全发现项自动创建和更新问题工单，DefectDojo 帮助确保漏洞在开发和运维团队已经使用的工具中保持可见、有专人负责并得到处理。

| Edition      | Supported Issue Tracking Integrations |
|--------------|---------------------------------------|
| Community Edition  | * [Jira](/connectors/os_jira/os__jira_guide/)                          |
| Pro          | * [Jira](/connectors/downstream/downstream_toolreference/#jira)（[旧版指南](/connectors/downstream/pro__jira_guide/)）<br>* [Azure DevOps](/connectors/downstream/downstream_toolreference/#azure-devops-boards)<br>* [Bitbucket](/connectors/downstream/downstream_toolreference/#bitbucket)<br>* [Freshservice](/connectors/downstream/downstream_toolreference/#freshservice)<br>* [GitHub](/connectors/downstream/downstream_toolreference/#github)<br>* [GitLab Boards](/connectors/downstream/downstream_toolreference/#gitlab)<br>* [Linear](/connectors/downstream/downstream_toolreference/#linear)<br>* [PagerDuty](/connectors/downstream/downstream_toolreference/#pagerduty)<br>* [ServiceDesk Plus](/connectors/downstream/downstream_toolreference/#servicedesk-plus)<br>* [ServiceNow](/connectors/downstream/downstream_toolreference/#servicenow)<br>* [Shortcut](/connectors/downstream/downstream_toolreference/#shortcut)<br>* [Zendesk](/connectors/downstream/downstream_toolreference/#zendesk) |


启用后，DefectDojo 可以自动创建问题工单，也可以选择性地从产品或测试活动中创建。当 DefectDojo 中的发现项被更新——解决、缓解或重新激活——时，对应的问题工单也可以保持同步，确保两个系统都反映当前的风险状态。

## 跟踪哪些内容

每个问题工单都可以包含关键的漏洞详细信息，例如严重程度、描述、证据和修复建议。DefectDojo 与问题跟踪系统之间的链接提供从发现到解决的可追溯性，支持报告、审计和持续改进。

## 为什么问题跟踪集成很重要

安全发现项只有在可采取行动时才最为有效。将 DefectDojo 与问题跟踪系统集成，通过把安全工作直接嵌入现有的工程工作流程，弥合了检测与修复之间的差距。这减少了上下文切换，提高了责任归属的清晰度，并帮助团队更快地修复问题。
