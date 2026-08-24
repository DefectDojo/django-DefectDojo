---
title: 出站 IP 地址
description: DefectDojo Cloud 用于连接的出站 IP 地址，供您在外部防火墙中加入允许列表。
weight: 5
audience: pro
---

当 DefectDojo Cloud 与您的系统进行通信时——例如连接器（Connectors）同步扫描器的
API、将问题推送到 Jira 或 ServiceNow、发送通知 Webhook，或通过 SMTP 发送电子
邮件——这些连接都是从您的 DefectDojo 环境**主动发起的出站连接**。如果对端系统
位于防火墙之后，您需要允许 DefectDojo 的出站（egress）IP 地址，以免这些连接
被阻断。

本页说明如何查找这些出站 IP 地址。

## 出站与入站

这是两个不同的概念，本页仅涉及第一个：

- **出站（本页内容）**——DefectDojo Cloud 在**连接到**您的外部系统时使用的源
  IP 地址。请在**您的**防火墙中将这些地址加入允许列表，以便 DefectDojo 能够
  访问与其集成的系统。
- **入站**——控制谁可以访问**您的** DefectDojo 实例的规则。这些规则在 Cloud
  Manager 中作为防火墙规则进行管理，不在本页范围内。
  请参阅[连接故障排查](../connectivity-troubleshooting/)，以及
  [设置额外的 Cloud 实例](../additional-cloud-instance/)中的防火墙规则步骤。

## 多租户部署

Standard、按需付费（Pay-as-you-go）和 Premium 实例运行在共享的、按区域划分的
Google Kubernetes Engine (GKE) 集群上。出站连接来自您实例所在区域中各节点的
外部 IP 地址。

当前的节点出站 IP 集合以 JSON 格式发布，按区域分组：

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

该数据源内容如下所示：

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

要将 DefectDojo 的出站流量加入允许列表：

1. 确定您实例所在的区域（即配置实例时所选择的服务器位置 Server Location）。
2. 允许该区域下列出的每个 IP 地址。每个条目均为 `/32`（单主机）CIDR。

**此列表会随时间变化。**随着平台自动扩缩容，节点会被添加或替换，因此某个区域
的出站 IP 集合并非固定不变。请将该 JSON 数据源视为权威来源，而不要只复制一次
地址：

- 通过程序定期拉取该数据源，并据此刷新您的防火墙允许列表；或者
- 定期重新检查该数据源，并核对您的规则。

如果您的防火墙无法跟踪不断变化的列表，而您需要一小组稳定的地址，请联系您的
DefectDojo 代表，了解**专用（Dedicated）**实例（见下文）。

## 单租户（专用）部署

**Dedicated（专用）**层级的实例运行在其自己的 GCP 项目和 VPC 中，其出站 IP
地址是**稳定的**——该地址在实例配置时分配，并且不会随平台扩缩容而改变。

由于该稳定出站 IP 与您的特定实例绑定，因此不会在公共数据源中发布。请联系
[support@defectdojo.com](mailto:support@defectdojo.com)，获取分配给您的
Dedicated 实例的出站 IP 地址，并将其加入您外部防火墙的允许列表。

*本页未能解答您的问题？请联系您的 DefectDojo 代表。*
