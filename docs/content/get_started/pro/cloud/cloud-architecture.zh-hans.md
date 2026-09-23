---
title: Cloud 架构
description: DefectDojo Cloud 如何在 Google Kubernetes Engine 上部署和实现隔离。
weight: 4
audience: pro
---

DefectDojo Cloud 是一个运行在 Google Cloud 上的多租户 SaaS 平台，基于
**Google Kubernetes Engine（GKE）**构建。本页介绍该平台的架构方式，以及
客户环境是如何相互隔离的。

![DefectDojo Cloud Kubernetes 架构示意图：客户流量通过启用 Google 托管 TLS 的 Google Cloud Load Balancing 进入区域级 GKE 集群；每个客户都运行在各自独立的 Kubernetes 命名空间中，拥有专属的 PostgreSQL 数据库、Cloud Storage 存储桶和 Vertex AI 项目。](images/cloud_architecture_kubernetes.svg)

## 请求如何流转

1. 客户流量（浏览器、API 或 CI）通过 **HTTPS** 到达 **Google Cloud Load
   Balancing**，由其使用 Google 托管证书终止 TLS。
2. 负载均衡器将请求路由到位于**区域级 GKE 集群**内的客户环境中，由
   Web/API 层（django，通过 nginx 和 uWSGI 提供服务）进行处理。
3. Web 层会读写客户**专属的 PostgreSQL 数据库**和**专属的 Cloud Storage
   存储桶**，并使用**命名空间内的缓存**（Redis/Valkey）来处理会话，同时
   作为任务代理（broker）。
4. 耗时较长的工作（例如扫描导入、去重和通知）会交由**异步工作进程**
   （Celery）处理，从而保持请求的响应速度。

## 租户隔离

每个客户都运行在**各自独立的 Kubernetes 命名空间**中，并且每个客户存储
的数据都不会与其他客户共用同一存储：

- **专属数据库**：每个客户拥有独立的 PostgreSQL 数据库（Cloud SQL）。
- **专属对象存储**：每个客户拥有独立的 Cloud Storage 存储桶，用于存放
  上传的扫描文件和媒体文件，并通过 GCS FUSE CSI 驱动挂载到工作负载中。
- **专属缓存**：每个命名空间都运行自己的 Redis/Valkey 实例。
- **按客户区分的凭据**：每个环境都拥有自己的 secret，以及各自的 TLS 证书
  和主机名。

客户之间**不存在共享的应用数据平面**。数据在传输过程中（TLS）和静态
存储时（Google Cloud 默认加密）均会被加密。

## 区域与数据驻留

该平台在**多个地理区域**运行**区域级 GKE 集群**（例如北美、欧洲和
亚太地区）。客户环境及其数据库和存储桶，都位于为该客户选定的区域内，
从而满足数据驻留方面的要求。

## 客户环境中的工作负载

每个命名空间都包含端到端运行 DefectDojo Pro 所需的全部组件：

| 分组 | 用途 |
|---|---|
| **Web 与 API** | 提供 UI 和 REST API 服务（django · nginx + uWSGI）。 |
| **异步处理** | 后台任务与调度（Celery worker + beat）。 |
| **编排** | 协调整个平台上的多步骤工作流。 |
| **集成** | 连接器与工单系统集成。 |
| **MCP 服务器** | 用于连接您自有 AI 工具的 AI 接口。 |
| **Sensei** | 通过 Google 的 Vertex Platform 提供 AI 修复能力。 |
| **命名空间内缓存** | 用于会话管理和任务代理的 Redis/Valkey。 |

每次部署时，都会先运行一个短生命周期的**初始化任务（initializer job）**
来执行数据库迁移，之后新版本才会开始处理流量。

## Sensei 与 AI 隔离

Sensei 是 DefectDojo 的 AI 修复能力，它通过 **Google 的 Vertex Platform**
运行，与数据平面的其他部分一样，采用按客户隔离的方式：

- 每个客户的 Sensei 请求都运行在**该客户专属的 GCP 项目**中，并使用
  **按客户区分的凭据**进行身份验证。
- 不存在共享的 AI 租户：一个客户的提示词、发现项和结果永远不会经过另一个
  客户的环境。
- **只有在客户自行配置的情况下，才会使用外部 AI 提供方**（例如通过 MCP
  服务器或客户自行提供的 AI 集成）。

## 平台服务与运维

由 Google 托管的共享服务为每个环境提供支持，且不会在租户之间传递客户
数据：

- **Artifact Registry**：已签名的容器镜像。
- **Secret Manager**：secret 和密钥材料。
- **Cloud Monitoring & Logging**：供我们的值班团队使用的指标、日志和
  告警。节点池会**自动扩缩容**以应对负载变化。

唯一在客户之间共享的数据是公开的漏洞富化信息（EPSS 和 KEV）。

## 集成仅为出站方向

与外部系统（例如电子邮件（SMTP）、工单系统（Jira、ServiceNow 等）、
安全扫描器和错误监控）的连接，均由**客户自行配置，并从客户自己的环境中
发起出站连接**。

## 按套餐等级划分的隔离级别

DefectDojo Cloud is offered in tiers that differ in how much of the stack is
dedicated to a single customer:

![按套餐等级划分的 DefectDojo Cloud 租户隔离方式：Standard 和 Pay-as-you-go 租户运行在共享 GKE 集群上的独立命名空间中，并共用一个 PostgreSQL 实例（各租户拥有独立的逻辑数据库）；Premium 租户拥有专属的 PostgreSQL 数据库；Dedicated 等级则运行在其专属的 GKE 集群、VPC 和 GCP 项目中。](images/cloud_architecture_tiers.svg)

| 等级 | 计算 | 数据库 | 网络边界 | Sensei |
|---|---|---|---|---|
| **Standard** | 共享集群上的独立命名空间 | 共享 PostgreSQL 实例上拥有独立的逻辑数据库和凭据 | 共享 VPC，按租户区分主机名 + TLS，可选 IP 允许列表 | 已包含 |
| **Pay-as-you-go**（即将推出） | 共享集群上的独立命名空间 | 共享 PostgreSQL 实例上拥有独立的逻辑数据库和凭据 | 共享 VPC，按租户区分主机名 + TLS，可选 IP 允许列表 | 已包含 |
| **Premium** | 共享集群上的独立命名空间 | 每个客户拥有**专属的 PostgreSQL 数据库** | 共享 VPC，按租户区分主机名 + TLS，可选 IP 允许列表 | 已包含 |
| **Dedicated** | **专属的 GKE 集群** | 客户自己 VPC 中**专属的 PostgreSQL 数据库** | **专属的 GCP 项目和 VPC**，入站流量限制在客户的 IP 范围内 | 已包含 |

Sensei 包含在每个等级中，并且在每个等级下都通过 Google 的 Vertex
Platform，在客户自己的 GCP 项目中使用按客户区分的凭据运行。

*本页未能解答您的疑问？请联系您的 DefectDojo 代表。*
