---
title: 上游连接器
description: 轻松将 DefectDojo 与您的安全工具套件连接起来
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 0
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
aliases:
- /zh-hans/import_data/pro/connectors/about_connectors/
- /zh-hans/en/connecting_your_tools/connectors/about_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：上游连接器（Upstream Connectors）是 DefectDojo Pro 专属功能。</span>

DefectDojo 允许用户构建复杂的 API 集成，并让用户完全掌控其漏洞数据的组织方式。

但每个人都需要一个起点，这正是上游连接器（Upstream Connectors）发挥作用的地方。上游连接器（此前称为 **API Connectors**）旨在让您的安全工具尽快接入并将数据导入 DefectDojo。

我们目前为以下工具提供上游连接器支持，并将持续增加：

* **Acunetix 360**
* **Akamai API Security**
* **Anchore**
* **AWS Security Hub**
* **Azure DevOps**
* **Backstage**
* **Bitbucket**
* **Black Duck**
* **Bright Security**
* **Bugcrowd**
* **BurpSuite**
* **Censys**
* **Checkmarx ONE**
* **Cloudflare**
* **Cobalt.io**
* **Contrast**
* **Coverity**
* **CrowdStrike Falcon**
* **Deepfence ThreatMapper**
* **Dependency-Track**
* **Docker Scout**
* **Edgescan**
* **Endor Labs**
* **Escape**
* **Fairwinds Insights**
* **Fortify**
* **GitGuardian**
* **GitHub**
* **GitHub Advanced Security**
* **GitLab**
* **Google Cloud Security Command Center**
* **Group-IB ASM**
* **HackerOne**
* **Harbor**
* **Have I Been Pwned**
* **HCL AppScan**
* **Intigriti**
* **Intruder**
* **IriusRisk**
* **JFrog Xray**
* **Jira Service Management Assets**
* **Kubescape**
* **Lacework / FortiCNAPP**
* **Mend**
* **Microsoft Defender**
* **Microsoft Defender for Cloud**
* **MobSF**
* **NeuVector**
* **Nuclei (ProjectDiscovery Cloud)**
* **OpenVAS / Greenbone**
* **Probely**
* **Prowler**
* **Qualys**
* **Quay**
* **Rapid7 InsightAppSec**
* **Rapid7 InsightVM**
* **runZero**
* **Semgrep**
* **ServiceNow CMDB**
* **Shodan**
* **Snyk**
* **Socket**
* **SonarQube**
* **Sonatype IQ**
* **Sysdig Secure**
* **Tenable**
* **Tenable Web App Scanning**
* **Veracode**
* **Wazuh**
* **Wiz**
* **YesWeHack**

有关每种工具的具体设置步骤，请参见[工具专属连接器设置](../toolreference/)参考文档。

大多数连接器导入的是**发现项**。也有少数是**资产连接器（Asset Connectors）**，它们导入的是您的**资产清单**，而不是发现项——用于构建并维护您的 Product（资产）与 Product Type（组织）层级结构：**Azure DevOps**、**Backstage**、**Bitbucket**、**GitHub**、**GitLab**、**Jira Service Management Assets** 以及 **ServiceNow CMDB**。（**runZero** 主要是一个资产连接器，但也可以选择将漏洞作为发现项导入。）

这些连接可为 DefectDojo 提供 API 速度的集成能力，能够自动摄取并组织来自该工具的漏洞数据。

## 熟悉连接器页面

连接器分为两个部分列出，每个部分的标题旁都会显示数量，并按字母顺序排序：

* **已配置的连接器（Configured Connectors）**——本实例上已存在的每一个连接器配置。同一个工具可以出现多次，每个配置对应一次，每个卡片的标题为 `<Tool> - <label>`，以便相互区分。当多个配置共用同一个工具时，会按其标签排序。
* **可用的连接器（Available Connectors）**——每一个您尚未配置的受支持工具。

标题旁的数量是当前显示的连接器数量，因此会随搜索框及 **Asset / Finding** 类型筛选器变化，而不总是显示总数。在 DefectDojo Pro Cloud 中，**Request Upstream Connector** 卡片本身不是连接器，也不计入数量。

两个部分都各自带有搜索框，可按工具名称进行匹配。

![连接器页面，每个部分标题旁均显示数量](images/upstream_counts.png)

[下游连接器](/connectors/downstream/about/)与[授权连接器](/admin/sso/pro__authorization_connectors/)页面的布局方式相同。

## 上游连接器快速上手

如果您使用 DefectDojo 的**自动映射（Auto\-Map）**设置，可以很快让第一个连接器运行起来。

1. 从受支持的工具中设置一个[连接器](../add_edit/)。
2. [发现](../manage_operations/#discover-operations)您所用工具的数据层级结构。
3. 将该工具中发现的漏洞[同步](../manage_operations/#sync-operations)到 DefectDojo 中。

就是这样，真的很简单！而且请记住，即使您以“简易”方式创建连接器，之后也可以随时更改设置方式，而不会丢失已完成的工作。

## 上游连接器的工作原理

只要您拥有要连接的工具的 API 密钥，连接器几分钟内即可添加完成。连接建立后，DefectDojo 会**发现（Discover）**您工具的环境，以了解您是如何组织扫描数据的。

举例来说，假设您有一个 BurpSuite 工具，被设置为扫描五个不同代码仓库中的漏洞。您的连接器会记录这种组织结构，并建立**记录（Records）**，帮助您将这些独立的代码仓库转化为 DefectDojo 的 Product / Engagement / Test 层级结构。如果您启用了**“自动映射记录（Auto\-Map Records）”**，DefectDojo 会自动学习并复制该结构。

![image](images/_index.png)

**记录**映射设置完成后，DefectDojo 会开始定期导入扫描数据。您将能及时了解该工具检测到的任何新漏洞，并可以立即使用 DefectDojo 的**发现项**系统处理已有漏洞。

当您准备向 DefectDojo 添加更多工具时，可以轻松地重新调整导入映射。多个工具可以设置为将漏洞导入同一个目标位置，而且您始终可以在不丢失任何已完成工作的前提下，重新组织您的设置以更好地适配需求。

## 我的连接器不受支持

### 从界面中申请连接器（DefectDojo Pro Cloud）

在 DefectDojo Pro Cloud 上，您可以直接从界面中请求我们的团队为尚不支持的工具构建连接器：

1. 前往 **Connectors → Upstream Connectors**（用于将数据导入 DefectDojo 的工具）。issue 跟踪系统等出站集成也可以在 **Connectors → Downstream Connectors** 下以同样的方式申请。
2. 在 **Available Connectors** 部分，点击 **Request a Connector**。
3. 填写申请表单。**Tool / Product Name**、**Tool API Base URL**、**Authentication Type** 以及该身份验证类型对应的凭据均为必填项，因为我们的团队需要一个可访问的地址和一份可用的凭据，才能构建连接器并确认其能对您的工具正常工作。凭据会被安全存储。您也可以选择性地填写供应商网站、该工具 API 文档的链接，以及描述您使用场景的备注。
4. 点击 **Submit Request**。您会看到一条确认信息，表明您的请求已收到。我们的团队会审核每一份请求以评估是否构建支持——提交请求并不保证一定会构建该连接器。

申请连接器需要**全局 Maintainer** 权限，且仅在 **DefectDojo Pro Cloud** 上可用——该选项不会出现在自托管（本地部署）实例上。

### 手动导入

即使没有连接器，DefectDojo 仍然可以为众多安全工具处理手动导入。请参见我们的[受支持工具列表](/supported_tools)，以及导入数据的指南。

# **后续步骤**

* 切换到 DefectDojo 的 **Pro UI**，打开 **Import** 标题下的 **Connectors \> Upstream Connectors**，查看 **Upstream Connectors** 页面。
* 按照我们的指南[创建您的第一个上游连接器](../add_edit/)。
* 了解如何[运行操作](../manage_operations/)，让您已连接的安全工具按配置导入数据。
