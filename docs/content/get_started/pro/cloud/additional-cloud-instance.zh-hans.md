---
title: 设置额外的 Cloud 实例
description: 为您的账户添加测试、开发或其他 DefectDojo 实例
weight: 3
audience: pro
aliases:
- /zh-hans/en/cloud_management/additional-cloud-instance
---

添加第二个 Cloud 实例的流程，与添加您的第一个实例大致相同。本指南假定您已经完成了初始 DefectDojo 服务器的搭建，并已与我们的销售团队就添加另一个实例达成协议。

如果您尚未申请额外的 Cloud 实例，请在继续操作之前联系 [info@defectdojo.com](mailto:info@defectdojo.com)。

## 第 1 步：打开新建订阅流程

您可以通过以下链接开始此流程：<https://cloud.defectdojo.com/accounts/onboarding/step_1>，也可以在 Cloud Manager 页面（cloud.defectdojo.com）中点击 🛒 **新建订阅**。

![image](images/request_a_trial.png)

## 第 2 步：设置您的服务器标签

输入您公司的**名称**，以及您想在 DefectDojo 中使用的**服务器标签**。系统随后会在我们的服务器上为您的 DefectDojo 实例创建一个自定义域名。

公司名称保持与之前相同，但需创建一个新的服务器标签，并勾选“**在域名中使用服务器标签**”按钮，以便您可以轻松区分不同的服务器。

![image](images/request_a_trial_2.png)

## 第 3 步：选择服务器位置

从下拉菜单中选择服务器位置。与之前一样，我们建议选择在地理位置上最靠近您用户的服务器，以降低服务器延迟。

![image](images/request_a_trial_3.png)

## 第 4 步：配置防火墙规则

输入您希望允许访问 DefectDojo 的 IP 地址范围、子网掩码和标签。在您的实例启动并运行后，您的团队可以继续添加或更改其他 IP 地址和规则。

如果需要，这些防火墙规则可以与您主 DefectDojo 实例上的规则不同。

![image](images/request_a_trial_4.png)

如果您想在此实例中使用外部服务（GitHub 或 JIRA），请勾选**选择外部服务**下列出的相应复选框。

您也可以选择**不使用防火墙继续**，跳过防火墙设置。您的防火墙可以在之后重新启用。

## 第 5 步：确认您的套餐类型和计费周期

在流程结束时，我们会安排您与销售团队联系，由他们为您的新服务器提供准确报价。我们建议您选择具备新实例所需服务器规格的套餐类型。 

![image](images/request_a_trial_5.png)

第二台服务器可能不需要与您的“主”实例相同的存储、CPU 和内存要求，但这具体取决于您团队的技术需求。

## 第 6 步：审核并提交您的请求

系统会提示您再次核对您的请求。提交之后，您的团队只能自行更改防火墙规则，其他更改需要支持团队的协助。

![image](images/request_a_trial_6.png)

在查看并接受 DefectDojo 的许可与支持协议后，您可以继续**通过 Stripe 结账**，如果您已有现行的计费安排，也可以点击**联系销售**。

当您的服务器获得批准并完成配置后，我们的支持团队会与您联系，提供登录凭据。
