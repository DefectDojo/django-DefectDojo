---
title: 使用 Cloud Manager
description: 管理您的订阅和账户设置
weight: 1
collapsed: true
audience: pro
aliases:
- /zh-hans/en/cloud_management/using-cloud-manager
---

登录 DefectDojo 的 Cloud Manager 可让您配置账户设置并管理您的 DefectDojo Cloud 订阅。

## **新建订阅**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

此页面可让您向 DefectDojo 申请新的（或[额外的](../additional-cloud-instance/)）Cloud 实例。

## **管理订阅**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

订阅管理页面显示您当前所有处于活动状态的 Cloud 实例，并可让您为每个实例配置防火墙设置。

### 更改您的防火墙设置
![image](images/using_the_cloud_manager.png)

进入**编辑订阅（Edit Subscription）**页面后，输入您要添加的规则的 IP 地址、掩码（Mask）和标签（Label）。如果需要多条防火墙规则，请点击**添加新范围（Add New Range）**以创建一条新的空白规则。

![image](images/using_the_cloud_manager_2.png)

在此处，您还可以向外部服务（GitHub 和 Jira Cloud）开放防火墙。如果需要，您也可以从菜单中选择**不使用防火墙（Proceed Without Firewall）**，完全禁用防火墙。

## 向 Cloud Portal 添加其他用户

如果您希望让多个用户能够控制您的 Cloud Portal / DefectDojo 订阅，可以通过此表单添加他们。您要添加的用户必须已在 cloud.defectdojo.com 上创建了自己的 Cloud Portal 账户；仅拥有 DefectDojo 实例上的账户是不够的。

![image](images/using_the_cloud_manager_5.png)

输入与该用户 Cloud Portal 账户关联的电子邮件地址，然后点击提交（Submit），将其添加到您的关联用户列表中。此后，该用户即可管理 Cloud Portal 以及您的 DefectDojo 订阅。

## 资源
<https://cloud.defectdojo.com/resources/>

资源页面包含一个联系我们（Contact Us）表单，您可以通过它联系我们的支持团队。

![image](images/using_the_cloud_manager_3.png)

## 工具
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

工具页面是您可以下载外部 Pro 工具（例如 Universal Importer 或 DefectDojo CLI）的位置之一。这些工具是外部附加组件，可用于在您的网络中快速构建命令行导入管道。有关这些工具的更多信息，请参阅[外部工具](/import_data/pro/specialized_import/external_tools/)文档。

![image](images/using_the_cloud_manager_6.png)


## 账户设置
<https://cloud.defectdojo.com/accounts/settings>

账户设置页面包含四个部分：

* **用户联系方式（User Contact）**：可让您设置用户名、电子邮件地址、名和姓。
* **电子邮件账户（Email Accounts）**：可让您为账户添加其他电子邮件地址。添加额外的电子邮件账户会向新地址发送一封验证邮件。
* **管理社交账户（Manage Social Accounts）**：可让您将 DefectDojo Cloud 与您的 GitHub 或 Google 凭据关联，从而可以使用这些凭据登录，而无需使用用户名和密码。
* **MFA 设置（MFA Settings）**：可让您将 MFA 代码添加到 Google Authenticator、1Password 或类似应用中。为登录流程增加一个额外步骤，是防止未经授权访问的有效主动措施。

### 为您的 Cloud Portal 登录添加 MFA
<https://cloud.defectdojo.com/settings/mfa/configure/>

请注意，这仅会为您的 DefectDojo Cloud 登录添加 MFA，而不会影响您 DefectDojo 应用本身的登录。

![image](images/using_the_cloud_manager_4.png)

1. 首先，在您的智能手机或计算机上安装一款支持二维码认证的身份验证器（Authenticator）应用。
2. 完成后，点击**生成二维码（Generate QR Code）**。
3. 使用您的身份验证器应用扫描 DefectDojo 中提供的二维码，然后输入该应用生成的六位数代码。
4. 点击**启用多重身份验证（Enable Multi-Factor Authentication）**。
