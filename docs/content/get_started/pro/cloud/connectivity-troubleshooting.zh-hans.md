---
title: 连接故障排查
description: 重新连接到您的 DefectDojo 实例
weight: 2
audience: pro
aliases:
- /zh-hans/en/cloud_management/connectivity-troubleshooting
---

如果您在访问 DefectDojo 实例时遇到困难，可以按照以下步骤重新建立连接：

## 我可以访问网站，但无法登录

1. 您可以在登录页面重置账户密码：**yourcompanyinstance.cloud.defectdojo.com/login**。点击“忘记密码”即可开始重置流程。  
​

![image](images/Connectivity_Troubleshooting.png)

2. 输入您的电子邮件地址，然后点击“重置我的密码”。  
​
3. 您应该会收到一封主题为“`Password reset on yourcompanyinstance.cloud.defectdojo.com`”的电子邮件。该邮件中包含一个链接，点击后即可设置新密码。  
  

![image](images/Connectivity_Troubleshooting_2.png)

如果您没有收到邮件，请检查您的垃圾邮件文件夹。如果仍未收到，请让您团队的 DefectDojo 管理员确认您的账户已在实例中注册。  



## 我无法访问我公司的 cloud.defectdojo 网站

如果您公司的 cloud.defectdojo 网站在浏览器中无法加载，或出现超时，您的公司可能需要更改防火墙规则，以便接受您的连接。

防火墙规则可以在您的 Cloud Manager 中更改，地址为 <https://cloud.defectdojo.com/accounts/manage_subscriptions>。

如果您的公司使用共享 VPN、代理服务器或类似工具，请确保该工具已获得连接 DefectDojo 的授权，并且其 IP 地址已被包含在 DefectDojo 的防火墙规则中。

如果问题仍然存在，请联系 [support@defectdojo.com](mailto:support@defectdojo.com)。



## 我无法登录 Cloud Manager

如果您无法访问 Cloud Manager，请前往登录页面 <https://cloud.defectdojo.com/accounts/login/>，然后点击**“忘记密码？”**


![image](images/Connectivity_Troubleshooting_3.png)  
系统会提示您输入电子邮件地址，我们的团队会向您发送一封包含链接的邮件，供您重置密码并设置新密码。 

请注意，此登录方式仅适用于**Cloud Manager**，这是一个管理站点，您团队中的成员可能并非都有权限访问。要直接登录并使用 DefectDojo 实例，只能通过直接访问 **yourcompanyinstance.cloud.defectdojo.com/login** 来完成。



## 我丢失了 MFA 验证码的访问权限

* **对于 Cloud Manager：** 如果您丢失了 MFA 验证码或身份验证器应用的访问权限，请通过 [support@defectdojo.com](mailto:support@defectdojo.com) 联系 DefectDojo 支持团队。
* **对于 DefectDojo 实例：** 请先尝试使用设置 MFA 时颁发的**恢复代码（recovery codes）**之一 —— 在登录时输入该代码来代替六位数验证码。如果恢复代码不可用，拥有服务器访问权限的管理员可以使用 `python manage.py remove_mfa --username <username>` 命令清除该账户的 MFA 设置；随后用户可以用密码登录并重新注册 MFA，所有现有权限和历史记录都会保留。在 DefectDojo Cloud 上，请联系支持团队来运行该命令。完整选项请参见[多重身份验证](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device)。
