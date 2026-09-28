---
title: 设置个人通知
description: 为个人账户配置通知
aliases:
- /zh-hans/en/customize_dojo/notifications/configure_personal_notifs
---

## 配置个人通知

个人通知会在系统级通知之外额外发送,适用于您有权访问的任何产品、产品类型或其他数据类型。个人通知偏好设置仅适用于单个用户,且只能在正在配置的账户上进行设置。

![image](images/Configure_System_&_Personal_Notifications.png)

系统通知由 DefectDojo 超级用户设置,个人用户无法选择退出。

1. 从通知页面开始(侧边栏中的⚙️**配置 > 通知**)。
2. 从**范围**下拉菜单中,您可以选择想要编辑的通知集合。
3. 选择个人通知。
4. 勾选您希望为每种通知类型使用的通知方式。您可以选择多种方式。

个人通知无法通过 Microsoft Teams 发送,因为 Teams 只允许在单个频道中发布全局通知。

### 接收特定产品的个人通知

除标准个人通知外,DefectDojo 用户还可以接收特定产品上活动的通知。当用户需要更密切地监控某些产品时,此功能会很有帮助。

![image](images/Configure_System_&_Personal_Notifications_3.png)

此配置可以在**产品**页面的**通知**部分进行更改,例如:`your-instance.defectdojo.com/product/{id}`。

在此处,您可以设置是否希望针对该特定产品上发生的操作接收**🔔 提醒**、**邮件**或 **Slack** 通知。这些通知会在您已经接收的任何系统级通知之外额外生效。

Microsoft Teams 无法发送任何类型的个人通知,因此无法从此菜单中选择 Teams 通知。

个人邮件通知始终会发送到与您的 DefectDojo 登录账户关联的邮箱。要设置个人 Slack 账户以接收通知,请参阅我们的[指南](../email_slack_teams/#send-personal-notifications-to-slack)。
