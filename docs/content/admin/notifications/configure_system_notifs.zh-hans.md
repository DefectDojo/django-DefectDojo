---
title: 设置系统级通知
description: 如何配置个人通知与系统通知
aliases:
- /zh-hans/en/customize_dojo/notifications/configure_system_notifs
---

DefectDojo 有两种不同类型的通知:**个人通知**(发送给单个账户)和**系统通知**(发送给所有用户)。

账户的个人通知和全局系统通知都可以在同一个页面进行配置:侧边栏中的**⚙️配置 > 通知**。

![image](images/Configure_System_&_Personal_Notifications.png)

## 配置系统通知(经典界面)

**您需要拥有超级用户权限才能更改系统级通知。**

1. 从通知页面开始(侧边栏中的⚙️ **配置 > 通知**)。
2. 从范围下拉菜单中,您可以选择想要编辑的通知集合。
3. 选择系统通知。
4. 勾选您希望为每种通知类型使用的发送方式。您可以选择多种方式。

![image](images/Configure_System_&_Personal_Notifications_2.png)

要设置系统级邮件通知的目标地址(电子邮件、Slack 或 MS Teams),请参阅我们的[指南](../email_slack_teams)。

## 模板通知

超级用户还可以访问"模板"表单。模板表单可用于设置为任何新用户默认启用的个人通知。

## 系统通知的发送对象

系统通知将发送给:
- 在系统设置中指定的单一电子邮件地址(如已启用)
- 拥有账户且具备相应 RBAC 权限的任何 DefectDojo 用户
- 系统级的 Slack 或 Teams 账户。

与 DefectDojo 中的任何通知一样,系统通知只会发送给有权访问相关数据的用户。因此,即使产品通知已在系统级设置,用户也只会收到其有权查看的产品的通知。

此限制不适用于发送到特定电子邮件地址或 Slack 频道的系统通知。

有关 RBAC 及权限设置的更多信息,请参阅我们关于[基于角色的访问控制](../../user_management/about_perms_and_roles/)的指南。

但是,所连接的系统电子邮件、Slack 和 Teams 账户无法应用 RBAC,因为它们并未与特定的 DefectDojo 用户关联。**所有已选择的系统级通知都会发送到这些位置,因此您应确保这些渠道只能被您组织内的特定人员访问。**
