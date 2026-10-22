---
title: LDAP 身份验证
description: 在 DefectDojo Pro 中配置 LDAP 身份验证
weight: 20
audience: pro
aliases:
- /zh-hans/en/open_source/ldap-authentication
---

DefectDojo Pro 支持从**企业设置**界面配置 LDAP 身份验证——无需自定义 Docker 镜像或配置文件。

与本页面上的其他提供商不同,LDAP 不是基于重定向的流程。用户使用标准的 DefectDojo 用户名和密码表单登录,其凭据会与您的目录进行比对。没有额外的登录按钮。

## 配置

打开**企业设置 > LDAP 设置**。

![image](images/sso_ldap_settings.png)

1. **Server URI**——要连接的目录,例如 `ldaps://ldap.example.com:636`。
   建议使用 `ldaps://`。如果必须使用明文的 `ldap://`,请在下方启用 **Use StartTLS**,以便在发送凭据之前先升级连接。
2. **Bind DN**——用于搜索用户的服务账户的可分辨名称。留空表示匿名绑定。
3. **Bind Password**——该服务账户的密码。已保存的值不会返回到浏览器;若要保留您已保存的密码,请将此字段留空。
4. **User Search Base**——搜索用户条目时所在的起始 DN,例如 `ou=people,dc=example,dc=com`。
5. **User Search Filter**——用于定位用户的过滤器。它**必须**包含字面量占位符 `%(user)s`,该占位符会被替换为提交的用户名。常见取值为 OpenLDAP 的 `(uid=%(user)s)` 和 Active Directory 的 `(sAMAccountName=%(user)s)`。
6. **User Attribute Mapping**——见下文。
7. 勾选**启用 LDAP** 以激活它。

使用**验证配置**可以在不保存设置的情况下进行检查。它会报告设置的完整性、服务器是否可达、绑定是否成功、搜索基是否能够解析,以及属性映射是否看起来可用。

## 用户属性映射

每一行将一个 **LDAP 属性**映射到它应填充的 **DefectDojo 字段**。使用**添加属性映射**可添加更多行,使用垃圾桶图标可删除某一行。

![image](images/sso_ldap_attribute_mapping.png)

- **LDAP 属性**是自由文本,必须与您目录实际返回的属性一致——例如 OpenLDAP 上的 `uid`、`givenName`、`sn`、`mail`,或 Active Directory 上的 `sAMAccountName`、`givenName`、`sn`、`mail`。
- **DefectDojo 字段**从列表中选择:**用户名**、**名字**、**姓氏**和**电子邮箱**。
- 强烈建议将某个属性映射到**电子邮箱**:DefectDojo 会使用该邮箱地址发送通知。
- 同一个属性可以同时提供给多个字段使用。但每个 DefectDojo 字段只能来自一个属性的映射。
- 完全不设置映射时,创建的账户将没有姓名或邮箱地址。

**Always Update User** 控制映射的应用时机。启用时(默认设置),映射的属性会在每次登录时从目录中刷新,因此 LDAP 中的姓名或邮箱变更会同步到 DefectDojo。禁用时,这些属性仅在账户首次创建时应用一次。

## 组映射

DefectDojo 可以在登录时将用户的 LDAP 组映射为 DefectDojo 组。勾选**启用组映射**以显示相关设置。

![image](images/sso_ldap_group_mapping.png)

- **Group Search Base**——搜索组条目时所在的起始 DN,例如 `ou=groups,dc=example,dc=com`。启用组映射时为必填项。
- **Group Type**——您目录建模成员关系的方式。OpenLDAP 和 Active Directory 请选择 **groupOfNames**,也可选择 **groupOfUniqueNames** 或 **posixGroup**。
- **Group Limiter Regex Expression**——只有名称匹配该表达式的组才会被映射。使用 `.*` 可允许全部,或使用类似 `^dd-` 的前缀,只映射您希望由 DefectDojo 管理的组。

组在首次使用时如果尚不存在会被创建。新创建的组在超级用户为其配置权限之前不具备任何权限——参见[用户组](../../user_management/create_user_group/)。

## 其他选项

* **Use StartTLS**——在绑定之前将明文的 `ldap://` 连接升级为 TLS。如果 URI 已经是 `ldaps://`,则无需此项。
* **Always Update User**——在每次登录时从目录刷新映射的属性。

## 故障排查

请先运行**验证配置**——它通常会直接指出问题所在。除此之外:

**所有登录都失败,但目录可以访问。** 检查 **User Search Filter** 是否包含 `%(user)s`,以及其中的属性是否与用户实际输入的内容一致。如果您的用户是用 Active Directory 的 `sAMAccountName` 登录,那么 `(uid=%(user)s)` 这样的过滤器将永远无法匹配。

**登录成功,但账户没有姓名或邮箱。** **User Attribute Mapping** 为空,或者左侧的 LDAP 属性名称与您目录实际返回的内容不匹配。

**LDAP 中的姓名已更改,但 DefectDojo 中没有变化。** **Always Update User** 已禁用,因此映射只在账户创建时应用过一次。

**登录尝试挂起或很慢。** 连接和搜索都受超时限制,因此无法访问的目录会直接失败,而不会无限期阻塞。请在**验证配置**中检查**服务器可达性**,并确认端口从 DefectDojo 主机可以访问。
