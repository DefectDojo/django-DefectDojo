---
title: 功能标志
description: 在 DefectDojo UI 中打开或关闭可选的 DefectDojo Pro 功能
weight: 1
audience: pro
---

功能标志(Feature Flags)让您可以在自己的实例上打开或关闭可选的 DefectDojo Pro 功能——以前只能通过联系 DefectDojo 支持才能启用的功能,现在可以在 UI 中自助完成。

功能标志页面仅对**超级用户**可见。其他用户(包括全局所有者)看不到该页面。

## 打开功能标志页面

在左侧边栏中前往**设置 > 功能标志**。

该页面列出了每一项可选功能,包含:

* **名称**——功能名称,若仍处于测试阶段则带有 **BETA** 标签
* **说明**——该功能的作用
* **文档链接**——该功能对应文档所在位置
* **开关**——该功能当前是否处于开启状态

使用搜索框可按功能名称或说明筛选列表。

### 未列出的功能

该页面列出的是您可以选择采用的功能。有两类功能不会出现在其中。

**始终开启。** 一旦某项功能进入正式发布(GA)阶段,它就会对所有实例保持开启,并不再列出,因为已经没有需要决定的事项:

* **下游连接器**——参见[下游连接器](/connectors/downstream/about/)
* **通用解析器**——参见[通用解析器](/import_data/pro/specialized_import/universal_parser/)
* **资产层级结构**——参见[资产层级结构](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **外观**和**功能标志**——两个同名的设置页面

如果您之前已经开启了其中某项功能,对您的实例不会有任何变化。如果您之前将其关闭,那么现在它已被开启:这些功能属于 DefectDojo Pro 的固有部分,而非可选启用项。如果这会给您的实例带来问题,请联系 [DefectDojo 支持](mailto:support@defectdojo.com)。

**由 DefectDojo 应请求启用。** 少数功能依赖于按实例预配置的基础设施,因此由 DefectDojo(而非在本页面)负责开启:

* **调度服务**——参见[调度规则](/automation/rules_engine/scheduling/)

如需启用上述功能,请联系 [DefectDojo 支持](mailto:support@defectdojo.com)。如果您的实例已经开启了该功能,它将保持开启状态。

## 开启或关闭某项功能

1. 在列表中找到该功能。
2. 点击其开关。
3. 更改会立即生效。其他用户会在下次加载页面时看到变化。

某些功能在应用更改前会显示确认对话框。这种情况出现在启用带有警告的功能时(例如需要重启,或可能影响现有数据的功能),或该功能一旦启用便无法再关闭时。

关闭某项功能通常只是开启操作的逆过程。例外情况见[开关被锁定时](#when-a-toggle-is-locked)。

### 组织/资产重命名

**组织/资产重命名**会将“产品类型”重命名为“组织”,将“产品”重命名为“资产”。该功能默认开启,并像其他功能一样可在本页面切换,但值得了解它所管辖的 DefectDojo 范围:

* **Pro UI** 会跟随该开关。新名称会在您下次加载页面时生效。
* **经典 UI** 页面及其 URL,以及生成的报告,其命名取自 `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` 部署设置(同样默认开启),该设置在 DefectDojo 启动时读取。本开关不会改变它们,重启也不会使其发生变化。

存储的开关状态最初是从该部署设置初始化的,因此两者在您更改其中任意一个之前是一致的。如果您在此处关闭重命名功能,同时又使用经典 UI,请在您的部署上将 `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False` 设置好并重启,以使两个界面保持一致。在 [DefectDojo Pro(云版)](/get_started/pro/cloud/)上,请联系 [DefectDojo 支持](mailto:support@defectdojo.com)以更改该部署设置。

正因如此,该功能在功能标志页面上带有**建议重启**标签:Pro UI 之外的命名在进程启动时就已固定。无论哪种情况,重命名都只是外观层面的变化。数据库模型、字段名称和 API 端点均不受影响,因此现有自动化流程不会受到影响。参见[资产层级结构](/asset_modelling/pro_hierarchy/asset_hierarchy/)。

## 开关被锁定时

无法更改的功能会显示一个锁定徽章,说明原因:

| 徽章 | 含义 | 应采取的操作 |
| --- | --- | --- |
| **由 DefectDojo 管理** | DefectDojo 已为您的实例集中设置了该功能。您的设置无法覆盖它。 | 如需更改,请联系 [DefectDojo 支持](mailto:support@defectdojo.com)。 |
| **此部署不可用** | 您的安装类型不提供该功能。请参见下方[功能可用性](#feature-availability)。 | 无需操作。该功能不适用于您的实例。 |
| **无法禁用** | 该功能已经开启,且是单向的。没有机制可以将其还原。 | 无需操作,这是预期行为。 |
| **由部署管理** | 该功能由您的部署配置控制,而非本页面。 | 参见下方 [DefectDojo Pro(本地部署)](#defectdojo-pro-on-premise)。 |

## DefectDojo Pro(云版)

在 [DefectDojo Pro(云版)](/get_started/pro/cloud/)上,您只需要**设置 > 功能标志**这一处即可。开启某项功能,它便立即生效。

以下两种情况由 DefectDojo 而非您本人处理:

* **由 DefectDojo 管理**——该功能被集中固定。如需更改,请联系 [DefectDojo 支持](mailto:support@defectdojo.com)。
* **由部署管理**——该功能属于您实例配置方式的一部分。这类情况也请联系支持,因为云端实例不向客户开放部署配置。

云端实例还可使用本地部署未提供的功能。请参见[功能可用性](#feature-availability)。

## DefectDojo Pro(本地部署)

在 [DefectDojo Pro(本地部署)](/get_started/pro/onprem/)上,大多数功能与云版完全相同:打开**设置 > 功能标志**并切换开关即可。

少数功能则改为从您的部署配置中读取。它们会影响应用程序的启动方式,因此无法在运行时切换。这类功能会在页面上显示为只读,标注为**由部署管理**,并注明控制它们的环境变量,例如 [位置](/asset_modelling/locations/pro__locations_overview/) 对应的 `DD_V3_FEATURE_LOCATIONS`。

由于这些功能需要重启,且其中一些一旦启用便无法还原,请在更改前查阅该功能自身的文档。其中多项功能最好在 [DefectDojo 支持](mailto:support@defectdojo.com)的协助下启用。

如需更改上述某项功能:

1. 在您的 DefectDojo 部署上设置相应的环境变量。页面会告诉您需要设置哪个变量。
2. 重启 DefectDojo,使新值在启动时被读取。
3. 重新加载功能标志页面以确认新状态。

由于这些值是在启动时读取的,因此无法通过 UI 更改;在您的环境中切换它们而不重启也不会产生任何效果。

仅在云端提供的功能,在本地部署实例上会显示为**此部署不可用**。这是预期行为,并非许可问题。

## 功能可用性

大多数功能在两种安装类型上都可用。例外情况如下:

| 功能 | 可用性 | 控制方式 |
| --- | --- | --- |
| 请求新连接器 | 仅 [DefectDojo Pro(云版)](/get_started/pro/cloud/) | 功能标志页面。本地部署会显示为**此部署不可用**。 |
| 位置 | 两者均可 | 功能标志页面。请注意,位置功能一旦启用便无法再关闭。参见[位置概述](/asset_modelling/locations/pro__locations_overview/)。 |
| 组织/资产重命名 | 两者均可 | Pro UI 通过功能标志页面控制;经典 UI 及其 URL 与生成的报告则跟随 `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` 部署设置。参见[上文](#organization--asset-relabeling)。 |

其他所有可选功能在云端和本地部署实例上都可直接在功能标志页面切换。

## 在 UI 之外读取功能标志

您不必打开功能标志页面才能知道哪些功能已启用——标志状态也可以通过编程方式读取,这在自动化流程需要在依赖某项能力之前先确认其是否可用时很有用。

```
GET /api/v2/defectdojo_information/feature_flags/
```

该接口会返回一个 JSON 数组,每个功能标志对应一个对象。除了标志的 `key`、`title` 和 `description` 之外,每个对象还会报告自动化流程通常需要的取值:`effective`(该功能对本实例是否实际开启)、`default`、`application_value`(该实例自身的设置,未设置时为 `null`)、`editable`,以及标志无法更改时的 `locked_reason`。已从产品中退役的标志不会出现在结果中。

任何**已通过身份验证**的用户都可以读取该接口——不需要超级用户角色。关于您所用版本的确切响应结构,请参见您实例上由当前构建生成的交互式 API 文档,地址为 `/api/v2/oa3/swagger-ui/`。另请参见 [API v2 文档](/automation/api/api-v2-docs/)。

同样的只读列表也发布在实例的 `/api/mcp/` 接口上,地址为 `/api/mcp/defectdojo_information/feature_flags/`。

该端点是**只读**的。开启或关闭某项功能仍需在功能标志页面完成,或者——对于上文提到的由部署配置的功能——在您的部署设置中完成。

## 常见问题

**我想要的功能不在列表中。**
该列表仅展示可选功能。始终开启的能力不会出现在其中。如果您认为缺少的某项功能应该存在,请先确认您的许可证是否包含该功能,然后联系 [DefectDojo 支持](mailto:support@defectdojo.com)。

**我开启了某项功能,但没有看到它。**
请重新加载页面——菜单项和路由是在页面加载时评估的,因此新启用的功能会在下次加载时出现,而不会立即出现在当前视图中。

**升级会改变我的设置吗?**
不会。升级会保留您已开启和已关闭的功能设置。
