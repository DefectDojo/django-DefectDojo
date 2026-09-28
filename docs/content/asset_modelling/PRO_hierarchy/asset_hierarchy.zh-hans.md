---
title: 资产层级结构
description: DefectDojo Pro — 产品层级结构改造
audience: pro
weight: 1
aliases:
- /zh-hans/en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
- /zh-hans/asset_modelling/pro_hierarchy/assets_organizations
---

DefectDojo Pro 正在扩展产品/产品类型（Product/Product Type）对象类，以便为数据模型提供更强的灵活性。

## Enabling the Hierarchy Feature

以下两部分功能相互独立，通过不同的方式进行控制。

### Asset Hierarchy

**资产层级结构（Asset Hierarchy）**支持在资产（Asset）之间建立父子关系。该层级结构可以从导航栏中的**产品（Product）**选项卡查看和管理。

资产层级结构已正式发布（GA），在云端和本地部署的每个实例上均默认开启。无需进行任何启用操作，该功能也不再列在功能开关（Feature Flags）页面中。

### Label Changes (optional)

**标签更改（Label Changes）**会在整个 UI 中将“产品类型（Product Type）”重命名为“组织（Organization）”，将“产品（Product）”重命名为“资产（Asset）”。这是与启用层级结构相独立的一个步骤，可以同时进行，也可以稍后再做。

自 3.0 版本起，标签更改默认处于启用状态。共有两个控制项，分别涵盖应用程序的不同部分：

* **Pro UI**（默认界面）：超级用户可以在**设置 > 功能开关（Settings > Feature Flags）**中切换“组织/资产重新标注（Organization / Asset Relabeling）”，云端和本地部署的实例均适用。新标签会在下次页面加载时显示。请参阅[功能开关](/admin/feature_flags/pro__feature_flags/)。
* **经典 UI 页面及生成的报告**：其标签和 URL 来自 `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` 部署设置项，该设置在 DefectDojo 启动时读取。若为本地部署，请设置该项并重启 DefectDojo。若使用 [DefectDojo Pro（云端）](/get_started/pro/cloud/)，请将您的实例 URL 通过邮件发送至 [support@defectdojo.com](mailto:support@defectdojo.com)。

这两项设置默认均为开启状态，且功能开关的初始值是根据部署设置生成的，因此除非您单独更改其中一项，否则两者会保持一致。如果您同时使用经典 UI 和 Pro UI，请保持这两项设置同步。

请注意，标签更改仅是外观上的调整：API 端点和字段名称保持不变，因此现有的自动化流程将继续正常工作。

## Significant Changes

* **产品类型（Product Types）**已重命名为“组织（Organizations）”，**产品（Products）**已重命名为“资产（Assets）”。自 3.0 版本起，此名称更改默认处于启用状态。有关关闭该功能的控制项，请参阅[标签更改](#label-changes-optional)。
* **资产（Assets）**现在可以彼此建立父子关系，从而对组织内的组成部分进行进一步细分。

### Organizations

与产品类型一样，**组织（Organizations）**应被理解为一个顶层类别。您可以使用组织来划分企业的核心软件应用、部门或业务职能。

例如，您可以为多个代码仓库分组创建一个组织：“Core Application”“Infrastructure”“DevOps”“Analytics”“SDK”都可以各自包含多个代码仓库。

请注意，出于报告目的，将多个组织合并到单个文档中，要比将单个组织拆分为多个独立文档更容易实现。因此，我们建议根据团队报告的实际需要，将组织设置在尽可能细粒度的层级上。例如，如果您主要是针对某个业务部门内部的各个部门分别进行报告，就没有必要将整个大型业务部门设为一个组织。

### Assets

资产旨在表示组织内部的细分单元。但与产品不同的是，资产可以嵌套，并且彼此之间可以建立父子关系。

## Asset Nesting Examples

### Asset-Level Branch Representation

开发分支和功能分支可以通过多种方式表示；使用独立的测试活动或测试就是现有的一种方式，可用来体现生产环境、开发环境以及其他功能分支之间的差异。

您也可以使用嵌套资产来表示这些分支。请参考以下资产树：

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

在此结构下，每个分支（`prod`、`dev`、`feature a`、`feature b`）都可以拥有各自独立的测试活动和测试，与其他资产相互隔离，从而不会彼此去重。这种设置也有助于导航，因为资产名称可以直接对应 Git 上的路径。

### Mono-Repo: Separate Components

如果您使用单一仓库存放所有代码，但由不同团队负责该仓库内的不同目录，您可以设置资产嵌套结构来表示这种情况。

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

在此图中，“Core Application”下的每个元素都可以被记录为一个独立的资产，拥有各自独立的业务重要性（参见：[优先级与风险](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines)）、RBAC 以及相应的测试活动和测试。您既可以继续在父资产（例如 `webapp-backend`）上进行测试并存储结果，也可以在特定的子资产（例如 `database`）上运行隔离的测试。

### Pen Tests: Isolated RBAC

如果您希望将渗透测试结果存储在单个资产内，但又不希望测试人员能够查看该资产的数据，您可以为每个测试小组创建子资产，用于各自上传测试结果。

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

关键在于，在此结构下，为用户授予对单个子资产（例如 `Pen Test Group A`）的 RBAC 访问权限，并不会让该用户看到其他子资产（例如 `Pen Test Group B`）中的任何发现项，也不会让其看到父资产（`webapp-frontend`）中的发现项。

父资产可以包含代表 CI/CD 结果、内部测试、历史数据，或其他您不希望第三方能够发现的发现项数据的测试活动。为特定测试结果创建子资产，可以让您的内部团队在报告这些结果的同时，结合父资产的整体状态一并呈现。

## Visualizing Assets - Hierarchy

您可以在 DefectDojo 中可视化资产的结构，并通过菜单中的资产层级结构选项来更改它们之间的关系。

![image](images/asset_hierarchy.png)

打开资产层级结构后，将显示一个包含您所有资产的表格，该表格支持筛选。从此表格中选择一个或多个资产，将渲染出一张层级结构图。

![image](images/asset_hierarchy_diagram.png)

### Diagram navigation

层级结构图左上角的图标可用于放大和缩小。在该图表中点击并拖动，可以滚动浏览整张图。

每个资产在此图中都渲染为一个单独的节点，可以出于展示目的自由移动。

各资产之间通过带标签的路径相连接，用以表示彼此之间的关系类型。目前仅支持 `parent` 这一种标签。

### Exploring Asset nodes

每个资产节点都可以通过点击蓝色按钮进行交互。这些按钮仅在选中某个资产节点（通过点击该节点）后才会出现。

![image](images/asset_hierarchy_node.png)

* 👁️（眼睛图标）将直接带您进入相应的资产视图（原称为产品视图）。
* ✏️（铅笔图标）将打开一个包含编辑资产表单的弹窗（原称为编辑产品表单）
* ➕（加号图标）允许您为该资产添加一个新的子资产。该资产不需要当前在图中可见，但必须属于同一个组织。
* ✥（四向箭头图标）允许您更改当前所选资产的父资产。
* 🗑️（垃圾桶图标）允许您移除某个资产的父级关系。此图标仅在该资产已经拥有父资产时才会出现。

如果您的图表中显示的某个资产存在未被选中的父资产，您可以点击“加载更多（Load More）”按钮，将该父资产（以及该父资产的子资产）填充到图中。

![image](images/assets_loadmore.png)

## Notes

* 请注意，去重范围并未发生变化；资产仅在其自身范围内对发现项进行去重，不会考虑其他资产中的发现项，无论父子关系如何。
* 此系统中的 RBAC 范围并未发生变化；就权限分配而言，每个资产仍被视为一个独立的对象。系统并未新增任何 RBAC 继承机制。
  * 为用户授予对整个组织的访问权限，仍会使该用户获得对该组织内所有资产的访问权限（与产品类型的情形一致）。
  * 为用户授予对单个资产的访问权限，并不会使该用户获得对相关父资产或子资产的访问权限，也不会获得对该组织的访问权限。
* 可以创建的父子关系数量没有限制。理论上，如果您愿意，可以使用独立的资产来表示某个仓库的整个目录结构。
* 不允许出现循环关系：父资产不能同时是其子资产的子级。
