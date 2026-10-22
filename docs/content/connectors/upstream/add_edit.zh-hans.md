---
title: 添加或编辑上游连接器
description: 连接到受支持的安全工具
aliases:
- /zh-hans/import_data/pro/connectors/add_edit_connectors/
- /zh-hans/en/connecting_your_tools/connectors/add_edit_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：上游连接器（Upstream Connectors）是 DefectDojo Pro 专属功能。</span>

无论您要连接哪种工具，添加和配置上游连接器的流程都是相似的。不过，某些工具可能需要您创建 API 密钥或完成额外的步骤。

在开始此流程之前，我们建议先查阅[工具专属参考文档](../toolreference/)，找到您要连接的工具所对应的 API 资源。

1. 如果尚未操作，请先在 DefectDojo 中**切换到 Pro UI**。
2. 在左侧菜单中，打开 **Import** 标题下嵌套的 **Connectors** 分组，点击 **Upstream Connectors**。
​
![image](images/add_edit_connectors.png)

3. 在 **Available Connectors** 中选择您要添加到 DefectDojo 的新连接器，并点击该工具卡片上的 **Add Configuration** 按钮。您可以使用 **Search Connectors** 搜索框按工具名称筛选每个部分，也可以使用页面标题中的 **All / Asset / Finding** 切换开关按连接器类型筛选。  
​  
您也可以在 **Configured Connectors** 标题下编辑已有的连接器。对于要编辑的已配置连接器，点击 **Manage Configuration \> Edit Configuration** 即可。  
​
![image](images/add_edit_connectors_2.png)

4. 您需要提供该工具的可访问**位置 URL（Location URL）**，以及一个 API **密钥（Secret）**。API 密钥的位置取决于您要配置的具体工具。详情请参见我们的[工具专属参考文档](../toolreference/)。  
​
5. 为该连接设置一个**标签（Label）**，以便在 DefectDojo 中识别它。  
​
6. 使用**发现配置（Discovery Configuration）**和**同步配置（Synchronization Configuration）**计划，安排该连接器的自动发现与同步。这些计划之后可以更改。  
​
7. 选择是否要**启用自动映射（Enable Auto\-Mapping）**。启用自动映射后，DefectDojo 会创建一个新的 Product 来存储此连接器的数据。自动映射可以随时开启或关闭。  
​
8. 点击 **Submit**。

![image](images/add_edit_connectors_3.png)

## 后续步骤

* 添加连接器后，您可以通过运行一次[发现](../manage_operations/#discover-operations)操作，确认所有设置均正确无误。
