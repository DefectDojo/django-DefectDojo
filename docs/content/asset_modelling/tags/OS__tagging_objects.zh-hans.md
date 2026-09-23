---
title: 为对象添加标签
description: 使用标签为您的数据模型创建新的切分维度
draft: false
weight: 2
exclude_search: false
audience: opensource
---

标签非常适合以一种可筛选、可拆分为更小、更易理解的方式对对象进行分组。您可以使用标签来表示状态,或者跨数据模型创建自定义的组织、资产、测试活动或发现项集合。

在 DefectDojo 中,标签是一等对象,被视为数据模型每一层级组织方式的促成因素。

以下示例展示了一个带有两个标签的资产,以及四个各自带有一个标签的发现项:

![High level example of usage with tags](images/tags-high-level-example.png)

### 标签格式

标签可以采用以下任意一种格式:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## 标签管理

### 添加与删除

标签可以通过以下几种方式进行管理:

1. 创建或编辑新对象

   当通过 UI 或 API 创建或编辑新对象时,会有一个字段用于指定要为该对象设置的标签。该字段是一个多选字段,并且带有自动补全功能,可以让搜索和添加现有标签变得轻而易举。以下是上一节截图中该资产上该字段的样子:

   ![Tag management on an object](images/tags-management-on-object.png)

2. 导入与重新导入

    标签也可以在导入或重新导入某个测试时应用到该测试上。当通过自动化方式经由 API 导入时,这是一个非常实用的场景,因为它提供了一个机会,可以附加那些可能不会直接体现在测试或发现项对象中的自动化运行详情和工具信息。

    该字段的外观和行为与其在普通对象上完全一致

3. 批量编辑菜单(仅限发现项)

    当需要用同一组标签更新大量发现项时,可以使用批量编辑菜单来减轻工作负担。

    在下面的示例中,假设我想将带有标签"tag-group-alpha"的两个发现项的标签更新为一个新的标签列表,如["tag-group-charlie", "tag-group-delta"]。
    首先,我会选中需要更新的发现项:

    ![Select findings for bulk edit tag update](images/tags-select-findings-for-bulk-edit.png)

    选中某个发现项后,会出现一个名为"Bulk Edit(批量编辑)"的新按钮。点击该按钮会弹出一个包含多个选项的下拉菜单,但目前我们只关注标签部分。将该字段更新为如下所需的标签列表,然后点击提交

    ![Apply changes for bulk edit tag update](images/tags-bulk-edit-submit.png)

    所选发现项上的标签将被更新为批量编辑菜单中标签字段所指定的内容

    ![Completed bulk edit tag update](images/tags-bulk-edit-complete.png)

## 标签继承

启用标签继承后,应用于某个资产的标签将自动应用到[资产层级结构](/asset_modelling/os_hierarchy/os__asset_hierarchy/)中该资产下的所有对象。

### 配置

标签继承可以在以下作用域级别启用:
- 全局作用域
  - 系统范围内的每个资产都会开始将标签应用到其所有子对象(测试活动、测试和发现项)
  - 该设置在系统设置中进行配置
- 资产作用域
  - 仅所选资产会开始将标签应用到其所有子对象(测试活动、测试和发现项)
  - 该设置在资产的创建/编辑页面中进行配置

### 行为

启用标签继承后,标准标签仍可以按常规方式添加到对象或从对象中删除。
但是,继承的标签如果不从父对象中删除,就无法从子对象中删除。请参见以下示例:向测试对象添加标签"test_only_tag",向测试活动添加标签"engagement_only_tag"。

![Example of inherited tags](images/tags-inherit-exmaple.png)

当资产上的标签列表发生更新时,相同的更改会异步应用到该资产内的所有对象。此任务所需的时长与发现项中所包含对象的数量直接相关。

**开源版:** 如果在合理的时间内没有观察到标签变更生效,请查阅 celery worker 日志以确定问题可能出现的位置。


### 按标签筛选(经典界面)

标签可以通过 UI 和 API 以多种方式进行筛选。例如,以下是发现项过滤器的一个片段:

![Snippet of the finding filters](images/tags-finding-filter-snippet.png)

与标签相关的字段共有十个:

 - 标签(Tags):筛选附加在给定发现项上的任意标签
   - 示例:
     - 该发现项会被返回
       - 发现项标签:["A", "B", "C"]
       - 筛选查询:"B"
     - 该发现项*不会*被返回
       - 发现项标签:["A", "B", "C"]
       - 筛选查询:"F"
 - 排除标签(Not Tags):筛选*未*附加在给定发现项上的任意标签
   - 示例:
     - 该发现项会被返回
       - 发现项标签:["A", "B", "C"]
       - 筛选查询:"F"
     - 该发现项*不会*被返回
       - 发现项标签:["A", "B", "C"]
       - 筛选查询:"B"
 - 标签名称包含(Tag Name Contains):筛选在给定发现项中,标签名称部分或全部包含查询内容的标签
   - 示例:
     - 该发现项会被返回
       - 发现项标签:["Alpha", "Beta", "Charlie"]
       - 筛选查询:"et"("Beta"的一部分)
     - 该发现项*不会*被返回
       - 发现项标签:["Alpha", "Beta", "Charlie"]
       - 筛选查询:"meg"("Omega"的一部分)
 - 排除标签(Not Tags):筛选在给定发现项中,标签名称*不*包含部分或全部查询内容的标签
   - 示例:
     - 该发现项会被返回
       - 发现项标签:["Alpha", "Beta", "Charlie"]
       - 筛选查询:"meg"("Omega"的一部分)
     - 该发现项*不会*被返回
       - 发现项标签:["Alpha", "Beta", "Charlie"]
       - 筛选查询:"et"("Beta"的一部分)

对于其余六个标签字段,它们遵循与上述"标签(Tags)"和"排除标签(Not Tags)"相同的规则,只是作用于数据模型中的不同层级:

 - 标签(测试)(Tags (Test)):筛选附加在给定发现项所属测试上的任意标签
 - 排除标签(测试)(Not Tags (Test)):筛选*未*附加在给定发现项所属测试上的任意标签
 - 标签(测试活动)(Tags (Engagement)):筛选附加在给定发现项所属测试活动上的任意标签
 - 排除标签(测试活动)(Not Tags (Engagement)):筛选*未*附加在给定发现项所属测试活动上的任意标签
 - 标签(资产)(Tags (Asset)):筛选附加在给定发现项所属资产上的任意标签
 - 排除标签(资产)(Not Tags (Asset)):筛选*未*附加在给定发现项所属资产上的任意标签
