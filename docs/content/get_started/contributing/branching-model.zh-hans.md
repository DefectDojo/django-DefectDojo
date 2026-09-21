---
title: 开源分支与发布流程
description: 我们如何创建发布版本
draft: false
weight: 3
audience: opensource
aliases:
- /zh-hans/en/open_source/contributing/branching-model
---

## 常规发布

DefectDojo 团队致力于保持以下发布节奏：

- 次要版本（Minor）：每月至少一次，于每月的第一个星期一发布。
- 补丁/缺陷修复（Patch/Bugfix）：每周一发布。
- 安全发布（Security）：根据严重程度，在常规节奏之外发布。

GitHub Actions 是权威依据。发布流程是半自动化的。常规发布的步骤如下：
1. 从 `dev` 或 `bugfix` 创建发布分支，并准备一个针对 `master` 的 PR（[详情](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml)）
--> 维护者验证并手动合并该 PR
1. 打标签、发布草稿版本并构建/推送 Docker 镜像（[详情](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml)）
--> 维护者整理 release-drafter 生成的发布说明并发布该版本
1. 创建一个将 `master` 合并回 `dev` 和 `bugfix` 的 PR，以重新对齐各分支（[详情](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml)）

## 安全发布
与安全问题相关的 PR 通过[安全公告](https://github.com/DefectDojo/django-DefectDojo/security/advisories)完成，该机制可让团队私下处理代码，而不会过早披露漏洞。

## 发布与热修复模型

图表使用 [plantUML](https://plantuml.com) 创建。可在 https://www.planttext.com 找到基于网页的 PlantUML 编辑器。



<!-- PlantUML Schema -->
<div hidden>
```
@startuml

participant "Dev Branch" as dev #LightBlue
participant "BugFix Branch" as bugfix #LightGreen
participant "Release Branch" as release #LightGoldenRodYellow
participant "Master Branch" as master #LightSalmon

== Minor Release (Monthly) ==

dev -> release: Create branch "release/2.x.0"
release -> master: Merge
note right: Official Release\n - Tag 2.x.0\n - Push 2.x.0 to DockerHub
master --> bugfix: Merge master into bugfix to realign
master --> dev: Merge master back into dev

== Patch/BugFix Release (Weekly) ==

bugfix -> release: Create branch "release/2.x.y"
release -> master: Merge
note right: Official Release\n - Tag 2.x.y\n - Push 2.x.y to DockerHub
master -> bugfix: Merge master back into bugfix to realign
master --> dev: Merge master into dev to realign

== Security Release (As Needed) ==

master -> release: Create branch "release/2.x.y"
release -> master: Merge
note right: Official Release\n - Tag 2.x.y\n - Push 2.x.y to DockerHub
master --> bugfix: Merge master into bugfix to realign
master --> dev: Merge master into dev to realign

@enduml
```
</div>
