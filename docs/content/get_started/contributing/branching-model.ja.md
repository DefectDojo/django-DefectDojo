---
title: オープンソースのブランチ運用とリリース
description: リリースの作成方法
draft: false
weight: 3
audience: opensource
aliases:
- /ja/en/open_source/contributing/branching-model
---

## 定期リリース

DefectDojoチームは、以下のケイデンスを維持することを目指しています。

- マイナーリリース: 毎月第1月曜日に少なくとも月1回。
- パッチ/バグフィックス: 毎週月曜日にリリース。
- セキュリティリリース: 深刻度に応じて、通常のケイデンスとは別に実施されます。

GitHub Actionsが正となります。リリースは半自動化されています。定期リリースの手順は以下のとおりです。
1. `dev`または`bugfix`からリリースブランチを作成し、`master`に対するPRを準備します([詳細](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-pr.yml))
--> メンテナーがPRを検証し、手動でマージします
1. タグ付け、ドラフトリリースの発行、Dockerのビルド+プッシュを行います([詳細](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-tag-docker.yml))
--> メンテナーがrelease-drafterのノートを整えてリリースを公開します
1. ブランチを再整合させるため、`master`を`dev`と`bugfix`にマージし直すPRが作成されます([詳細](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/new-release-master-into-dev.yml))

## セキュリティリリース
セキュリティ問題に関連するPRは、[セキュリティアドバイザリ](https://github.com/DefectDojo/django-DefectDojo/security/advisories)を通じて行われます。これにより、脆弱性を早期に公開することなく非公開でコードに取り組むことができます。

## リリースおよびホットフィックスのモデル

図は[plantUML](https://plantuml.com)で作成されています。PlantUML用のWebベースエディタはhttps://www.planttext.com で見つかります。



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
