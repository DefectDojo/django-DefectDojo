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

すべてのリリースは`dev`ブランチから作成されます。DefectDojoチームは、以下のケイデンスを維持することを目指しています。

- マイナーリリース: 毎月第1月曜日に少なくとも月1回。
- パッチ: 毎週月曜日にリリース。
- セキュリティリリース: 深刻度に応じて、通常のケイデンスとは別に実施されることがあります。これも`dev`から作成されます。

バグ修正用の独立したブランチや、`master`から分岐するホットフィックスブランチはありません。バグ修正も機能追加も、すべてのプルリクエストは`dev`を対象とします。

GitHub Actionsが正となります。リリースは半自動化されています。リリースの手順は以下のとおりです。
1. `dev`からリリースブランチを作成し、`master`に対するPRを準備します([詳細](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-1-create-pr.yml))
--> メンテナーがPRを検証し、手動でマージします
1. タグ付け、ドラフトリリースの発行、Dockerのビルド+プッシュを行います([詳細](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-2-tag-docker-push.yml))
--> メンテナーがrelease-drafterのノートを整えてリリースを公開します
1. ブランチを再整合させるため、`master`を`dev`にマージし直すPRが作成されます([詳細](https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-3-master-into-dev.yml))

## セキュリティリリース
セキュリティ問題に関連するPRは、[セキュリティアドバイザリ](https://github.com/DefectDojo/django-DefectDojo/security/advisories)を通じて行われます。これにより、脆弱性を早期に公開することなく非公開でコードに取り組むことができます。

## リリースモデル

図は[plantUML](https://plantuml.com)で作成されています。PlantUML用のWebベースエディタはhttps://www.planttext.com で見つかります。



<!-- PlantUML Schema -->
<div hidden>
```
@startuml

participant "Dev Branch" as dev #LightBlue
participant "Release Branch" as release #LightGoldenRodYellow
participant "Master Branch" as master #LightSalmon

== Minor Release (Monthly) ==

dev -> release: Create branch "release/merge-dev-into-master-2.x.0"
release -> master: Merge
note right: Official Release\n - Tag 2.x.0\n - Push 2.x.0 to DockerHub
master --> dev: Merge master back into dev

== Patch Release (Weekly) ==

dev -> release: Create branch "release/merge-dev-into-master-2.x.y"
release -> master: Merge
note right: Official Release\n - Tag 2.x.y\n - Push 2.x.y to DockerHub
master --> dev: Merge master back into dev

@enduml
```
</div>
