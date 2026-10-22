---
title: ☑️ 新規ユーザー向けチェックリスト
description: DefectDojoを使ってみる
draft: 'false'
weight: 3
audience: pro
aliases:
- /ja/en/about_defectdojo/new_user_checklist
---

DefectDojoの本質は、セキュリティデータをインポートし、整理し、それを知る必要がある人々に提示することです。以下は、白紙の状態から完全に機能するアプリになるまで、実装を確実に成功させるためのクイックリファレンスです。

### DefectDojoを知る

1. まずUIを使用して[ファイルをインポート](/import_data/import_scan_files/pro__import_scan_ui/)することから始めます。これは通常、データがDefectDojoのモデルにどのように収まるかを確認する最も手っ取り早い方法です。

2. DefectDojoにデータが入ったので、[Product Hierarchy Overview](/asset_modelling/os_hierarchy/product_hierarchy/)でその整理方法についてさらに学びましょう。Product Hierarchyはアプリの実用的なインベントリを作成し、データを論理的なカテゴリに分割し、アクセス制御ルールを適用し、[Priority and Risk](/asset_modelling/pro_hierarchy/priority_sla/)によって検出事項を並べ替えたり、レポートを適切なチームにセグメント分けしたりするのに役立ちます。

3. 主要なステークホルダーと検出事項のレポートを迅速に共有するために使用できる[Metrics pages](/metrics_reports/pro_metrics/pro__overview/)を確認してください。

これがDefectDojoの本質です - セキュリティデータをインポートし、整理し、それを知る必要がある人々に提示します。

これらの機能はすべて自動化でき、DefectDojoは(本稿執筆時点で)500以上のツールに対応しているため、組織全体のアウトプットに対する実用的なセキュリティインベントリを作成する準備が整っているはずです。

### Proの機能
- 組織がJira、ServiceNow、AzureDevops、GitHub、GitLabのいずれかを課題管理に使用している場合は、それらの連携に関する[ドキュメント](/connectors/issue_tracking/)をご覧ください。
- フィルタ済みのタイルで[main Dashboard](/metrics_reports/dashboards/introduction_dashboard/)をカスタマイズし、環境を一目で確認できるようにします。
- [Connectors](/connectors/upstream/about/)を使用して、データを迅速にインポートし、チームの既存のセキュリティ環境をミラーリングする方法を学びましょう。
- [Global Search](/navigation/pro__global_search/)を使用して、インスタンス全体から検出事項、アセット、エンゲージメントを素早く見つけましょう。
