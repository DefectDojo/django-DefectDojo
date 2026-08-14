---
title: ☑️ 新規ユーザー向けチェックリスト
description: DefectDojoを使ってみる
draft: 'false'
weight: 3
audience: opensource
---

これは、白紙の状態から完全に機能するアプリになるまで、実装を確実に成功させるためのクイックリファレンスです。この記事は、**DefectDojo Community Edition**が環境にインストールされ、稼働していることを前提としています。

DefectDojoの本質は、セキュリティデータをインポートし、整理し、それを知る必要がある人々に提示することです。ここでは、DefectDojo Open-Sourceでこれらを実現する方法を紹介します。

### DefectDojo Open-Source

1. Open-Sourceのユーザーは、まず最初の[Product TypeとProduct](/asset_modelling/os_hierarchy/product_hierarchy/)を作成することから始められます。作成後は、UIを使用してそれらのProductのいずれかに[ファイルをインポート](/import_data/import_scan_files/os__import_scan_ui/)できます。

2. DefectDojoにデータが入ったので、次に[Product Hierarchy Overview](/asset_modelling/os_hierarchy/product_hierarchy/)でProductのレイアウトを拡張することを検討してください。Product Hierarchyはアプリの実用的なインベントリを作成し、データを論理的なカテゴリに分割するのに役立ちます。これらのカテゴリは、アクセス制御ルールの適用や、レポートを適切なチームにセグメント分けするために使用できます。

3. インポートしたデータを要約するには、[Report Builder](/metrics_reports/reports/using-the-report-builder/#opening-the-report-builder)を使用してください。レポートは、Product Ownerなどのステークホルダーと検出事項を迅速に共有するために使用できます。

これがDefectDojoの本質です - セキュリティデータをインポートし、整理し、それを知る必要がある人々に提示します。

これらの機能はすべて自動化でき、DefectDojoは(本稿執筆時点で)500以上のツールに対応しているため、組織全体のアウトプットに対する実用的なセキュリティインベントリを作成する準備が整っているはずです。

### Open-Sourceの機能
- 組織でJiraを使用していますか? 取り込んだデータからJiraチケットを作成する方法については、[Jira integration](/connectors/os_jira/os__jira_guide/)をご覧ください。
- 組織内の多くのユーザーとDefectDojoを共有する予定はありますか? [ユーザー管理](/admin/user_management/about_perms_and_roles/)のガイドを確認し、ロールベースアクセス制御(RBAC)を設定してください。
- 自動化に取り組む準備はできていますか? [DefectDojo API](/import_data/import_scan_files/api_pipeline_modelling/)を使用して新しいデータを自動的にインポートし、堅牢なCI/CDパイプラインを構築する方法を学びましょう。
