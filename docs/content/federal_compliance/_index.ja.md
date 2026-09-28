---
title: 連邦コンプライアンス
description: FedRAMPのPOA&MおよびConMon成果物、CMMC Level 2評価、NIST 800-53統制カバレッジ
summary: ''
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
audience: pro
exclude_search: true
---

DefectDojo Proは、連邦コンプライアンスプログラムにおける脆弱性管理の側面を担うことができます。各システムについてFedRAMP形式のPlan of Action and Milestones(POA&M)を保持し、公式のExcelおよびOSCAL形式で月次のContinuous Monitoring(ConMon)成果物を生成し、CMMC Level 2の自己評価を採点し、スキャナーが実際にどのNIST 800-53統制をカバーしているかを示します。

このセクションで説明する内容はすべて、Assetの**Compliance**タブにあります。

## 機能を有効にする

Federal Complianceは**Compliance**フィーチャーフラグの後ろに配置されており、これはベータ版であり、デフォルトでは無効です。管理者はフィーチャーフラグメニューから有効化します — [Feature Flags](/admin/feature_flags/pro__feature_flags/)を参照してください。有効化すると、各Assetに Complianceタブが表示されます。

## ベータ版: 利用する前に結果を確認してください

**この機能はベータ版です。** 同梱されているNIST 800-171および800-53の統制文言、DoD SPRSの配点、POA&M適格性ルールは、状況の追跡と見積もりを支援するために提供されており、権威ある原典文書に対する独立した検証は未実施です。

SPRSスコア、条件付き適格性の判定結果、統制カバレッジは**参考情報**です。認定、評価提出、その他契約上の目的で利用する前に、公式のDoD NIST SP 800-171 Assessment Methodologyおよび現行のFedRAMPガイダンスと照合して確認してください。

## このセクションの内容

| Page | What it covers |
| --- | --- |
| [コンプライアンスプロファイル](compliance_profile) | Assetをシステムとして登録し、すべての成果物に表示される情報を設定する |
| [POA&M台帳](poam_ledger) | 検出事項からPOA&M項目がどのように作成されるか、および台帳が従う規則 |
| [ConMonスナップショット](conmon_snapshots) | FedRAMPのExcelおよびOSCAL形式による月次成果物と、任意のOSCAL検証サービス |
| [是正期限](remediation_slas) | FedRAMP Rev 5とFedRAMP VDRのSLAプリセット |
| [CMMC Level 2 評価](cmmc_assessments) | NIST 800-171 Rev 2に基づく自己評価の採点 |
| [統制カバレッジ](control_coverage) | スキャナーがテストしている800-53統制と、統制ごとの未解決の弱点 |
