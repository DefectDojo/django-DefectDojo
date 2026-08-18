---
title: コンプライアンスプロファイル
description: Assetをシステムとして登録し、すべての成果物に表示される情報を設定する
weight: 1
audience: pro
---

コンプライアンスプロファイルは、Assetをシステムとして登録し、そのシステムが生成するすべての成果物に表示される情報を保持します。システム境界を表すAssetを開き、**Compliance**タブ、続いて**Profile**に移動します。

![コンプライアンスプロファイルのフォーム](images/01-compliance-profile.png)

## プロファイルのフィールド

| Field | What it does |
| --- | --- |
| **Enabled** | この製品のコンプライアンス追跡を有効にします。 |
| **Automatic Sync** | POA&M項目を検出事項と同期した状態に保ちます。 |
| **POA&M ID Prefix** | 項目の採番方法。必須です。デフォルトでは`V-1`、`V-2`のように採番されます。 |
| **Impact Level** | LI-SaaS、Low、Moderate、またはHigh。 |
| **Cloud Service Provider** | POA&Mの表紙データに表示されるCSP名。 |
| **System / Offering Name** | POA&Mの表紙データに表示されるシステム名。 |
| **FedRAMP System Identifier** | システムの識別子(例: `F00000042`)。 |
| **Default Point of Contact** | 独自の担当者を持たない項目に適用されるPOC。 |
| **Scan Item Policy** | 未解決の項目をすべて含めるか、期限超過のスキャン項目のみを含めるか。 |
| **OSCAL SSP Reference** | 任意項目。設定すると、生成されるOSCAL POA&Mが`import-ssp`を通じてこれを参照します。 |

### スキャン項目ポリシーを選ぶ

期限超過のみとするのは、FedRAMP ConMonの最低要件です。**Include all open items**(未解決の項目をすべて含める)はより保守的な選択肢であり、デフォルトの設定です。

## 保存と同期

**Save Compliance Profile**でAssetを登録します。その後、POA&M台帳はAssetの既存の検出事項から自動的に生成され、Complianceタブの残りの機能が利用可能になります。

**Automatic Sync**を有効にすると、台帳は常に最新の状態に保たれます — [POA&M台帳](../poam_ledger)を参照してください。**Sync POA&M Now**は即座に同期を実行するもので、プロファイルを変更した直後や新しいスキャンをインポートした直後に便利です。

## APIからのみ利用可能な設定

フォームには存在せず、コンプライアンスAPIを通じてのみ設定できるプロファイル設定が2つあります。

* **Default scan controls** — 独自の統制マッピングを持たないスキャナーの検出事項に割り当てられる統制。脆弱性スキャン結果には一般的に`RA-5`が選ばれます。独自の統制参照を*持つ*検出事項は、代わりにそちらからマッピングされます。[統制カバレッジ](../control_coverage)を参照してください。
* **Configuration test types** — その検出事項が構成項目として扱われるテストタイプで、台帳内でのCM-6統合を駆動します。

## 監査可能性

コンプライアンスプロファイルは監査履歴の対象です。すべての変更について、誰が何を変更し、いつ行ったかが記録されます。
