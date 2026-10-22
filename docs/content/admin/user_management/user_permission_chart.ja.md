---
title: アクション権限チャート
description: DefectDojo Pro のすべてのユーザー権限の詳細
weight: 4
audience: pro
aliases:
- /ja/en/customize_dojo/user_management/user_permission_chart
---

> **DefectDojo Pro の機能です。** このページで説明する メンバー / グループ / グローバルロール のRBACシステムは、DefectDojo Pro の一部です。オープンソース版のDefectDojoでは、[Authorized Users](../os__authorized_users/) モデルを使用します — オープンソース版のアクセス制御についてはそのページを、エディション間を移行する場合は [3.0 アップグレードノート](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) を参照してください。

## ロール権限チャート

このチャートは、製品または製品タイプに関連するすべての権限と、各ロールで利用可能な権限を一覧にすることを目的としています。

以下の5つのロールは、DefectDojo Pro の **組み込みロール**(built-in roles)です。これらはロックされたプリセットであり、権限はすべてのインスタンスで同一で変更できません。独自のロールを作成している場合、このチャートはそのロール自体ではなく、複製元となった組み込みロールについて説明しています。ロールに付与できる権限の全カタログについては、[Custom RBAC Roles](../pro__custom_rbac_roles/#choosing-permissions) を参照してください。

| **セクション** | **権限** | Reader | Writer | Maintainer | Owner | API Importer |
| --- | --- | --- | --- | --- | --- | --- |
| **製品 / 製品タイプ へのアクセス** | 割り当てられた製品または製品タイプの閲覧 ¹ | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | ネストされた製品、エンゲージメント、テスト、検出事項、エンドポイントの閲覧 | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | 新しい製品の追加(割り当てられた製品タイプ内) ² |  |  | ☑️ | ☑️ |  |
|  | 割り当てられた製品または製品タイプの削除 |  |  |  | ☑️ |  |
| **製品 / 製品タイプ のメンバーシップ** | ユーザーをメンバーとして追加(Owner ロールを除く) |  |  | ☑️ | ☑️ |  |
|  | メンバーのロールを編集(Owner ロールを除く) |  |  | ☑️ | ☑️ |  |
|  | メンバーのロールを編集(Owner ロールを含む) |  |  |  | ☑️ |  |
|  | 製品 / 製品タイプ のメンバーシップから自身を削除 | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | 他のユーザーに Owner ロールを追加 |  |  |  | ☑️ |  |
|  | グループ内で関連付けられた製品/製品タイプのメンバーシップを編集³ |  |  |  | ☑️ |  |
|  | グループ内で関連付けられた製品/製品タイプのメンバーシップを削除³ |  |  |  |  |  |
| **エンゲージメント**(製品内) | エンゲージメントの追加、編集 |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | リスク受容の閲覧 ⁴ |  | ☑️ | ☑️ | ☑️ |  |
|  | リスク受容の追加、編集 |  | ☑️ | ☑️ | ☑️ |  |
|  | エンゲージメントの削除 |  |  | ☑️ | ☑️ |  |
| **テスト**(製品内) | テストの追加 |  | ☑️ | ☑️ | ☑️ |  |
|  | テストの編集 |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | テストの削除 |  |  | ☑️ | ☑️ |  |
| **検出事項**(製品内) | 検出事項の追加 |  | ☑️ | ☑️ | ☑️ |  |
|  | 検出事項の編集 |  | ☑️ | ☑️ | ☑️ |  |
|  | スキャン結果のインポート、再インポート |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | 検出事項の削除 |  |  | ☑️ | ☑️ |  |
|  | 検出事項グループの追加、編集、削除 |  | ☑️ | ☑️ | ☑️ |  |
| **その他のデータ**(製品内) | エンドポイントの追加、編集 |  | ☑️ | ☑️ | ☑️ |  |
|  | エンドポイントの削除 |  |  | ☑️ | ☑️ |  |
|  | ベンチマークの編集 |  | ☑️ | ☑️ | ☑️ |  |
|  | ベンチマークの削除 |  |  | ☑️ | ☑️ |  |
|  | メモ履歴の閲覧 | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | 自身のメモの追加、編集、削除 | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | 他者のメモの編集 |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | 他者のメモの削除 |  |  | ☑️ | ☑️ |  |

1. 製品レベルのみで権限を割り当てられたユーザーは、その製品が含まれる製品タイプを閲覧できません。
2. 製品タイプの下に新しい製品が追加されると、その製品タイプレベルのすべてのユーザーが、その製品タイプレベルのロールで新しい製品のメンバーとして追加されます。
3. グループに変更を加えたいユーザーは、**Edit Group** **コンフィギュレーション権限** と、編集したいグループにおける **Maintainer または Owner** の **グループコンフィギュレーションロール** の両方を持っている必要があります。
4. リスク受容の閲覧可否は、検出事項の閲覧可否とは異なる最小権限によって制御されます — 製品の Reader は基盤となる検出事項を閲覧できますが、その検出事項が属するリスク受容は閲覧**できません**。リスク受容の権限、有効期限の動作、再適用のワークフローの詳細については、[Risk Acceptances (Pro)](/triage_findings/findings_workflows/pro__risk_acceptance/#risk-acceptance-permissions-and-visibility) を参照してください。

## コンフィギュレーション権限チャート

各コンフィギュレーション権限は、ソフトウェア内の特定の機能を指し、その機能に関連してユーザーが実行できる一連のアクションが紐づいています。

コンフィギュレーション権限の大部分は、UI内の特定のページへのアクセスをユーザーに付与します。

| **コンフィギュレーション権限** | **閲覧 ☑️** | **追加 ☑️** | **編集 ☑️** | **削除 ☑️** |
| --- | --- | --- | --- | --- |
| Credential Manager | **⚙️Configuration \> Credential Manager** ページへのアクセス | Credential Manager に新しいエントリを追加 | Credential Manager のエントリを編集 | Credential Manager のエントリを削除 |
| Development Environments | 該当なし | 🗓️**Engagements \> Environments** リストに新しい Development Environment を追加 | 🗓️**Engagements \> Environments** リストの Development Environment を編集 | **🗓️Engagements \> Environments** リストから Development Environment を削除 |
| Finding Templates¹ | **Findings \> Finding Templates** ページへのアクセス | Finding Template を追加 | Finding Template を編集 | Finding Template を削除 |
| Groups | **👤Users \> Groups** ページへのアクセス | 新しい User Group を追加 | スーパーユーザーのみ | スーパーユーザーのみ |
| Jira Instances | **⚙️Configuration \> JIRA page** へのアクセス | 新しい JIRA Configuration を追加 | 既存の JIRA Configuration を編集 | JIRA Configuration を削除 |
| Language Types |  |  |  |  |
| Login Banner | 該当なし | 該当なし | **⚙️Configuration \> Login Banner** にあるログインバナーを編集 | 該当なし |
| Announcements | 該当なし | 該当なし | **⚙️Configuration \> Announcements** にある Announcements を設定 | 該当なし |
| Note Types | ⚙️Configuration \> Note Types ページへのアクセス | Note Type を追加 | Note Type を編集 | Note Type を削除 |
| Prioritization Engines | Prioritization Engine 設定ページへのアクセス | 新しい Prioritization Engine を追加 | 既存の Prioritization Engine を編集 | Prioritization Engine を削除 |
| Product Types | 該当なし | 新しい Product Type を追加(Products \> Product Type 内) | 該当なし | 該当なし |
| Questionnaires | **Questionnaires \> All Questionnaires** ページへのアクセス | 新しい Questionnaire を追加 | 既存の Questionnaire を編集 | Questionnaire を削除 |
| Questions | **Questionnaires \> Questions** ページへのアクセス | 新しい Question を追加 | 既存の Question を編集 | 該当なし |
| Regulations | 該当なし | **⚙️Configuration \> Regulations** ページに Regulation を追加 | 既存の Regulation を編集 | Regulation を削除 |
| Scheduling Service Schedule | **Scheduling** ページへのアクセス | スーパーユーザーのみ | 既存の Schedule を編集(トリガーの変更、有効/無効化) | Schedule を削除 |
| SLA Configuration | **⚙️Configuration \> SLA Configuration** ページへのアクセス | 新しい SLA Configuration を追加 | 既存の SLA Configuration を編集 | SLA Configuration を削除 |
| Test Types | 該当なし | 新しい Test Type を追加(**Engagements \> Test Types** 内) | 既存の Test Type を編集 | 該当なし |
| Tool Configuration | **⚙️Configuration \> Tool Configuration** ページへのアクセス | 新しい Tool Configuration を追加 | 既存の Tool Configuration を編集 | Tool Configuration を削除 |
| Tool Types | **⚙️Configuration \> Tool Types** ページへのアクセス | 新しい Tool Type を追加 | 既存の Tool Type を編集 | Tool Type を削除 |
| Users | **👤Users \> Users** ページへのアクセス | DefectDojo に新しい User を追加 | 既存の User を編集 | User を削除 |

1. Finding Templates ページへのアクセスには、このユーザーに **Writer、Maintainer**、または **Owner** のグローバルロールも必要です。

## グループコンフィギュレーション権限

| Configuration Permission | **Reader** | **Maintainer** | **Owner** |
| --- | --- | --- | --- |
| グループの閲覧 | ☑️ | ☑️ | ☑️ |
| グループから自身を削除 | ☑️ | ☑️ | ☑️ |
| グループ内のメンバーのロールを編集 |  | ☑️ | ☑️ |
| グループから製品または製品タイプのメンバーシップを編集または削除¹ |  | ☑️ | ☑️ |
| グループメンバーのロールを Owner に変更 |  |  | ☑️ |
| グループを削除 |  |  | ☑️ |

1. これには、編集したい製品または製品タイプにおいて、ユーザーが少なくとも Maintainer ロールを持っている必要もあります。
