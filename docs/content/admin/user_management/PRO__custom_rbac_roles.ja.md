---
title: カスタムRBACロール
description: 5つの組み込みロールを複製可能な出発点として使用し、個々の権限を選択して独自のロールを構築する
weight: 5
audience: pro
---

> **DefectDojo Pro feature.** このページで説明されているMembers / Groups / Global RolesのRBACシステムは、DefectDojo Proの一部です。オープンソース版のDefectDojoは[Authorized Users](../os__authorized_users/)モデルを使用します。オープンソース版のアクセス制御についてはそのページを参照し、エディション間を移行する場合は[3.0アップグレードノート](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization)を参照してください。

DefectDojo Proには、**Reader**、**Writer**、**Maintainer**、**Owner**、**API Importer**の5つのロールが用意されています。これらのいずれも適合しない場合は、付与する権限を正確に選択して独自のロールを構築できます。

カスタムロールは、組み込みロールが機能するあらゆる場所で機能します。グローバルロールとして、グループのロールとして、デフォルトのグループロールとして、また個々のOrganizationやAssetのメンバーロールとしてです。

5つの組み込みロールは、**ロックされた複製可能なプリセット**になります。それぞれの権限は変更されておらず(各ロールが付与する権限については[操作権限チャート](../user_permission_chart/)を参照)、編集や削除はできません。新しいロールを作成する際は、いずれかを複製することが推奨される方法です。

## Before you start

カスタムロール管理はデフォルトでオフになっています。**スーパーユーザー**は、**Settings > Feature Flags**から**Custom Roles**を有効にすることでオンにできます。そのページの動作については[Feature Flags](/admin/feature_flags/pro__feature_flags/)を参照してください。

この機能がオフの間も、Rolesページは引き続き閲覧可能です。組み込みロールとその権限を表示できますが、作成、編集、複製、削除は一切できません。

ロールの管理には、**スーパーユーザー**ステータスまたは組み込みの**Owner**グローバルロールが必要です。これは意図的な設計であり、カスタムロールに委譲することはできません — [カスタムグローバルロールが解放するもの](#what-a-custom-global-role-unlocks)を参照してください。

## Opening the Roles page

左サイドバーの**👤 Users > Roles**に移動します。このメニュー項目は、スーパーユーザーおよび組み込みのOwnerグローバルロールを保有するユーザーに表示されます。

![The Roles page listing built-in and custom roles](images/pro_roles_list.png)

このテーブルには、インスタンス内のすべてのロールが一覧表示されます。

| Column | What it shows |
| --- | --- |
| **ID** | ロールの数値ID。Usersテーブルをフィルタリングしたり、APIを呼び出したりする際に便利です。 |
| **Name** | ロール名。 |
| **Description** | ロールの目的に関する独自のメモ。任意項目で、誰かが入力しない限り空欄です。組み込みロールにはこの項目はありません。 |
| **Permissions** | 付与された権限の数。クリックすると、グリッド全体の読み取り専用ビューが開きます。 |
| **Users** | このロールをグローバルロールとして保有するユーザー数。クリックするとUsersテーブルでそれらのユーザーを確認できます。 |
| **Type** | 5つのプリセットは**Built-in**、作成したロールは**Custom**です。 |

すべての列は並べ替えおよびフィルタリングが可能で、キーワード検索は名前と説明の両方に一致します。

## Creating a role

### Clone a built-in role (recommended)

複製から始めると、空のグリッドではなく既知の正しい権限セットから開始できるため、ロールに必要な権限を誤って除外してしまう可能性が大幅に低くなります。

1. 目的に最も近いロールを見つけます。
2. その**⋮**メニューを開き、**Clone Role**を選択します。
3. `<original> (copy)`という名前で、複製元と同じ権限と説明を持つコピーが即座に作成されます。
4. コピーの**⋮**メニューを開き、**Edit Role**を選択して、名前を変更し権限を調整します。

組み込みロールは編集できませんが、複製することはできます。複製されたロールには、複製元のロールが記録されます。

### Start from scratch

1. **New Role**をクリックします。
2. **Name**(必須)を入力し、任意で**Description**を入力します。
3. 下のグリッドで権限を選択します(次のセクションを参照)。
4. **Save Role**をクリックします。

ロール名は一意である必要があり、この確認では大文字と小文字は区別されません。`Triage Lead`が存在する場合、`triage lead`は拒否されます。

## Choosing permissions

![The permission grid in the role form](images/pro_role_permission_grid.png)

権限は、3つのテーブルと1つのチェックリストにグループ化されています。

**Object Permissions**は、ロールが割り当てられているOrganizationおよびAsset、およびそれらの配下にあるすべての項目に適用されます。

| Row | View | Add | Edit | Delete |
| --- | --- | --- | --- | --- |
| Organization | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset | ☑️ | ☑️ ¹ | ☑️ | ☑️ |
| Engagement | ☑️ | ☑️ | ☑️ | ☑️ |
| Test | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding Group | ☑️ | ☑️ | ☑️ | ☑️ |
| Risk Acceptance | ☑️ | ☑️ | ☑️ | ☑️ |
| Location | ☑️ | ☑️ | ☑️ | ☑️ |
| Component | ☑️ | | | |
| Note | ² | ☑️ | ☑️ | ☑️ |
| Benchmark | ² | | ☑️ | ☑️ |
| Language | ☑️ | ☑️ | ☑️ | ☑️ |
| Technology | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset API Scan Configuration | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset Tracking Files | ☑️ | ☑️ | ☑️ | ☑️ |
| Group | ☑️ | | ☑️ | ☑️ |

1. **Asset > Add**は、ロールが割り当てられているOrganization内に新しいAssetを作成することを意味します。
2. NotesおよびBenchmarksのViewは継承されます。親のEngagement、Test、Finding、またはAssetを表示できるロールは、そのNotesおよびBenchmarksも表示できます。これらのセルには、チェックボックスの代わりに**?**アイコンが表示されます。

**Group & Member Permissions**は、メンバーシップを管理できるユーザーを制御します。ここでの列は、View、Manage、Add、Add Owner、Edit、Deleteです。

| Row | Available actions |
| --- | --- |
| Organization Group, Asset Group | View, Add, Add Owner, Edit, Delete |
| Organization Member, Asset Member, Group Member | Manage, Add Owner, Delete |

**Global Feature Permissions**は、個々のOrganizationやAssetではなく、インスタンス全体のPro機能をゲートするものであるため、**ロールがグローバルロールとして保持されている場合にのみ有効になります**。Assetのメンバーシップとしてのみ使用されるロールにこれらを付与しても効果はありません。

| Row | Available actions |
| --- | --- |
| Report Template | View, Add, Edit, Delete |
| Generated Report | View, Add, Delete |
| Connector, Sensei, Asset Hierarchy, Version Manager, Tuner, Universal Parser, Rule, Integration | View, Edit |
| Mitigation Policy | Edit |
| Audit Log, Metering | View |

**Additional Permissions**は、View/Add/Edit/Deleteの形に当てはまらない機能のチェックリストです。

* **Configure Asset Notifications**: 単一のAssetがどの通知をどこに送信するかを選択します。
* **Import Scan Result**: スキャン結果をインポートおよび再インポートし、検出事項を作成・更新します。
* **Share Dashboard Layout**: ダッシュボードレイアウトを他のユーザーに公開します。Global Roleのみ。
* **Share Table Preference**: 保存されたテーブルビュー(列、フィルター、並べ替え順)を公開します。Global Roleのみ。
* **View Note History**: メモをいつ誰が変更したかを確認します。

### How to read the grid

![The read-only view of a role's permissions](images/pro_role_permissions_modal.png)

| What you see | What it means |
| --- | --- |
| An empty checkbox | 権限は存在するが付与されていない。クリックすると付与される。 |
| A checked checkbox | 付与済み。 |
| A shaded, empty cell | その行とアクションに対する権限が存在しない。選択不可。 |
| A **?** icon | Viewが親オブジェクトから継承されているため、ここで付与するものはない。 |
| A green ✔ (read-only view) | 付与済み。 |
| A red ✘ (read-only view) | 付与されていない。 |

各行において、最も左の権限(**View**、メンバー行の場合は**Manage**)が、その行の残りをゲートします。表示できないものを意味のある形で編集・削除することはできないため、その行の他のセルを利用可能にするには、まずこの権限を付与する必要があります。このゲートを解除すると、行の残りの部分も一緒に解除されます。

## Editing, cloning, and deleting

各行の**⋮**メニューには、**Edit Role**、**Clone Role**、**Delete Role**、**Role History**があります。

組み込みロールでは**Clone Role**のみが提供されます。スーパーユーザーを含め、誰もこれらを編集または削除することはできません。これにより、既知のベースラインが維持され、アップグレードの予測可能性が保たれます。

誰かに割り当てられたままのロールを削除しようとすると失敗します。まずそれらの割り当てを再割り当てまたは削除してから、ロールを削除してください。ここでの割り当てには、Organizationおよびassetのメンバーシップ(ユーザーとグループの両方)、Global Role、グループメンバーシップ、System Settingsのデフォルトグループロールが含まれます。

APIを使用すると、この再割り当てを1回の呼び出しで行うことができます。[APIを通じたロールの管理](#managing-roles-through-the-api)を参照してください。

## Assigning a custom role

カスタムロールは、組み込みロールと並んで、すべてのロールドロップダウンに表示されます。

| Where | How |
| --- | --- |
| **Global Role on a user** | ユーザーのフォームにある**Global Role**フィールド。スーパーユーザーのみ。[ユーザーの権限を設定する](../set_user_permissions/)を参照。 |
| **Global Role on a group** | グループのフォームにある**Global Role**フィールド。[権限の共有: ユーザーグループ](../create_user_group/)を参照。 |
| **Organization or Asset membership** | OrganizationまたはAssetのPermissionsダイアログ(ユーザーとグループの両方)。[Proでの権限設定](../pro_permissions_overhaul/)を参照。 |
| **Default group role** | System Settingsの**Default group role**。新規作成されたユーザーに適用されます。[デフォルト権限の管理](../about_perms_and_roles/#manage-default-permissions)を参照。 |
| **Role within a group** | グループのメンバーリストにあるロールドロップダウン。このドロップダウンには、少なくとも1つのGroup権限を付与するロールのみが表示されるため、Group権限を持たないロールはここに表示されません。 |

知っておくべき2つの制約があります。

* **Owner-tierは予約されています。** カスタムロールがOwner-tierのロールになることは決してありません。組み込みのOwnerのみがOwner-tierであり、そのため他のOwnerを管理する暗黙の権限を持つのもOwnerのみです。
* **他のユーザーにOwnerロールを付与するには、対応するAdd Owner権限が必要です**。これは、Organization、Asset、Groupのいずれで行う場合も同様です。

## What a custom Global Role unlocks

UIの一部は、個々の権限ではなく、最低限必要なGlobal Roleによってゲートされています。カスタムロールをこれらのゲートに対応させるため、DefectDojoはカスタムGlobal Roleを組み込みのティアと比較してランク付けします。カスタムロールは、その権限が**完全に**カバーする最高位のティアを獲得します。

* Maintainerが付与するすべてをカバーするカスタムロールは、それらのゲートに対してMaintainerとして扱われます。
* Writerが付与するすべてをカバーする場合は、Writerとして扱われます。Readerも同様です。
* いずれも完全にカバーしない場合、ティアは獲得されません。個々の権限は付与されたとおりに機能しますが、ティアベースのUIゲートは閉じたままになります。
* **Ownerはこの方法では決して獲得できません。** ロール管理、およびOwner Global Roleによってゲートされているその他すべては、スーパーユーザーと組み込みのOwnerに留まります。

カバレッジは完全である必要があり、これは時に人を驚かせます。Maintainerから複製されたロールはMaintainerティアを獲得します。しかし、Maintainerの権限を手作業で再現する際に1つでも見落とすと、そのロールはWriterティアになってしまいます。カスタムGlobal Roleに期待したUIが表示されない場合は、[操作権限チャート](../user_permission_chart/)の組み込みティアと比較してください。

## Role history

カスタムロールは監査証跡を保持します。ロールの**⋮**メニューから**Role History**を開くと、どの権限が誰によっていつ付与または取り消されたか、およびロールの保有者の変更を確認できます。

この履歴に表示されない2つのことがあります。ロール自体の名前や説明の変更、および組み込みロールの権限(これらはシード投入されたもので編集されることがないため、履歴は生成されません)です。

ロール履歴は読み取り専用であるため、Custom Roles機能のオン/オフに関わらず利用できます。

## Managing roles through the API

ロールは`/api/v2/roles/`で利用できます。クライアントはドロップダウンにロール一覧を表示する必要があるため、読み取りはすべての認証済みユーザーに開放されています。書き込みには、スーパーユーザーステータスまたは組み込みのOwner Global Roleに加え、Custom Roles機能フラグが必要です。

| Operation | Request |
| --- | --- |
| List roles | `GET /api/v2/roles/` |
| Retrieve one role | `GET /api/v2/roles/{id}/` |
| List every grantable permission | `GET /api/v2/roles/permissions_catalog/` |
| Create a role | `name`、任意の`description`、`permissions`リストを指定して`POST /api/v2/roles/` |
| Replace a role's permissions | `permissions`リストを指定して`PATCH /api/v2/roles/{id}/` |
| Clone a role | 任意の`name`と`description`を指定して`POST /api/v2/roles/{id}/clone/` |
| Delete a role | `DELETE /api/v2/roles/{id}/` |
| Delete a role and move its assignments | `DELETE /api/v2/roles/{id}/?reassign_to={other_role_id}` |
| Read a role's history | `GET /api/v2/roles/{id}/history/` |

Notes:

* `permissions`は、ロールの権限リストに追加するのではなく、**置き換えます**。ロールに最終的に持たせたい完全なセットを送信してください。
* `?reassign_to=`は、削除されるロールのすべての割り当てを、指定したロールへ1つのトランザクションで移動します。これは一括で再割り当てを行う唯一の方法であり、UIにはこの機能はありません。
* 組み込みロールの編集または削除を試みると`403`が返されます。不明な権限値の編集、既存のロール名の再利用、`reassign_to`を指定せずに使用中のロールを削除しようとすると、説明付きの`400`が返されます。
* `is_owner`はAPIから設定できません。送信しても受理されますが無視されます。

## Things to know

* **同一オブジェクトに複数のロールがある場合、それらの権限の和集合が付与されます。** ユーザーがAssetに直接ロールを保有し、グループを通じて別のロールを継承している場合、いずれかのロールが付与するすべての権限を得られます。ロールは権限を追加するだけで、決して削除しません。
* **権限の変更は、現在の画面には即座に反映されず、次回のページ読み込み時に反映されます。** バックグラウンドジョブは最大30秒、キャッシュされた権限データは最大5分かかって編集内容を反映します。
* **ロールドロップダウンには最大250件のロールが表示されます。** それを超えると、一部のロールはドロップダウンに表示されなくなりますが、引き続き機能します。
* **MaintainerとOwnerはOrganizationを追加できますが、グリッドにはそれが表示されません。** これら2つのロールでは、その権限はグローバルスコープの付与として保存されており、グリッドはオブジェクトスコープの付与のみを読み取るため、**Organization > Add**セルは付与されていないと表示されます。いずれかのロールを複製すると、この権限は保持されます。
* **用語はインスタンスの設定に従います。** 本ドキュメントではデフォルトのラベルであるOrganizationとAssetを使用しています。インスタンスでOrganization / Assetのリラベリングがオフになっている場合、同じ行はProduct TypeとProductと表示されます。
* **Rolesページは、それ以外のユーザーにとっては読み取り専用です。** `/settings/roles`に直接アクセスしたユーザーはロールとその権限を見ることができますが、何も変更できません。権限データは機密性が高いものではなく、実際の境界はすべての書き込み時にサーバー側で強制されます。
