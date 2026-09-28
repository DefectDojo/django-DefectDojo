---
title: ルールのスケジュール設定
description: Rules Engineのルールを、繰り返しまたは単発のスケジュールで自動実行する
weight: 2
audience: pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Rules Engine SchedulingはDefectDojo Pro限定機能です。</span>

ルールは、毎回手動でトリガーする代わりに、自動的に実行されるようスケジュールできます。スケジュールされたルールは、設定された時刻に、そのフィルター条件に一致するすべてのFindingに対して実行されます。

Schedulingはデフォルトでは無効になっており、Feature Flagsページからではなく、DefectDojoによってインスタンスごとに有効化されます。**Scheduling Service**を有効にするには[DefectDojo Support](mailto:support@defectdojo.com)にお問い合わせください。有効化されると**Schedule Rule**オプションが表示されるようになります。DefectDojoが一元管理する機能がどのように表示されるかについては、[Feature Flags](/admin/feature_flags/pro__feature_flags/)を参照してください。

スケジュールを設定するユーザーは、**Change Scheduling Service Schedule**の設定権限を持っている必要があります。

## スケジュールの種類

### Single Run（単発実行）

Single Runスケジュールは、指定した日時に1回だけルールを実行します。実行が完了すると、そのスケジュールが繰り返されることはありません。

### Repeated Run（繰り返し実行）

Repeated Runスケジュールを使用すると、例えば毎日午前9:00や毎週月曜日の15:00など、定期的にルールをトリガーできます。

**注:** Rules Engineのスケジュールは15分単位に制限されています。cronスケジュールの分フィールドは**0、15、30、45**のいずれかでなければなりません。それ以外の分の値は使用できません。

有効なスケジュールの例:
- 毎時0分: `0 * * * *`
- 毎日午前9:15: `15 9 * * *`
- 毎週月曜日の午後3:00: `0 15 * * 1`
- 15分ごと: `0,15,30,45 * * * *`

## ルールのスケジュールを作成する

1. サイドバーの**Rules Engine**メニューから**All Rules**ページに移動します。
2. スケジュールしたいルールを見つけ、そのアクションメニュー（**⋮**）を開きます。
3. **Schedule Rule**をクリックします。このオプションは、Scheduling Serviceが有効になっており、かつ必要な権限を持っている場合にのみ表示されます。
4. **Schedule Rule**モーダルで、以下のフィールドを入力します。

| Field | Description |
|---|---|
| **Name** | このスケジュールの一意の名前（必須、最大100文字）。 |
| **Description** | スケジュールの目的についての任意の説明。 |
| **Trigger Type** | 1回限りの実行には**Single Run**を、繰り返しのcronスケジュールには**Repeated Run**を選択します。 |
| **Frequency** | Repeated Runの場合: cronビルダーを使用して、期間（毎時、毎日、毎週など）と、具体的な分・時・日の値を選択します。Single Runの場合: 日付ピッカーを使用して日時を選択します。 |
| **Enable Schedule** | スケジュールを有効化または無効化するトグルです。無効化されたスケジュールは、再度有効化されるまで実行されません。 |

5. **Submit**をクリックしてスケジュールを保存します。ルールは次にスケジュールされた時刻に自動的に実行されます。


## 権限

Rules Engine内のスケジュール機能へのアクセスには、Superuser権限または適切なConfiguration Permissionが必要です。詳細については、[User Permission Chart](/admin/user_management/user_permission_chart)を参照してください。
