---
title: 設定メニュー
description: DefectDojo Proサイドバーの設定セクションの構成、All Settingsディレクトリページ、および現在のレイアウトと以前のレイアウトの切り替え方法について
weight: 6
audience: pro
---

サイドバーの設定セクションには、DefectDojo Proのすべての管理ページがグループ化されています。表示されるレイアウトは、インスタンスがいつ作成されたかによって異なります。

- **新規インストール**では、以下で説明する再編成後のレイアウトが表示されます。
- **既存のインストール**では、管理者が**Menu 2.0**を有効にするまで（[レイアウトの切り替え](#switching-layouts)を参照）、以前のレイアウトが維持されます。

どちらの場合でも、**すべての設定ページは同じURLを維持します**。ブックマークや保存済みのリンク、自分自身のRunbookに記載したものは、どちらのレイアウトが有効であっても引き続き機能します。

## 再編成後のレイアウト

Settingsは7つのグループに分かれており、システムのどの部分に関わるかではなく、何をしたいかに基づいて名付けられています。

| グループ | 含まれるもの |
| --- | --- |
| **System** | System Settings、Appearance、Announcement Banner、Login Banner、E-mail、Feature Flags |
| **Users & Permissions** | Users、Groups、Roles |
| **Finding Workflow** | 3つのDeduplicationページ、Finding Enrichment、Service Level Agreements、Prioritization Engines、Mitigation Policies |
| **Configuration** | Environments、Regulations、Note Types、Test Types、CI/CD Infrastructure、Tool Types、Tool Configurations |
| **Notifications** | Notification Events、Notification Webhooks |
| **Operations** | Audit Logs、Usage Logs、Schedules、Celery Status、および — DefectDojo Cloudでは — Message Portal、Firewall Rules、Maintenance Windows |
| **License & Support** | License Manager、Version Manager、Contact Support |

表示されるのは、自分のアカウントに開く権限がある項目だけであり、そのグループ内のページが1つも利用できない場合、グループ自体が表示されなくなります。

知っておくと良い2つの規則があります。

- **独立した「New」項目はありません。** 各一覧ページには作成フォームを開く**New**ボタンがあるため、メニューには1つのカタログにつき2つではなく1つの項目のみが表示されます。アカウントにレコードの一覧表示権限はないが作成権限がある場合、メニュー項目は直接作成フォームへ移動します。
- **グループの下に2階層以上ネストされることはありません。** ページへの到達は、最大でもSettings → グループ → ページの階層で済みます。

## All Settings

セクションの最初の項目である**All Settings**を開くと、自分のアカウントがアクセスできるすべての設定ページのディレクトリが表示されます。メニューと同じグループで並んでおり、名前やページの機能で検索できます。`deduplication`で検索すると、3つの重複排除ページ*に加えて*System Settingsも見つかります。System Settingsにも重複排除のオプションが含まれているためです。

最後のカテゴリである**Elsewhere in the app**には、DefectDojoを設定するページのうち、サイドバーの他のセクションにあるもの（認証プロバイダー、Login and MFA設定、Jiraインスタンス、Upstream/Downstreamコネクタ、Universal Parser）が一覧表示されます。各タイルには、それが属するセクションを示すチップが付いています。

## 移動した項目

以前のレイアウトに慣れている方向けの対応表です。

| 以前 | 現在 |
| --- | --- |
| Settings → *(トップレベル)* → Feature Flags | Settings → System → Feature Flags |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → E-mail Settings | Settings → System → E-mail |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(3ページ)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(参照データのカタログ)* | Settings → Configuration → *(変更なし)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(クラウド関連ページ)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

ライセンスパッケージにちなんで名付けられていたグループ（Proインスタンスでは**Pro Settings**、Enterpriseインスタンスでは**Enterprise Settings**）は、もう存在しません。そのページは、System、Finding Workflow、Notifications、Operationsに分散配置されています。

## レイアウトの切り替え

[Feature Flags](/admin/feature_flags/pro__feature_flags/)ページの**Menu 2.0**が、どちらのレイアウトを有効にするかを制御します。オン/オフを切り替えると、サイドバーは即座に再構成されます。再起動は不要で、インスタンスの他の部分に変更が生じることもありません。

新規インストールではデフォルトでオンになっています。既存のインストールではデフォルトでオフになっているため、アップグレードによってチームの作業中にメニューが勝手に変わることはありません。管理者の準備が整ったタイミングでオンにしてください。

オフの状態では、**All Settings**ページは利用できず、そのURLはNot Foundを返します。
