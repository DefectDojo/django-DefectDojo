---
title: ユーザー管理
description: DefectDojoにおけるユーザー、アクセス制御、認証の管理
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

DefectDojoのユーザー管理画面は、エディションごとに異なります。お使いの環境に該当するセクションを選択してください。

## DefectDojo Open-Source

オープンソース版のDefectDojoは**認可済みユーザー**モデルを採用しています。ユーザーは、対象のProductまたはProduct Typeの認可済みユーザーリストに追加されることでアクセス権を得ます。スーパーユーザーとスタッフはすべてを閲覧できます。

* [認可済みユーザー](./os__authorized_users/) — ProductとProduct Typeへのアクセス権を付与する方法

オープンソース版のDefectDojoにおける認証は、ローカルのユーザー名/パスワードとパスワードリセットフローによって行われます。

## DefectDojo Pro

DefectDojo Proは、メンバー、グループ、グローバルロールによるロールベースのシステムを採用しています。ユーザーには、SAMLまたはサポートされているOAuthプロバイダーの1つを通じてSSOアクセスを付与することもできます。

* [DefectDojoにおける権限](./about_perms_and_roles/) — ロール、メンバーシップ、グローバルロール、設定権限の概要
* [ユーザーの権限を設定する](./set_user_permissions/) — ロール、グローバルロール、設定権限の割り当て
* [権限を共有する: ユーザーグループ](./create_user_group/) — 多数のユーザーに一括で権限を割り当てる
* [Proでの権限設定](./pro_permissions_overhaul/) — メンバーと権限を管理するためのPro専用UI
* [ユーザー認証情報の一括リセット](./pro__resetting_user_credentials/) — 多数のユーザーのAPIトークンをローテーションし、パスワードの再設定を強制する
* [操作権限チャート](./user_permission_chart/) — すべての組み込みロールにおけるすべての権限の完全なリファレンス
* [カスタムRBACロール](./pro__custom_rbac_roles/) — 個別の権限を選択して独自のロールを構築する
* [シングルサインオン](/admin/sso/) — ProにおけるSAMLおよびOAuthの設定

## エディション間の移行

オープンソース版の認可済みユーザーからProのRBACへ移行する場合や、RBACを使用していた3.0より前のオープンソース版から現在の認可済みユーザーモデルにアップグレードする場合は、[3.0アップグレードノート](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization)を参照してください。既存のアクセス権は自動的に保持されます。
