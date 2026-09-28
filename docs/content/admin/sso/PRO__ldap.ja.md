---
title: LDAP認証
description: DefectDojo ProでLDAP認証を設定する
weight: 20
audience: pro
aliases:
- /ja/en/open_source/ldap-authentication
---

DefectDojo Proは**Enterprise Settings**のUIからLDAP認証をサポートしています。カスタムのDockerイメージや設定ファイルは不要です。

このページの他のプロバイダーと異なり、LDAPはリダイレクト方式のフローではありません。ユーザーは標準のDefectDojoのユーザー名・パスワードフォームでサインインし、その資格情報がディレクトリと照合されます。追加のログインボタンはありません。

## Configuration

**Enterprise Settings > LDAP Settings**を開きます。

![image](images/sso_ldap_settings.png)

1. **Server URI** — 接続先のディレクトリ(例: `ldaps://ldap.example.com:636`)。
   `ldaps://`の使用を推奨します。平文の`ldap://`を使わざるを得ない場合は、資格情報を送信する前に接続をアップグレードするよう、下記の**Use StartTLS**を有効にしてください。
2. **Bind DN** — ユーザーの検索に使用するサービスアカウントの識別名(DN)。
   匿名バインドの場合は空欄のままにします。
3. **Bind Password** — そのサービスアカウントのパスワード。保存済みの値がブラウザに返されることはありません。すでに保存したパスワードを維持する場合は、このフィールドを空欄のままにします。
4. **User Search Base** — ユーザーエントリを検索する起点となるDN(例: `ou=people,dc=example,dc=com`)。
5. **User Search Filter** — ユーザーを特定するために使用するフィルタ。送信されたユーザー名に置き換えられるプレースホルダ`%(user)s`を、リテラルとして**必ず**含める必要があります。一般的な値は、OpenLDAPでは`(uid=%(user)s)`、Active Directoryでは`(sAMAccountName=%(user)s)`です。
6. **User Attribute Mapping** — 下記を参照してください。
7. **Enable LDAP**をチェックして有効化します。

**Validate Config**を使うと、設定を保存せずに確認できます。設定の完全性、サーバーへの到達可否、バインドの成否、検索ベースが解決するかどうか、属性マッピングが使用可能に見えるかどうかを報告します。

## User Attribute Mapping

各行は、1つの**LDAP Attribute**を、それが値を設定すべき**DefectDojo Field**にマッピングします。行を追加するには**Add Attribute Mapping**を、削除するにはゴミ箱アイコンを使用します。

![image](images/sso_ldap_attribute_mapping.png)

- **LDAP Attribute**は自由入力のテキストで、ディレクトリが実際に返す属性と一致している必要があります。たとえばOpenLDAPでは`uid`、`givenName`、`sn`、`mail`、Active Directoryでは`sAMAccountName`、`givenName`、`sn`、`mail`です。
- **DefectDojo Field**は一覧から選択します: **Username**、**First Name**、**Last Name**、**Email**。
- ある属性を**Email**にマッピングすることを強く推奨します。DefectDojoは通知にメールアドレスを使用します。
- 同じ属性を複数のフィールドに使うことができます。各DefectDojoフィールドにマッピングできる属性は1つだけです。
- マッピングをまったく行わない場合、アカウントは名前やメールアドレスなしで作成されます。

**Always Update User**は、マッピングがいつ適用されるかを制御します。有効な場合(デフォルト)、マッピングされた属性はログインのたびにディレクトリから再取得されるため、LDAP側での名前やメールアドレスの変更がDefectDojoに反映されます。無効な場合、アカウントの初回作成時にのみ適用されます。

## グループマッピング

DefectDojoは、ログイン時にユーザーのLDAPグループをDefectDojoグループにミラーリングできます。**Enable Group Mapping**をチェックすると設定が表示されます。

![image](images/sso_ldap_group_mapping.png)

- **Group Search Base** — グループエントリを検索する起点となるDN(例: `ou=groups,dc=example,dc=com`)。グループマッピングが有効な場合は必須です。
- **Group Type** — ディレクトリがメンバーシップをどのようにモデル化しているか。OpenLDAPとActive Directoryには**groupOfNames**、その他**groupOfUniqueNames**や**posixGroup**から選択します。
- **Group Limiter Regex Expression** — この式に名前が一致するグループのみがミラーリングされます。すべて許可する場合は`.*`を、DefectDojoに管理させたいグループのみをミラーリングする場合は`^dd-`のようなプレフィックスを使用します。

グループがまだ存在しない場合は、初回使用時に作成されます。新しく作成されたグループには、スーパーユーザーが設定するまで権限がありません。[User Groups](../../user_management/create_user_group/)を参照してください。

## その他のオプション

* **Use StartTLS** — バインドの前に、平文の`ldap://`接続をTLSにアップグレードします。URIがすでに`ldaps://`の場合は不要です。
* **Always Update User** — マッピングされた属性を、ログインのたびにディレクトリから再取得します。

## トラブルシューティング

まず**Validate Config**を実行してください。多くの場合、問題を直接特定できます。それ以外に、以下のようなケースがあります。

**すべてのログインが失敗するが、ディレクトリには到達できる。** **User Search Filter**に`%(user)s`が含まれていること、そこで使われている属性がユーザーが実際に入力するものと一致していることを確認してください。`(uid=%(user)s)`というフィルタは、ユーザーがActive Directoryの`sAMAccountName`でログインしている場合には決して一致しません。

**ログインは成功するが、アカウントに名前やメールアドレスがない。** **User Attribute Mapping**が空であるか、左側のLDAP属性名がディレクトリの返す値と一致していません。

**LDAP側で名前が変わったが、DefectDojoには反映されない。** **Always Update User**が無効になっているため、マッピングはアカウント作成時にのみ適用されています。

**ログイン試行がハングする、または遅い。** 接続と検索にはタイムアウトが設定されているため、到達できないディレクトリは無期限にブロックされるのではなく失敗します。**Validate Config**の**Server Reachability**を確認し、DefectDojoホストからポートが開いていることを確認してください。
