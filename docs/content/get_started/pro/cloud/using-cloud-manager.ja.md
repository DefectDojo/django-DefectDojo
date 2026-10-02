---
title: Cloud Managerの使用
description: サブスクリプションとアカウント設定を管理する
weight: 1
collapsed: true
audience: pro
aliases:
- /ja/en/cloud_management/using-cloud-manager
---

DefectDojoのCloud Managerにログインすると、アカウント設定を構成し、DefectDojo Cloudのサブスクリプションを管理できます。

## **新規サブスクリプション**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

このページでは、DefectDojoに新規、または[追加の](../additional-cloud-instance/)Cloudインスタンスをリクエストできます。

## **サブスクリプションの管理**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

Subscription Managementページには、現在アクティブなすべてのCloudインスタンスが表示され、各インスタンスのFirewall設定を構成できます。

### Firewall設定の変更
![image](images/using_the_cloud_manager.png)

**Edit Subscription**ページで、追加したいルールのIP Address、Mask、Labelを入力します。複数のFirewallルールが必要な場合は、**Add New Range**をクリックして新しい空のルールを作成します。

![image](images/using_the_cloud_manager_2.png)

ここでは、外部サービス(GitHub & Jira Cloud)にファイアウォールを開放することもできます。また、希望する場合はメニューから**Proceed Without Firewall**を選択して、ファイアウォールを完全に無効化することもできます。

## Cloud Portalへの追加ユーザーの登録

Cloud Portal / DefectDojoサブスクリプションの管理権限を複数のユーザーに与えたい場合、このフォームを使用してユーザーを追加できます。追加したいユーザーは、cloud.defectdojo.comで自分自身のCloud Portalアカウントを作成済みである必要があります。DefectDojoインスタンス上にアカウントがあるだけでは不十分です。

![image](images/using_the_cloud_manager_5.png)

ユーザーのCloud Portalアカウントに関連付けられたメールアドレスを入力し、Submitをクリックしてリンク済みユーザーのリストに追加します。これでそのユーザーはCloud PortalとDefectDojoサブスクリプションを管理できるようになります。

## Resources
<https://cloud.defectdojo.com/resources/>

Resourcesページには、サポートチームに連絡するためのContact Usフォームがあります。

![image](images/using_the_cloud_manager_3.png)

## Tools
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

Toolsページは、Universal ImporterやDefectDojo CLIなどの外部Proツールをダウンロードできる場所のひとつです。これらのツールは外部アドオンであり、ネットワーク内でコマンドラインのインポートパイプラインを迅速に構築するために使用できます。これらのツールの詳細については、[External Tools](/import_data/pro/specialized_import/external_tools/)のドキュメントを参照してください。

![image](images/using_the_cloud_manager_6.png)


## Account Settings
<https://cloud.defectdojo.com/accounts/settings>

Account Settingsページには4つのセクションがあります。

* **User Contact**では、Username、Email Address、First Name、Last Nameを設定できます。
* **Email Accounts**では、アカウントに追加のメールアドレスを登録できます。メールアドレスを追加すると、その新しいアドレスに確認メールが送信されます。
* **Manage Social Accounts**では、DefectDojo CloudをGitHubまたはGoogleの認証情報に接続でき、ユーザー名とパスワードの代わりにログインに使用できます。
* **MFA Settings**では、Google Authenticator、1Passwordなどのアプリに MFAコードを追加できます。ログインプロセスに追加のステップを設けることは、不正アクセスを防ぐための有効な予防策です。

### Cloud PortalログインへのMFAの追加
<https://cloud.defectdojo.com/settings/mfa/configure/>

これはDefectDojo Cloudログインにのみ MFAを追加するものであり、DefectDojoアプリ側のログインには適用されない点にご注意ください。

![image](images/using_the_cloud_manager_4.png)

1. まず、スマートフォンまたはコンピューター上でQRコード認証に対応したAuthenticatorアプリをインストールします。
2. インストールが完了したら、**Generate QR Code**をクリックします。
3. AuthenticatorアプリでDefectDojoに表示されたQRコードをスキャンし、アプリに表示された6桁のコードを入力します。
4. **Enable Multi-Factor Authentication**をクリックします。
