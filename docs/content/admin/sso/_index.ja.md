---
title: シングルサインオン
description: DefectDojo Pro はシングルサインオンのために SAML と幅広い OAuth プロバイダーをサポートしています
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2026-04-30 00:00:00+00:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
pro-feature: true
aliases:
- /ja/admin/user_management/configure_sso/
- /ja/admin/sso/os__saml/
- /ja/admin/sso/os__auth0/
- /ja/admin/sso/os__azure_ad/
- /ja/admin/sso/os__github_enterprise/
- /ja/admin/sso/os__gitlab/
- /ja/admin/sso/os__google/
- /ja/admin/sso/os__keycloak/
- /ja/admin/sso/os__oidc/
- /ja/admin/sso/os__okta/
- /ja/admin/sso/os__remote_user/
---

シングルサインオンは **DefectDojo Pro** の機能です。DefectDojo 3.0 以降、SAML、OIDC、バンドルされた OAuth プロバイダーを含む SSO 機能一式は DefectDojo Pro でのみ利用可能です。オープンソース版の DefectDojo は、ローカルのユーザー名/パスワードによるログインとパスワードリセットのフローを使用します。

オープンソース版の DefectDojo を使用していて SSO が必要な場合は、[DefectDojo Pro](https://defectdojo.com) への切り替えが必要です。移行手順については [3.0 upgrade notes](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only) を参照してください。アップグレード時、既存のユーザーアカウントとグループメンバーシップは維持されます。オープンソース版 DefectDojo のアクセス制御については、[Authorized Users](/admin/user_management/os__authorized_users/) ページを参照してください。

## Seeing what is configured

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** は、サポートされているすべてのプロバイダーを 1 つのページに一覧表示し、どれが設定済みか、どれが有効か、それぞれがどのプロトコルを話すかを示すとともに、各プロバイダーの設定フォームに直接移動できます。特定のプロバイダーを設定するのではなく、このインスタンスの状態を確認したい場合はここから始めてください。

## Supported SSO providers (DefectDojo Pro)

DefectDojo Pro は SAML と、次の OAuth プロバイダーをサポートしています。各ガイドでは、プロバイダー側の設定手順と、それに対応する Pro の **Enterprise Settings** UI での設定を説明しています。

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**
* **[LDAP](/admin/sso/pro__ldap/)**

## Provisioning users from your directory (DefectDojo Pro)

上記のプロバイダーは、誰がサインインできるかを決定します。**[SCIM Provisioning](/admin/sso/pro__scim/)** はアカウント一覧自体をディレクトリと同期させ、ユーザーが加入したときに作成し、詳細が変更されたときに更新し、離脱したときに(API トークンとともに)無効化します。

DefectDojo Pro における SSO の設定は **Superuser** のみが行えます。

**DefectDojo Pro をご利用の場合:** SSO を設定する前に、SAML または SSO サービスの IP アドレスをファイアウォールのホワイトリストに追加してください。詳細は [Firewall Rules](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) を参照してください。

## Disabling Username / Password login

DefectDojo Pro で SSO を設定したら、従来のユーザー名/パスワードのログインフォームを無効にしたい場合があります。**Enterprise Settings > Login Settings** で **Allow Login via Username and Password** のチェックを外してください。

![image](images/pro_login_settings.png)

### Login fallback

SSO の連携が機能しなくなった場合でも、DefectDojo の URL に以下を追加することで、常に標準のログインフォームに戻ることができます。

`/login?force_login_form`

フォールバックとして、ユーザー名とパスワードを設定した管理者アカウントを少なくとも 1 つ保持しておくことをお勧めします。
