---
title: GitHub Enterprise
description: DefectDojo ProでGitHub Enterprise SSOを設定する
weight: 7
audience: pro
---

DefectDojo ProはGitHub Enterpriseによるログインをサポートしています。オープンソース版のDefectDojoにはSSOは含まれていません。オープンソース版のアクセス制御については[Authorized Users](/admin/user_management/os__authorized_users/)を参照してください。

## Prerequisites

DefectDojoを設定する前に、GitHub Enterpriseで以下の手順を完了してください。

1. GitHub Enterprise Serverで[新しいOAuthアプリを作成](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app)します。

2. アプリケーションの名前を選びます(例: `DefectDojo`)。

3. **Redirect URI**を設定します。
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. アプリから**Client ID**と**Client Secret**を控えます。

## Configuration

DefectDojoで**Enterprise Settings > OAuth Settings**に移動し、**GitHub Enterprise**を選択してフォームに入力します。

- **GitHub Enterprise OAuth Key** — **Client ID**を入力します
- **GitHub Enterprise OAuth Secret** — **Client Secret**を入力します
- **GitHub Enterprise URL** — 組織のGitHub URLを入力します(例: `https://github.yourcompany.com/`)
- **GitHub Enterprise API URL** — 組織のGitHub API URLを入力します(例: `https://github.yourcompany.com/api/v3/`)

**Enable GitHub Enterprise OAuth**をチェックしてフォームを送信します。ログインページに**Login With GitHub**ボタンが表示されます。
