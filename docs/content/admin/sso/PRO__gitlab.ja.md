---
title: GitLab
description: DefectDojo ProでGitLab SSOを設定する
weight: 9
audience: pro
---

DefectDojo ProはGitLabによるログインをサポートしています。オープンソース版のDefectDojoにはSSOは含まれていません。オープンソース版のアクセス制御については[Authorized Users](/admin/user_management/os__authorized_users/)を参照してください。

## Prerequisites

DefectDojoを設定する前に、GitLabで以下の手順を完了してください。

1. GitLabプロフィールのApplicationsページに移動します。
   - GitLab.com: `https://gitlab.com/profile/applications`
   - セルフホスト: `https://your-gitlab-host/profile/applications`

2. 新しいアプリケーションを作成します。
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. アプリケーションから**Application ID**と**Secret**を控えます。

## Configuration

DefectDojoで**Enterprise Settings > OAuth Settings**に移動し、**GitLab**を選択してフォームに入力します。

- **GitLab OAuth Key** — **Application ID**を入力します
- **GitLab OAuth Secret** — **Secret**を入力します
- **GitLab API URL** — GitLabインスタンスのベースURLを入力します(例: `https://gitlab.com`)

**Enable GitLab OAuth**をチェックしてフォームを送信します。ログインページに**Login With GitLab**ボタンが表示されます。
