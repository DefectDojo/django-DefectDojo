---
title: Sensei リファレンス
description: ステータス、行アクション、クォータ、トラブルシューティング
draft: false
audience: pro
weight: 5
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Sensei は DefectDojo Pro 限定機能であり、現在 BETA(ベータ版)です。</span>

Sensei を使用する際に目にするステータス、アクション、制限事項についてのクイックリファレンスです。

## リポジトリのステータス

Sensei ハブでオンボーディングされたリポジトリに表示されるステータスです。

| ステータス | 意味 |
|--------|---------|
| **Active** | オンボーディング済みでスキャン可能な状態です。 |
| **Pull Request Open** | Sensei がリポジトリに対してオープンなプルリクエストを持っています。 |
| **Pull Request Closed** | Sensei のプルリクエストがクローズされました。 |
| **Error** | 直前の操作が失敗しました。根本原因については Scan Activity を確認してください。 |
| **Not Configured** | リポジトリは接続済みですが、まだ設定されていません。 |

## 候補と修正のステータス

自動修正候補と修正レコードは、次の状態を経て遷移します。

| ステータス | 意味 |
|--------|---------|
| **Candidate** | スキャンの自動修正条件によってステージングされました。承認するまで何も実行されません。 |
| **In Progress** | 承認済みです。Sensei が修正を生成しており、プルリクエストを開く予定です。 |
| **PR Open** | 修正のプルリクエストが開いています。バッジからリンクされます。 |
| **Failed** | 修正を完了できませんでした。黙って消えてしまわないよう、一覧に残り続けます。 |

## リポジトリの行アクション

オンボーディングされた各リポジトリには、Sensei ハブに行アクションメニューがあります。

![リポジトリの行アクション](images/repo_row_menu.png)

- **Scan now:** オンデマンドスキャンを開始します(ブランチピッカーが開きます)。
- **Scan history:** このリポジトリの過去のスキャンを表示します。
- **Configure:** 設定フォーム(PR レポート、自動修正、製品との紐付け)を再度開きます。
- **Re-stage candidates:** リポジトリの検出事項を自動修正条件に対して再評価し、新しい候補をステージングします。
- **Delete:** リポジトリを Sensei から削除します。これによりスキャンは停止しますが、基になるアセットや検出事項が削除されるわけではありません。

## クォータとメータリング

Sensei は DefectDojo Pro ライセンスに対してメータリングされ、ハブの上部にメーターとして表示されます。

- **Fixes:** 事前契約した上限に対して適用された修正数です。候補の承認または修正のトリガーは、このクォータを消費します。使い切ると、上限が引き上げられるまでそれ以上の修正がブロックされます(警告バナーが表示されます)。
- **Onboarded Repositories:** リポジトリの上限に対してオンボーディングされたリポジトリ数です。上限に達すると、新しいリポジトリのオンボーディングがブロックされます。

上限を引き上げるには、DefectDojo のアカウントチームにお問い合わせください。

## GitLab 固有の情報

GitLab は GitHub と並んでサポートされています(gitlab.com およびセルフマネージド)。スキャンと修正の動作は同一であり、以下は GitLab 固有の詳細です。

- **Connection:** GitHub App ではなく、**`api`** および **`write_repository`** スコープを持つ**プロジェクトまたはグループアクセストークン**(ロールは **Developer**、プッシュルールで要求される場合は **Maintainer**)。[Sensei のセットアップ](/sensei/setup_sensei/#connect-gitlab) を参照してください。
- **Webhook:** オンボーディングされた各プロジェクトには、`…/sensei/gitlab/webhooks` への webhook(接続のシークレット付き)が必要で、**Push**、**Merge request**、**Comment** イベントを購読します。webhook を追加するには、プロジェクトに対する **Maintainer**/**Owner** 権限が必要です。
- **プルリクエストではなくマージリクエスト:** 修正はデフォルトブランチに対して **マージリクエスト** を開きます。`/fix` コメントはマージリクエストのノートで機能します。
- **コミットステータスによるゲート:** PR のステータスチェックは、マージリクエストのヘッドコミットに対する GitLab の **コミットステータス** です。スキャン中は `running`、その後 `success` または `failed`(fail-on-new)になります。GitLab には *neutral* 状態がないため、検出事項が残っている**非ゲーティング**のスキャンは**緑色**のステータスになります。詳細はサマリーノートに記載されます。
- **セルフマネージド:** **GitLab Base URL** を自分のインスタンスに設定してください。DefectDojo はそのホストに対してクローンと API 呼び出しを行います。

## Bitbucket 固有の情報

Bitbucket **Cloud** および **Server/Data Center** がサポートされています。スキャンと修正の動作は同一であり、以下は Bitbucket 固有の詳細です。

- **Connection:** **OAuth**(推奨)、Atlassian の **API トークン**(アカウントのメールアドレスと併用)、またはリポジトリ/ワークスペースの**アクセストークン**。[Sensei のセットアップ](/sensei/setup_sensei/#connect-bitbucket) を参照してください。アプリパスワードは非推奨でありサポートされていません。
- **ワークスペースのスコープ(Cloud):** API/アクセストークンはワークスペースに紐付いているため、Cloud では**ワークスペース**が必須です。OAuth はユーザーコンテキストであり、アクセス可能なワークスペースを自動的に検出します。
- **Webhook:** オンボーディングされた各リポジトリには、`…/sensei/bitbucket/webhooks` への webhook(接続のシークレットを使用し、HMAC-SHA256 の `X-Hub-Signature` で検証)が必要で、**Push**、**Pull request**(created/updated/merged/declined)、**Pull request comment** イベントを購読します。
- **ビルドステータスによるゲート:** PR のステータスチェックは、ヘッドコミットに対する Bitbucket の**ビルドステータス**として投稿されます(`INPROGRESS` → `SUCCESSFUL`/`FAILED`)。Bitbucket には *neutral* 状態がないため、非ゲーティングのスキャンは `SUCCESSFUL` にマッピングされ、詳細はサマリーコメントに記載されます。ビルドステータスのリンクは公開 URL である必要があるため、DefectDojo のホストが使用されます。
- **リポジトリ名:** `workspace/repo`(Cloud)または `PROJECTKEY/repo`(Server/Data Center)。
- **Server/Data Center:** **Base URL** を自分のホストに設定してください。DefectDojo は v1.0 REST API と `/scm/…` の git パスを使用します。

## Azure DevOps 固有の情報

Azure DevOps Repos は **個人用アクセストークン** を通じてサポートされています。スキャンと修正の動作は同一であり、以下は Azure 固有の詳細です。

- **Connection:** **Code (Read, Write, & Manage)** スコープを持つ **PAT** と、**organization**。Azure DevOps の OAuth アプリは廃止が予定されているため、PAT が推奨される認証情報です。[Sensei のセットアップ](/sensei/setup_sensei/#connect-azure-devops) を参照してください。
- **Webhook:** Azure の **Service Hooks** は(HMAC ではなく)HTTP **Basic** で認証し、**イベントごとに1つのサブスクリプション**を使用します。接続の Basic ユーザー名/パスワードを使用して、**Code pushed** および **Pull request created/updated/merged** 用に `…/sensei/azure/webhooks` へのサブスクリプションを作成します。
- **コミットステータスによるゲート:** PR のステータスチェックは、ヘッドコミットに対する Git の**コミットステータス**として投稿されます。
- **リポジトリ名:** `project/repo`(organization は接続情報に保存されます)。
- **Azure DevOps Server:** **Base URL** をオンプレミスのコレクション URL に設定してください。

## GitHub Enterprise Server 固有の情報

GitHub Enterprise Server は github.com と**同じ GitHub App** モデルを使用します。異なるのはホストのみです。

- **Connection:** App-manifest による自動作成フローは github.com 専用であるため、GHES ホスト上で App を**手動**で作成し、**Set up manually** からその認証情報と **Enterprise host** を入力します。[GitHub Enterprise Server を接続する](/sensei/setup_sensei/#connect-github-enterprise-server) を参照してください。DefectDojo は API(`/api/v3`)と web のオリジンをホストから導出します。
- **共存:** github.com の App 接続と GHES の App 接続は、同一インスタンス上で設定できます。各リポジトリは、オンボーディングに使用された接続に解決されます。
- **到達性:** DefectDojo は GHES の API ホストに到達できる必要があり、GHES は DefectDojo の `…/sensei/webhooks` エンドポイントに到達できる必要があります(双方が接続できれば、内部ホストでも問題ありません)。

## トラブルシューティング

- **検出事項の Sensei ボタンに「Configure Product」と表示される。** その検出事項の製品がオンボーディングされていません。クリックしてその製品のリポジトリをオンボーディングしてから、検出事項に戻ってください。
- **Auto-fix Candidates または Scan Activity で修正が「Failed」と表示される。** **Scan Activity** を開き、その実行の **Root Cause** / **Details** を確認してください。失敗した修正は、PR を生成する前に消えてしまわないよう一覧に残り続けます。再ステージングして再試行できます。
- **オンボーディング時にリポジトリが一覧に表示されない。** 接続がアクセスできるリポジトリのみが表示されます。**GitHub** では、App が正しい組織にインストールされており、そのリポジトリアクセスに対象リポジトリが含まれていることを確認してください。**GitLab** では、アクセストークンのスコープがそのプロジェクトをカバーしていることを確認してください。**Bitbucket Cloud** では、**workspace** が設定されていることを確認してください(トークンはワークスペースにスコープされています)。**Azure DevOps** では、PAT の organization が一致しており、**Code** スコープが付与されていることを確認してください。
- **webhook を設定してもスキャンや修正が開始されない。** リポジトリの webhook が、プロバイダーの受信エンドポイント(`…/sensei/{gitlab,bitbucket,azure}/webhooks`、GitHub の場合は `…/sensei/webhooks`)を正しいシークレット/認証情報とともに指しており、push + pull-request(+ comment)イベントを購読していることを確認してください。プロバイダーの**recent deliveries** には `HTTP 200` が表示されるはずです。webhook 駆動の実行は、**hosted** モードでオンボーディングされたリポジトリに対してのみ発生します。デフォルト以外のブランチへの push は、それ単体ではなく、そのプルリクエストを通じてスキャンされます。
- **スキャン後に何も起こらない。** リポジトリの設定で自動修正が有効になっていること(および深刻度/リスクのしきい値が検出事項と一致していること)、そして **Fixes** クォータが使い切られていないことを確認してください。

> **🔎 まだ BETA です:** Sensei は急速に進化しています。動作がこのガイドと一致しない場合は、[Pro 変更履歴](/releases/pro/changelog/) で最近の変更を確認してください。
