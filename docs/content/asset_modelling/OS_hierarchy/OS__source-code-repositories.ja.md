---
title: 検出事項をソースコードにリンクする
description: 検出事項のソースコード内の場所へ移動するためのリポジトリ統合。
draft: false
weight: 5
audience: opensource
aliases:
- /ja/en/working_with_findings/organizing_engagements_tests/source-code-repositories
---

一部のツール（特にSASTツール）は、脆弱性データに関連するファイル名と行番号を含みます。エンゲージメントでソースコードのリポジトリが指定されている場合、DefectDojoはファイルパスをリンクとして表示し、ユーザーは脆弱性の場所に直接移動できます。

## エンゲージメントとテストでのリポジトリの設定

### エンゲージメント

エンゲージメントの編集中に、ユーザーは特定のソースコード管理リポジトリのURLを設定できます。**（Pro UIでは、このフィールドは編集エンゲージメント > オプションフィールド > Repo で設定できます）**。

インタラクティブエンゲージメントの場合、ブランチを指定するURLである必要があります。
- GitHubの場合 - https://github.com/DefectDojo/django-DefectDojo/tree/dev のような形式
![エンゲージメントの編集（GitHub）](images/source-code-repositories_1.png)
- GitLabの場合 - https://gitlab.com/gitlab-org/gitlab/-/tree/master のような形式
![エンゲージメントの編集（Gitlab）](images/source-code-repositories-gitlab_1.png)
- パブリックBitBucketの場合 -    （git cloneのURLと同様）
![エンゲージメントの編集（Bitbucket public）](images/source-code-repositories-bitbucket_1.png)
- スタンドアロン/オンプレミスBitBucketの場合、パブリックなユーザーリポジトリでは https://bb.example.com/scm/some-project/some-repo.git または https://bb.example.com/scm/some-user-name/some-repo.git （git cloneのURLと同様）
![エンゲージメントの編集（Bitbucket standalone）](images/source-code-repositories-bitbucket-onpremise_1.png)

CI/CDエンゲージメントの場合、コミットハッシュ、ブランチ/タグ、コード行が変わる可能性があるため、リポジトリのURLのみを含める必要があります。
- GitHubの場合 - `https://github.com/DefectDojo/django-DefectDojo` のような形式
- GitLabの場合 - `https://gitlab.com/gitlab-org/gitlab` のような形式
- パブリックBitBucket、Gitea、Codebergの場合 - `https://bitbucket.org/some-user/some-project.git` のような形式（git cloneのURLと同様）
- スタンドアロン/オンプレミスBitBucketの場合、パブリックなユーザーリポジトリでは `https://bb.example.com/scm/some-project.git` または `https://bb.example.com/scm/some-user-name/some-repo.git` （git cloneのURLと同様）

CI/CDエンゲージメントでは、**エンゲージメントの編集**フォームでコミットハッシュやブランチ/タグを指定でき、これはDefectDojoが表示するすべてのリンクに付加されます。これらが設定されていない場合、SCMのURLにはコードブランチを含む完全なリンクが含まれている必要があります。

SCMナビゲーションURLは、SCMタイプを使用してリポジトリURLから構成されます。特定のSCMタイプは、アセットのカスタムフィールド「scm-type」で設定できます。「scm-type」が設定されておらず、URLに「https://github.com」が含まれている場合は、「github」のSCMタイプが想定されます。

アセットのカスタムフィールド:

![アセットのカスタムフィールド](images/asset-custom-fields_1.png)

アセットのSCMタイプの追加:

![アセットのSCMタイプ](images/asset-scm-type_1.png)

利用可能なSCMタイプは、「github」、「gitlab」、「bitbucket」、「bitbucket-standalone」、「gitea」、「codeberg」、または未設定（デフォルトのgithub）です。


## 検出事項内のソースコードリンク

検出事項を表示する際、エンゲージメントでソースコードのリポジトリが設定されていれば、場所はリンクとして表示されます。

![場所へのリンク](images/source-code-repositories_2.png)

このリンクをクリックすると、ブラウザで新しいタブが開き、対応する行番号の脆弱性のソースファイルが表示されます。

![リポジトリで表示](images/source-code-repositories_3.png)
