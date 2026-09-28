---
title: "Sonatype IQ"
description: "DefectDojo で Sonatype IQ の Upstream Connector をセットアップする方法"
weight: 128
audience: pro
---
Sonatype IQ コネクタは Sonatype IQ Server(Nexus Lifecycle)の REST API を使用して、オープンソースコンポーネントの脆弱性をインポートします。IQ 組織内のすべてのアプリケーションを列挙し、それぞれについて、設定したライフサイクルステージにおけるそのアプリケーションの最新レポートからコンポーネントの脆弱性をインポートします。DefectDojo は各アプリケーションに対して自動的に Record を作成します — アプリケーションごとの設定は不要です。

#### Prerequisites

インポートしたいアプリケーションに対して **View IQ Elements** 権限を持つ Sonatype IQ ユーザーアカウントが必要です。Sonatype はパスワードではなく、(IQ Server の **My Profile > User Token** で生成する)**ユーザートークン**を使用した認証を推奨しています。トークンの 2 つの部分は、以下の Username フィールドと User Token フィールドにそれぞれ対応します。このコネクタはセルフホスト型の IQ Server と、Sonatype がホストする(SaaS)インスタンスの両方に対応しています。

#### Connector Mappings

1. **Location** フィールドに IQ Server のベース URL を入力します — セルフホスト型サーバーの場合は `https://iq.example.com`、Sonatype がホストするインスタンスの場合は `https://<tenant>.sonatype.app/platform` です。
2. **Username** フィールドに IQ ユーザー(またはユーザートークンのユーザーコード部分)を入力します。
3. **User Token** フィールドに IQ ユーザートークン(またはパスワード)を入力します。
4. 必要に応じて、**Stage** を設定して、アプリケーションごとにどのライフサイクルステージのレポートをインポートするかを選択します(`build`、`stage-release`、`release` など)。空欄のままにすると `build` が使用されます。
5. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

各アプリケーションは Record になり、選択したステージにおけるそのアプリケーションの最新レポート内の各セキュリティ問題が検出事項としてインポートされます。深刻度は問題の数値スコアから導出され、CVE 参照、CWE、CVSS ベクター、影響を受けるコンポーネントのパッケージ URL(PURL)が利用可能な場合は含まれます。
