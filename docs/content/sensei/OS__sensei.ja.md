---
title: Sensei
description: SenseiはDefectDojo Proの機能です
draft: false
audience: opensource
weight: 1
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Senseiは、DefectDojo Pro専用の機能です。</span>

**Sensei**は、ソースコードリポジトリ向けのDefectDojoのAI搭載**スキャン&修正**機能で、**DefectDojo Pro**でのみ利用できます。オープンソース版には含まれていません。

Senseiを使用すると、DefectDojo Proは以下を行うことができます。

- GitHubリポジトリをスキャンし、その結果を検出事項としてインポートします。
- 大規模言語モデルを使用してそれらの検出事項を**修正**するプルリクエストを、プレビューファーストの承認ワークフロー(承認するまで何も実行されません)で開きます。
- 検出事項テーブルから、ステージングされた自動修正候補から、またはプルリクエストへの`/fix`コメントによって、修正を開始します。

## Senseiの完全なドキュメントを見る

Senseiの完全なガイドは、**Pro**ドキュメントの一部です。読むには、ドキュメントバージョンの切り替え(左側ナビゲーション上部)を**Pro**に切り替えてください。

- **Senseiについて:** それが何であるか、およびホスト型のスキャン&修正の仕組み
- **Senseiのセットアップ:** GitHub Appを接続し、リポジトリをオンボーディングする
- **Senseiで検出事項を修正する:** スキャン、候補のトリアージ、修正PRを開く
- **Senseiリファレンス:** ステータス、クォータ、トラブルシューティング

DefectDojo Proについて詳しくは、[defectdojo.com](https://www.defectdojo.com/)にアクセスするか、DefectDojoのアカウントチームにお問い合わせください。
