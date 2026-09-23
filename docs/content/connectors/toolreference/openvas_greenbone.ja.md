---
title: "OpenVAS / Greenbone"
description: "DefectDojo で OpenVAS / Greenbone の Upstream Connector をセットアップする方法"
weight: 98
audience: pro
---
OpenVAS / Greenboneコネクタは、Greenbone(Greenbone Community EditionまたはGreenbone Enterprise)インスタンスから**ネットワーク脆弱性の検出事項**をインポートします。これは、HTTPではなく**GMP (Greenbone Management Protocol)** — TLSソケット上のXMLプロトコル — を介して `gvmd` と通信し、インスタンス全体を同期します。スキャン**タスク**を列挙してそれぞれについてDefectDojoの製品を作成し、各タスクの最新レポートの結果をインポートします。

#### 前提条件

Greenboneの**GMPユーザー**(ユーザー名とパスワード)と、gvmdのGMP TLSポート(デフォルトは**9390**)へのネットワークアクセスが必要です。Greenbone Community Editionのcomposeスタックは、unixソケット経由でgvmdをフロントに置いているため、ネットワーク経由のコネクタからそこに到達するには、ソケットに到達できる場所でコネクタを実行するか、GMP TLSポートを公開する必要があります(例: `gvmd.sock` へのTLSブリッジとして `socat` を使用)。

#### Connector Mappings

1. **Location** フィールドにgvmdホストを入力します(ホスト名、または `host:port`)。
2. GMPの **Username** と **Password** を入力します。
3. 必要に応じて **GMP Port** を設定します(デフォルトは9390)。
4. gvmdのデフォルトの自己署名証明書に対しては、検証用に **CA Certificate (PEM)** を指定するか、**Skip TLS Verification** を `true` に設定してください。
5. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各Greenboneタスクが1件のRecordになります。検出事項はタスクの最新の完了レポートから取得され、`<result>` ごとに1件です。深刻度は結果の脅威レベルから取得され(Greenboneの `Log`/`Debug` の情報レベルはInfoにマッピングされます)、数値のCVSSスコアが記録されます。CVEの参照は脆弱性IDになり、NVTのsolutionは緩和策になり、各結果のホスト/ポートはエンドポイントになります。
