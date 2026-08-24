---
title: "Harbor"
description: "DefectDojo で Harbor の Upstream Connector をセットアップする方法"
weight: 71
audience: pro
---
Harborコネクタは、Harbor v2.0 REST APIを使用して、レジストリ全体のコンテナイメージの脆弱性をインポートします。DefectDojoはすべてのHarbor**project**を列挙し、それぞれにRecordを作成した上で、そのprojectのリポジトリとアーティファクトを走査し、**スキャン済み**の各アーティファクトから脆弱性をインポートします — その際、イメージ(リポジトリ+タグ/ダイジェスト)を検出事項のコンテキストとして保持します。イメージごとの個別設定はありません。

#### Prerequisites

インポート対象のprojectへのpull/読み取りアクセス権を持つHarborアカウント(または**robotアカウント**)が必要です。専用のrobotアカウントの使用をお勧めします。Harborでprojectを開き(システムrobotの場合は**Administration > Robot Accounts**)、リポジトリとアーティファクトに対する**pull**権限を持つrobotを作成し、そのフルネームとシークレットをコピーします。robot名はデフォルトで`robot$`から始まりますが、このプレフィックスはHarborインスタンスごとに設定可能です(`robot_`を使用するものもあります) — Harborに表示されている名前をそのままコピーしてください。通常のユーザー名/パスワードも使用できます。

#### Connector Mappings

1. **Location**フィールドにHarborのURLを入力します — 例: `https://harbor.example.com`。DefectDojoは`/api/v2.0`のAPIパスを自動的に付加します。
2. **Username**フィールドにHarborのユーザー名、またはHarborに表示されているとおりのrobotアカウント名(デフォルトでは`robot$<name>`)を入力します。
3. **Secret**フィールドにパスワードまたはrobotアカウントのシークレットを入力します。これはHTTP Basic認証で送信されます。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

各Harbor projectがRecordとなります。スキャンが完了しているアーティファクトごとに、その脆弱性が検出事項としてインポートされます。影響を受けるパッケージ/バージョン、CVSSに基づく深刻度、CVE、CWE、および修復方法(修正済みバージョン)は、Harborが提供している場合に含まれます。インポートされるのはスキャン済みのアーティファクトのみです — まだスキャンされていないイメージについては、Harbor側でスキャンを実行してください。
