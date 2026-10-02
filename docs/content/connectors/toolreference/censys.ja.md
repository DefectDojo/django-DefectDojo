---
title: "Censys"
description: "DefectDojo で Censys の Upstream Connector をセットアップする方法"
weight: 32
audience: pro
---
Censys コネクタは Censys Platform からホストアセットを読み取り、各ホストの公開サービスを検出事項としてインポートします。スコープ対象のホストを列挙するために Censys Platform のグローバル検索 API を使用します。

#### Prerequisites

API アクセスを備えた Censys **Platform** アカウントが必要です。

* Censys Platform Console の Personal Access Tokens で作成した**Personal Access Token**。
* 同じ設定ページの「Current Organization」に表示される**Organization ID**。search エンドポイントへの API アクセスには組織が必要なため、Starter 以上のティアが必要です。無料ティアのトークンには organization ID がなく、search API を利用できません。

ホストごとの CVE およびリスクデータは Censys Core(エンタープライズ)ティアでのみ利用可能なため、それより下位のティアでは検出事項は脆弱性ではなく公開サービスを表します。

詳細は [Censys Platform API documentation](https://docs.censys.com/reference/get-started) を参照してください。

#### Connector Mappings

1. **Location** フィールドに `https://api.platform.censys.io` を入力します。
2. **API Key** フィールドに Personal Access Token を入力します。
3. **Organization ID** を入力します。
4. インポート対象を自社のアセットに絞り込む**Search Query**を入力します。例: `host.autonomous_system.asn: <your ASN>` や `host.ip: 203.0.113.0/24`。
5. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

DefectDojo はホストごとにレコードを作成し、その公開サービスを検出事項としてインポートします。
