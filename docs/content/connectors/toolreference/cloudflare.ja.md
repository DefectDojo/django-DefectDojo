---
title: "Cloudflare"
description: "DefectDojo で Cloudflare の Upstream Connector をセットアップする方法"
weight: 36
audience: pro
---
Cloudflare コネクタは**Security Center insights** をインポートします。これは、DMARC レコードの欠落、DNSSEC が有効化されていない、証明書の問題など、Cloudflare がアカウントとゾーンについて表示するセキュリティ体制上の問題です。DefectDojo は、未解決の insight を持つゾーン(ドメイン)ごとにレコードを作成し、特定のゾーンに紐づかない insight についてはアカウントレベルのレコードを作成します。

#### Prerequisites

Cloudflare の**API トークン**(従来の Global API Key ではない)が必要です。Cloudflare ダッシュボードの **My Profile > API Tokens > Create Token** で作成してください。最も手軽な方法は**「Read all resources」**テンプレートです。最小権限のトークンにする場合は、**Zone > Zone > Read**(すべてのゾーン)に加えて、Security Center 用のアカウントレベルの読み取りアクセスを付与してください。

#### Connector Mappings

1. **Location** フィールドに `https://api.cloudflare.com/client/v4` を入力します。
2. **Secret** フィールドに API トークンを入力します。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

DefectDojo は、トークンがアクセスできるアカウントとゾーンを自動検出します。アカウント ID は不要です。未解決(アクティブで、却下されていない)の insight のみがインポートされるため、Cloudflare 上で解決または却下した insight は、次の同期で DefectDojo 上でも自動的に緩和済みになります。
