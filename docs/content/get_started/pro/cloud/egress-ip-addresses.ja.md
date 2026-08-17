---
title: エグレスIPアドレス
description: 外部ファイアウォールでアローリストに登録するための、DefectDojo Cloudが接続元とするアウトバウンドIPアドレス。
weight: 5
audience: pro
---

DefectDojo Cloudがお客様のシステムにアクセスする場合 — Connectorsによるスキャナーの
API同期、JiraやServiceNowへのIssueのプッシュ、通知Webhookの送信、SMTP経由の
メール配信など — これらの接続はすべてDefectDojo環境から**アウトバウンドで開始**
されます。接続先のシステムがファイアウォールの内側にある場合、これらの接続が
ブロックされないよう、DefectDojoのアウトバウンド(エグレス)IPアドレスを許可する
必要があります。

このページでは、そのエグレスIPアドレスの確認方法を説明します。

## エグレスとイングレス

この2つは異なるものであり、このページで扱うのは前者のみです。

- **エグレス(このページ)** — DefectDojo Cloudが*お客様の*外部システムに
  **アクセスする**際の接続元IPアドレスです。DefectDojoが連携先のシステムに
  到達できるよう、**お客様の**ファイアウォールでこれらを許可してください。
- **イングレス** — **お客様の**DefectDojoインスタンスへのアクセスを誰に許可するかを
  制御するルールです。これらはここではなく、Cloud ManagerのFirewall Rulesとして
  管理されます。[Connectivity Troubleshooting](../connectivity-troubleshooting/)、
  および[Set up an additional Cloud instance](../additional-cloud-instance/)の
  Firewall Rulesの手順を参照してください。

## マルチテナント環境

Standard、Pay-as-you-go、Premiumの各インスタンスは、共有のリージョン単位の
Google Kubernetes Engine(GKE)クラスター上で稼働します。アウトバウンド接続は、
インスタンスが稼働するリージョン内のノードの外部IPアドレスから発信されます。

現在のノードのエグレスIPのセットは、リージョンごとにグループ化されたJSON
フィードとして公開されています。

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

このフィードは以下のような内容です。

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

DefectDojoのエグレストラフィックを許可リストに登録するには、以下の手順に従います。

1. インスタンスが稼働しているリージョンを確認します(インスタンスのプロビジョニング時に
   選択したServer Location)。
2. そのリージョンに記載されているすべてのIPアドレスを許可します。各エントリは`/32`
   (単一ホスト)のCIDRです。

**このリストは随時変更されます。** プラットフォームのオートスケールに伴いノードが
追加・入れ替えされるため、あるリージョンのエグレスIPのセットは固定されていません。
アドレスを一度だけコピーするのではなく、このJSONフィードを正とみなしてください。

- フィードをプログラムで取得し、スケジュールに従ってファイアウォールの
  許可リストを更新する、または
- 定期的にフィードを再確認し、ルールを照合する。

ファイアウォールが変化するリストを追跡できず、少数の安定したアドレスのセットが
必要な場合は、**Dedicated**インスタンス(下記参照)についてDefectDojoの
担当者にご相談ください。

## シングルテナント(Dedicated)環境

**Dedicated**プランのインスタンスは、専用のGCPプロジェクトとVPC内で稼働し、
そのエグレスIPアドレスは**固定**です — インスタンスのプロビジョニング時に
割り当てられ、プラットフォームがスケールしても変化しません。

固定エグレスIPは特定のインスタンスに紐づいているため、公開フィードには
掲載されません。Dedicatedインスタンスに割り当てられたエグレスIPアドレスを
確認するには、[support@defectdojo.com](mailto:support@defectdojo.com)まで
ご連絡いただき、それらのアドレスを外部ファイアウォールで許可リストに
登録してください。

*このページで解決しない疑問がありますか? DefectDojoの担当者にお問い合わせください。*
