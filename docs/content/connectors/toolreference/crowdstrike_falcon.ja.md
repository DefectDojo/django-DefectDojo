---
title: "CrowdStrike Falcon"
description: "DefectDojo で CrowdStrike Falcon の Upstream Connector をセットアップする方法"
weight: 41
audience: pro
---
CrowdStrike Falconコネクタは、Falconプラットフォームから**Spotlightの脆弱性**と**EDR検知**を、2つの独立した検出事項タイプ（`CrowdStrike:Spotlight`と`CrowdStrike:Detections`）としてインポートします。DefectDojoは、Falconの**ホスト**ごとにレコードを作成します。

#### Prerequisites

Falconコンソールの**Support > API Clients and Keys**で作成する、Falconの**APIクライアント**（Client IDとsecret）が必要です。インポートしたいデータに応じたスコープを付与してください: **Hosts: Read**（ホスト検出に必須）、**Vulnerabilities (Spotlight): Read**（Spotlightの検出事項用）、**Alerts: Read**（EDR検知用）。この2つの検出事項タイプは独立しており、クライアントに該当スコープがない場合、同期全体が失敗するのではなく、そのタイプの検出事項がスキップされます。そのため、**Alerts: Read**を持たないクライアントでも、Spotlightの脆弱性は問題なくインポートされます。

#### Connector Mappings

1. **Location**フィールドに、コンソールのリージョンに対応するFalconクラウドのAPIベースURLを入力します。例: `https://api.crowdstrike.com`（US-1）、`https://api.us-2.crowdstrike.com`（US-2）、`https://api.eu-1.crowdstrike.com`（EU-1）、`https://api.laggar.gcw.crowdstrike.com`（US-GOV-1）。
2. **Client ID**フィールドにAPIクライアントのClient IDを入力します。
3. **Client Secret**フィールドにAPIクライアントのsecretを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

各Falconホストはレコードとなり、そのホスト名・OS・タイプにちなんで命名されます。Spotlightの脆弱性は**open**および**reopened**のものだけがインポートされるため、再インポートを行うと修復済みの検出事項はクローズされます。
