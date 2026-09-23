---
title: "Tenable Web App Scanning"
description: "DefectDojo で Tenable Web App Scanning の Upstream Connector をセットアップする方法"
weight: 132
audience: pro
---
Tenable Web App Scanning コネクタは、Tenable Web App Scanning から**Web アプリケーション(DAST)検出事項**をインポートします。これは Tenable(Vulnerability Management)とは別のコネクタです。両製品は対象とするアセットが異なり、それぞれ独立して設定されるため、どちらか一方、または両方を使用できます。

DefectDojo は**スキャン対象の Web アプリケーション**ごとに Record を作成します。アプリケーションは Web App Scanning のスキャン設定から検出されます。一度も実行されていない設定は、最初のスキャンが完了するまで Record を生成しません。複数の設定が同じアプリケーションをスキャンする場合、それらは 1 つの Record を共有します。

#### Prerequisites

Web App Scanning の権限を持つユーザー用の Tenable **API キー**(アクセスキーとシークレットキー)。Tenable で **My Account > API Keys** に移動して生成し、そのユーザーがインポートしたいスキャンを閲覧できることを確認してください — Vulnerability Management に限定されたキーでは Web App Scanning のデータを読み取れません。

オンプレミス版の Tenable コネクタは現時点では利用できません。

#### Connector Mappings

1. **Location** フィールドに <https://cloud.tenable.com> を入力します。
2. **Access Key** と **Secret Key** を入力します。
3. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

検出事項は、チームが変更した深刻度も含め、Tenable がアカウントに対して報告する深刻度でインポートされます。各検出事項には、影響を受ける URL がエンドポイントとして、検出のきっかけとなったリクエストパラメータとペイロード、および Tenable の証拠と出力が再現手順として含まれ、検出プラグインが提供する場合は CWE、CVE、CVSS、EPSS の値も含まれます。

現在オープンまたは再オープンされている検出事項のみがインポートされます。Tenable が修正済みとマークした検出事項は、次回の同期時に DefectDojo でクローズされます。
