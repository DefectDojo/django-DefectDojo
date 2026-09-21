---
title: "MobSF"
description: "DefectDojo で MobSF の Upstream Connector をセットアップする方法"
weight: 91
audience: pro
---
MobSFコネクタは、[Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) REST APIを使用して、モバイルアプリケーション(APK/IPA)の静的解析結果をインポートします。DefectDojoは、お使いのMobSFインスタンス上でスキャン済みのすべてのアプリを検出し、それぞれについてRecordを作成した上で、そのアプリの静的解析の検出事項をインポートします。

#### 前提条件

MobSFの**REST APIキー**が必要です。MobSFのホームページの **API** の下にあります(MobSFドキュメントでは `Authorization` 値としても示されています)。このキーはすべてのリクエストで送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドにMobSFのベースURLを入力します(例: `https://mobsf.example.com`)。
2. **Secret** フィールドに、MobSFのREST APIキーを入力します。
3. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは、スキャン済みの各**アプリ**をRecordにマッピングし、MobSFのJSONレポートの複数のセクション — アプリケーションの権限、コード解析、署名証明書、Androidマニフェスト、Android APIの使用状況、バイナリ解析 — から検出事項をインポートします。各検出事項には**CWE 919**(モバイル)のタグが付けられ、深刻度はMobSF自身の評価(high、warning、info、secure/good)に基づきます — *dangerous*な権限はHighとして扱われます。検出事項は静的検出事項として記録され、スキャン、セクション、タイトル、深刻度、ファイルパスで重複排除されます。

詳細については、[MobSF REST APIドキュメント](https://mobsf.github.io/docs/#/rest_api)を参照してください。
