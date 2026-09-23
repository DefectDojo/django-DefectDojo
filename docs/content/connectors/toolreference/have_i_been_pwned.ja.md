---
title: "Have I Been Pwned"
description: "DefectDojo で Have I Been Pwned の Upstream Connector をセットアップする方法"
weight: 72
audience: pro
---
Have I Been Pwned(HIBP)コネクタは、HIBP REST APIを使用して、組織自身のドメイン上のどのアカウントが既知のデータ漏洩に含まれているかを報告します。DefectDojoはHIBPで検証済みの各ドメインを検出し、そのドメインに影響する漏洩ごとに1件の検出事項をインポートします。

#### Prerequisites

ドメイン検索機能付きのHave I Been Pwned APIキーが必要です。これには**Core**サブスクリプション以上のプランが必要です。キーは[Have I Been Pwnedアカウント](https://haveibeenpwned.com/API/Key)から取得できます。

また、漏洩データを利用できるようにするには、HIBPアカウントで**少なくとも1つのドメインを検証**する必要があります。HIBPでは、アカウントの**Domain search**セクションから、DNS TXTレコード、metaタグ、ファイルアップロード、またはメールでドメインを検証できます。ドメインが検証されるまで、コネクタはドメインを検出せず、検出事項もインポートされません。

#### Connector Mappings

1. **Location**フィールドに`https://haveibeenpwned.com`を入力します。
2. **Secret**フィールドにAPIキーを入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。選択した深刻度を下回る検出事項はインポートされません。

DefectDojoは、HIBPで検証済みの各ドメインごとに個別のRecordを作成し、そのドメイン上のアカウントに影響する漏洩ごとに1件の検出事項をインポートします。各検出事項の深刻度は漏洩で公開されたデータの種類を反映し、説明にはあなたのドメイン上で影響を受けたアカウントが記載されるため、チームが対応を取ることができます。

詳細については、[Have I Been Pwned APIドキュメント](https://haveibeenpwned.com/API/v3)を参照してください。
