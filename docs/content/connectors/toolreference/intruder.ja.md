---
title: "Intruder"
description: "DefectDojo で Intruder の Upstream Connector をセットアップする方法"
weight: 79
audience: pro
---
Intruderコネクタは、[Intruder REST API](https://developers.intruder.io/)を使用して、アカウント全体のセキュリティ状況をDefectDojoに取り込みます。各Intruderの**target**はRecord(Product)として検出され、target上のissueの各**occurrence**がFindingになります。

#### Connector Mappings

1. **Location**フィールドは`https://api.intruder.io/`(デフォルトのIntruder APIサーバー)のままにしておきます。
2. **Secret**フィールドにIntruderの**APIアクセストークン**を入力します。

Intruderの**My account > API Access Tokens**でアクセストークンを生成します(作成にはアカウントパスワードが必要で、トークンは一度しか表示されません)。詳細は[Intruder APIドキュメント](https://developers.intruder.io/docs/creating-an-access-token)を参照してください。

検出事項はoccurrenceごとに導出されます。深刻度はissueの深刻度から、CVEとCVSSはoccurrenceから、locationはtarget/portから取得され、snooze(一時停止)されたoccurrenceは非アクティブ(誤検知またはリスク受容済み)な検出事項としてインポートされます。
