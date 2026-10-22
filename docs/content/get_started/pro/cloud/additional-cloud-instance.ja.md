---
title: 追加の Cloud インスタンスをセットアップする
description: アカウントにテスト用、開発用などの DefectDojo インスタンスを追加する
weight: 3
audience: pro
aliases:
- /ja/en/cloud_management/additional-cloud-instance
---

2 つ目の Cloud インスタンスを追加する手順は、最初のインスタンスを追加する場合とほぼ同じです。このガイドは、すでに最初の DefectDojo サーバーをセットアップ済みであり、追加のインスタンスについて営業チームとの合意ができていることを前提としています。

追加の Cloud インスタンスをまだ申し込んでいない場合は、進める前に [info@defectdojo.com](mailto:info@defectdojo.com) までご連絡ください。

## ステップ 1: 新規サブスクリプションの手続きを開始する

この手続きは、次のリンクから開始できます。<https://cloud.defectdojo.com/accounts/onboarding/step_1>。または、Cloud Manager のページ（cloud.defectdojo.com）で 🛒 **New Subscription** をクリックしても開始できます。

![image](images/request_a_trial.png)

## ステップ 2: サーバーラベルを設定する

会社の**名前（Name）**と、DefectDojo で使用したい**サーバーラベル（Server Label）**を入力します。これにより、当社のサーバー上に、あなたの DefectDojo インスタンス用のカスタムドメインが作成されます。

会社名は以前と同じにしたまま、新しいサーバーラベルを作成し、「**Use Server Label in Domain**」ボタンをチェックしてください。こうすることで、サーバー同士を簡単に区別できるようになります。

![image](images/request_a_trial_2.png)

## ステップ 3: サーバーの所在地を選択する

ドロップダウンメニューからサーバーの所在地（Server Location）を選択します。以前と同様に、サーバーのレイテンシーを抑えるため、ユーザーに地理的に最も近いサーバーを選択することをお勧めします。

![image](images/request_a_trial_3.png)

## ステップ 4: ファイアウォールルールを設定する

DefectDojo へのアクセスを許可したい IP アドレス範囲、サブネットマスク、ラベルを入力します。インスタンスの稼働開始後も、追加の IP アドレスやルールをチームで追加・変更できます。

必要であれば、これらのファイアウォールルールをメインの DefectDojo インスタンスのルールとは異なる内容にすることもできます。

![image](images/request_a_trial_4.png)

このインスタンスで外部サービス（GitHub や JIRA）を使用したい場合は、**Select External Services** の下にある該当するチェックボックスをオンにしてください。

**Proceed Without Firewall** を選択して、ファイアウォールなしで進めることもできます。ファイアウォールは後から再度有効にできます。

## ステップ 5: プランの種類と請求頻度を確認する

手続きの最後に、営業チームと連絡を取り、新しいサーバーの正確な見積もりを受け取ることができます。新しいインスタンスに必要なサーバー仕様を満たすプランタイプを選択することをお勧めします。

![image](images/request_a_trial_5.png)

2 つ目のサーバーには、「メイン」インスタンスと同じストレージ、CPU、RAM の要件が必要とは限りませんが、これはチームの技術要件によって異なります。

## ステップ 6: リクエストを確認して送信する

もう一度リクエストの内容を確認するよう促されます。送信後は、サポートの支援なしでチームが変更できるのはファイアウォールルールのみです。

![image](images/request_a_trial_6.png)

DefectDojo の License and Support Agreement を確認し同意した後、**Checkout With Stripe** に進むことができます。既存の請求契約がある場合は、**Contact Sales** をクリックしてください。

サーバーが承認され、プロビジョニングが完了すると、サポートチームからログイン情報とともにご連絡します。
