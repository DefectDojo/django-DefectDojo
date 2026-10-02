---
title: 重複排除の有効化
description: ProductレベルまたはEngagementレベルで重複排除を有効にする方法
weight: 2
audience: pro
aliases:
- /ja/en/working_with_findings/finding_deduplication/enabling_product_deduplication
---

重複排除は、Product全体に対して適用することも、単一のEngagementに絞って適用することもできます。

## Productに対する重複排除

1. サイドバーの**Settings \> System \> ⚙️ System Settings**からSystem Settingsページに移動します(以前のメニュー構成を使用しているインスタンスでは**Settings \> Pro Settings \> System Settings**)。

![image](images/enabling_product-level_deduplication.png)

2. **Deduplication and Finding Settings**カードは、**System Settings**ページの一番上にあります。

![image](images/enabling_product-level_deduplication_2.png)

### 検出事項の重複排除の有効化

**Enable Finding Deduplication**は、すべての検出事項に対してDeduplication Algorithmを有効にします。有効にすると、以降のすべてのインポートで重複排除が実行されます。DefectDojoは、インポートされた検出事項を対象Product内の既存の検出事項と比較し、設定に従って重複としてマークします。

### 重複した検出事項の削除

**Delete Duplicate Findings**は、**Maximum Duplicates**フィールドと組み合わせることで、DefectDojoが保持する重複した検出事項の数を制限します。有効にすると、バックグラウンドジョブが定期的に余分な重複を削除し、各オリジナルの検出事項が設定された**Maximum Duplicates**の件数を超えて重複を保持しないようにします。最も古い重複から削除されます。

## Engagementに対する重複排除

Product全体にわたって重複排除を行う代わりに、重複排除の範囲を単一のEngagementに限定することもできます。

### Engagementフォームを開く

* **新規Engagementの場合:** サイドバーの**📥 Engagements**サブメニューを開き、**\+ New Engagement**をクリックします。

![image](images/enabling_deduplication_within_an_engagement.png)

* **既存のEngagementの場合(All Engagementsページから):** そのEngagementの**⋮**メニューを開き、**Edit Engagement**を選択します。

![image](images/enabling_deduplication_within_an_engagement_2.png)

* **既存のEngagementの場合(Engagementページから):** ページ右上の**⚙️ Gear**メニューを開き、**Edit Engagement**を選択します。

![image](images/enabling_deduplication_within_an_engagement_3.png)

### Engagementフォームの入力

1. Engagementフォームで、☐ **Isolate Deduplication from Other Engagements**チェックボックスを見つけます。これは**Optional Fields \+**パネルの上に表示されます。
2. チェックボックスをオンにして、重複排除の範囲をこのEngagementに限定します。
3. フォームを送信します。

このオプションを有効にすると、このEngagement内の検出事項は、同じEngagement内の他の検出事項に対してのみ重複排除されます。同じProduct内の他のEngagementにある検出事項は、Deduplication Algorithmによって無視されます。

![image](images/enabling_deduplication_within_an_engagement_4.png)
