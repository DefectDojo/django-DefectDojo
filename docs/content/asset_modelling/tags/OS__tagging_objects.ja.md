---
title: オブジェクトへのタグ付け
description: タグを使用してデータモデルの新しい切り口を作成する
draft: false
weight: 2
exclude_search: false
audience: opensource
---

タグは、オブジェクトをより小さく扱いやすい単位にフィルタできる形でグループ化するのに最適な方法です。ステータスを示すために使用したり、Organizations、Assets、Engagements、Findingsといったデータモデル全体にわたるカスタムなまとまりを作成したりするために使用できます。

DefectDojoでは、タグはファーストクラスの存在として扱われており、データモデルの各階層内で整理を促進する仕組みとして認識されています。

以下は、2つのタグを持つ1つのAssetと、それぞれ1つずつタグを持つ4つの検出事項の例です。

![High level example of usage with tags](images/tags-high-level-example.png)

### タグの形式

タグは以下のいずれの形式でも指定できます。
- スペースなしの文字列(StringWithNoSpaces)
- ハイフン区切りの文字列(string-with-hyphens)
- アンダースコア区切りの文字列(string_with_underscores)
- コロンを含む形式(colons:acceptable)

## タグの管理

### 追加と削除

タグは以下の方法で管理できます。

1. 新しいオブジェクトの作成または編集

   UIまたはAPIを通じて新しいオブジェクトを作成または編集する際、そのオブジェクトに設定するタグを指定するためのフィールドがあります。このフィールドはマルチセレクト形式で、オートコンプリート機能も備えているため、既存のタグを簡単に検索・追加できます。前のセクションのスクリーンショットにあるAssetでは、このフィールドは次のように表示されます。

   ![Tag management on an object](images/tags-management-on-object.png)

2. インポートおよび再インポート

    タグは、インポートまたは再インポートの時点で特定のテストに適用することもできます。これは、自動化によりAPI経由でインポートする際に非常に便利なユースケースです。テストや検出事項オブジェクト自体には直接記録されない可能性がある、自動化実行の詳細情報やツール情報を追加する機会になるためです。

    このフィールドの見た目と動作は、他のオブジェクトの場合とまったく同じです。

3. 一括編集メニュー(検出事項のみ)

    多数の検出事項に同じタグのセットを設定したい場合、一括編集メニューを使用することで手間を軽減できます。

    次の例では、タグ「tag-group-alpha」が付いた2つの検出事項のタグを、新しいタグリスト["tag-group-charlie", "tag-group-delta"]に更新したいとします。まず、更新対象のタグ(検出事項)を選択します。

    ![Select findings for bulk edit tag update](images/tags-select-findings-for-bulk-edit.png)

    検出事項を選択すると、「Bulk Edit」という名前の新しいボタンが表示されます。このボタンをクリックすると、多数のオプションを持つドロップダウンメニューが表示されますが、ここではタグのみに注目します。以下のように、フィールドを希望のタグリストに更新し、送信をクリックします。

    ![Apply changes for bulk edit tag update](images/tags-bulk-edit-submit.png)

    選択した検出事項のタグは、一括編集メニュー内のタグフィールドで指定した内容に更新されます。

    ![Completed bulk edit tag update](images/tags-bulk-edit-complete.png)

## タグの継承

タグの継承(Tag Inheritance)が有効な場合、特定のAssetに適用されたタグは、[Asset Hierarchy](/asset_modelling/os_hierarchy/os__asset_hierarchy/)内のそのAsset配下にあるすべてのオブジェクトに自動的に適用されます。

### 設定

タグの継承は、以下のスコープレベルで有効にできます。
- グローバルスコープ
  - システム全体のすべてのAssetが、すべての子オブジェクト(Engagements、Tests、Findings)にタグを適用するようになります
  - これはSystem Settings内で設定します
- Assetスコープ
  - 選択したAssetのみが、すべての子オブジェクト(Engagements、Tests、Findings)にタグを適用するようになります
  - これはAssetの作成/編集ページで設定します

### 動作

タグの継承が有効な場合でも、標準的なタグは通常の方法でオブジェクトに追加・削除できます。ただし、継承されたタグは、親オブジェクトから削除しない限り、子オブジェクトから削除することはできません。以下は、Testオブジェクトに「test_only_tag」タグを、Engagementに「engagement_only_tag」タグを追加した例です。

![Example of inherited tags](images/tags-inherit-exmaple.png)

Asset上のタグリストが更新されると、Asset内のすべてのオブジェクトに対しても非同期で同じ変更が行われます。このタスクにかかる時間は、検出事項に含まれるオブジェクトの数に直接比例します。

**オープンソース版:** タグの変更が妥当な時間内に反映されない場合は、celeryワーカーのログを確認し、問題の発生箇所を特定してください。


### タグによるフィルタリング(クラシックUI)

タグは、UIとAPIの両方を通じてさまざまな方法でフィルタできます。例えば、以下はFindingフィルタの一部です。

![Snippet of the finding filters](images/tags-finding-filter-snippet.png)

タグに関連するフィールドは10種類あります。

 - Tags:特定の検出事項に付与されているタグでフィルタします
   - 例:
     - 検出事項が返される場合
       - 検出事項のタグ:["A", "B", "C"]
       - フィルタクエリ:"B"
     - 検出事項が返され*ない*場合
       - 検出事項のタグ:["A", "B", "C"]
       - フィルタクエリ:"F"
 - Not Tags:特定の検出事項に付与され*ていない*タグでフィルタします
   - 例:
     - 検出事項が返される場合
       - 検出事項のタグ:["A", "B", "C"]
       - フィルタクエリ:"F"
     - 検出事項が返され*ない*場合
       - 検出事項のタグ:["A", "B", "C"]
       - フィルタクエリ:"B"
 - Tag Name Contains:特定の検出事項において、クエリの一部または全部を含むタグでフィルタします
   - 例:
     - 検出事項が返される場合
       - 検出事項のタグ:["Alpha", "Beta", "Charlie"]
       - フィルタクエリ:"et"("Beta"の一部)
     - 検出事項が返され*ない*場合
       - 検出事項のタグ:["Alpha", "Beta", "Charlie"]
       - フィルタクエリ:"meg"("Omega"の一部)
 - Not Tags:特定の検出事項において、クエリの一部または全部を含ま*ない*タグでフィルタします
   - 例:
     - 検出事項が返される場合
       - 検出事項のタグ:["Alpha", "Beta", "Charlie"]
       - フィルタクエリ:"meg"("Omega"の一部)
     - 検出事項が返され*ない*場合
       - 検出事項のタグ:["Alpha", "Beta", "Charlie"]
       - フィルタクエリ:"et"("Beta"の一部)

他の6つのタグフィルタについては、上記の「Tags」および「Not Tags」と同じルールに従いますが、データモデル内の異なる階層に適用されます。

 - Tags (Test):特定の検出事項のTestに付与されているタグでフィルタします
 - Not Tags (Test):特定の検出事項のTestに付与され*ていない*タグでフィルタします
 - Tags (Engagement):特定の検出事項のEngagementに付与されているタグでフィルタします
 - Not Tags (Engagement):特定の検出事項のEngagementに付与され*ていない*タグでフィルタします
 - Tags (Asset):特定の検出事項のAssetに付与されているタグでフィルタします
 - Not Tags (Asset):特定の検出事項のAssetに付与され*ていない*タグでフィルタします
