---
title: アップストリームコネクタの追加または編集
description: サポートされているセキュリティツールに接続する
aliases:
- /ja/import_data/pro/connectors/add_edit_connectors/
- /ja/en/connecting_your_tools/connectors/add_edit_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: アップストリームコネクタは DefectDojo Pro 限定の機能です。</span>

アップストリームコネクタの追加と設定のプロセスは、接続しようとしているツールに関わらずほぼ同じです。ただし、ツールによっては API キーの作成や追加の手順が必要になる場合があります。

この作業を始める前に、接続しようとしているツールの API リソースを確認するため、[ツール別リファレンス](../../toolreference/upstream/) を確認することをお勧めします。

1. まだの場合は、まず DefectDojo で **Pro UI に切り替え** てください。
2. 左側のメニューから、**Import** ヘッダーの下にネストされた **Connectors** グループを開き、**Upstream Connectors** をクリックします。
​
![image](images/add_edit_connectors.png)

3. DefectDojo に追加したい新しいコネクタを **Available Connectors** から選び、そのツールのタイルにある **Add Configuration** ボタンをクリックします。**Search Connectors** ボックスを使用してツール名で各セクションを絞り込んだり、ページヘッダーの **All / Asset / Finding** トグルでコネクタタイプによって絞り込んだりすることもできます。
​
**Configured Connectors** の下にある既存のコネクタを編集することもできます。編集したい Configured Connector について、**Manage Configuration \> Edit Configuration** をクリックします。
​
![image](images/add_edit_connectors_2.png)

4. ツールにアクセス可能な **Location URL** と、API **Secret** キーが必要です。API キーの場所は、設定しようとしているツールによって異なります。詳細は [ツール別リファレンス](../../toolreference/upstream/) を参照してください。
​
5. DefectDojo でこの接続を識別しやすいように、**Label** を設定します。
​
6. **Discovery Configuration** と **Synchronization Configuration** のスケジュールを使用して、コネクタの自動 discovery と sync をスケジュールします。これらは後から変更できます。
​
7. **Enable Auto-Mapping** を有効にするかどうかを選択します。Auto-Mapping を有効にすると、このコネクタからのデータを保存するための新しい製品が DefectDojo 内に作成されます。Auto-Mapping はいつでもオン/オフを切り替えられます。
​
8. **Submit** をクリックします。

![image](images/add_edit_connectors_3.png)

## 次のステップ

* コネクタを追加したら、[Discover](../manage_operations/#discover-operations) オペレーションを実行して、すべてが正しく設定されていることを確認できます。
