---
title: '権限を共有する: ユーザーグループ'
description: DefectDojo Proで多数のユーザーの権限を共有・維持する
weight: 3
audience: pro
aliases:
- /ja/en/customize_dojo/user_management/create_user_group
---

> **DefectDojo Pro機能。** ユーザーグループおよびその基盤となるRBACシステムは、DefectDojo Proの機能です。オープンソース版のDefectDojoは[認可済みユーザー](../os__authorized_users/)モデルを使用しています。オープンソース版のアクセス制御についてはそちらのページを、エディション間を移行する場合は[3.0アップグレードノート](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization)を参照してください。

DefectDojoのユーザー数が多い場合は、多数のユーザーに同じロールベースアクセス制御(RBAC)ルールを一括で設定するために、1つ以上の**グループ**を作成するとよいでしょう。ユーザーグループを作成できるのはスーパーユーザーのみです。

グループは複数の方法で機能します。

* すべてのグループメンバーに対して、1つまたは複数の異なるProductレベルまたはProduct TypeレベルのRoleを設定し、そのグループがどのProductまたはProduct Typeにアクセス・編集できるかを細かく制御できます。
* すべてのグループメンバーにグローバルロールを設定し、すべてのProductまたはProduct Typeへの可視性とアクセス権を付与できます。
* グループに設定権限を設定し、DefectDojoの特定機能を変更できるようにします。

ロールの詳細については、**Introduction To Roles**の記事を参照してください。

## The All Groupsページ

サイドバーから👤**Users \> Groups**に移動すると、アクティブおよび非アクティブなすべてのユーザーグループの一覧が表示されます。

![image](images/Create_a_User_Group_for_shared_permissions.png)
ここから、個々のグループページの作成、削除、閲覧を行えます。

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>のユーザーの場合、Pro UIのAll Groupsにはいくつか追加のオプションがあります。
* このテーブルは、グループ名、説明、メールアドレス、グローバルロールに加え、グループに関連付けられたユーザー数、Product Type数、Product数の合計でフィルタリングできます。
* 編集したいグループの隣にある「⋮」ボタンをクリックすることで、グループの権限やその他の設定を調整することもできます。

![image](images/all_groups_pro.png)

## グループを表示する

グループを表示すると、ID、名前、説明、グローバルロールなど、グループのすべての情報が表示されます。また、そのグループに関連付けられたグループメンバー、Product Type、Productも表示されます。さらに、グループに紐づく設定権限は、「View Group」ページから直接更新できます。

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>のユーザーの場合、Pro UIのGroup Viewでは、設定権限の調整を少し異なる方法で割り当てることができます。

![image](images/group_view_pro_ui.png)

* すべての設定権限は、サブカテゴリごとにグループ化されたドロップダウンに表示されます。選択した設定権限が現在の値と異なる場合、「Update Configuration Permissions」ボタンが表示されます。

![image](images/groups_pro_configuration_permissions.png)

* いくつかの追加の権限を選択すると、更新を行う前に、選択したグループの権限を更新してよいかどうかの確認が求められます。

## ユーザーグループを作成/編集する

1. サイドバーの👤**Users \> Groups**ページに移動します。名前、説明、ユーザー数、グローバルロール(該当する場合)、メールアドレスを含む、既存のすべてのユーザーグループの一覧が表示されます。
​
![image](images/Create_a_User_Group_for_shared_permissions_2.png)

2. All Groupsの見出しの隣にある**🛠️ボタン**をクリックし、**\+ New Group**を選択します。
​
![image](images/Create_a_User_Group_for_shared_permissions_3.png)


3. これにより、新しいグループを作成できるページに移動します。このグループの名前を設定し、必要に応じて説明を追加します。

必要であれば、このグループに適用したいグローバルロールも選択できます。グループにグローバルロールを追加すると、すべてのグループメンバーに、選択したグローバルロールに応じた一定の編集アクセス権とともに、DefectDojoの全データへのアクセス権が付与されます。詳細については**Introduction To Roles**の記事を参照してください。

グループを最初に作成したアカウントには、デフォルトでそのグループのOwnerロールが付与されます。

### レポートを受け取るメールアドレスを設定する

Weekly Digestは、グループに割り当てられたすべてのProduct/Product Typeに関するレポートです。Weekly Digestを送信するには、Create/Edit Groupフォームで使用したい送信先メールアドレスを入力します。グループメンバーは、これまでどおり通知を受け取り続けます。

### グループページを表示する

グループを作成すると、**Users \> Groups**の下に表示されるメニューから選択してアクセスできます。

グループページは**説明**でカスタマイズできます。すべての**グループメンバー**、割り当てられた**Product、Product Type**、およびそれぞれに関連付けられた**ロール**の一覧が表示されます。

グループの**設定権限**もここに表示されます。

## グループのユーザーを管理する

グループメンバーシップは、**Users \> Groups**ページの一覧から選択できる個々のグループページから管理します。編集したいグループページにアクセスするには、ハイライトされたグループ名をクリックします。

グループのメンバーシップを閲覧または編集するには、ユーザーが適切な設定権限を有効にしていることに加えて、そのグループのメンバーであること(またはスーパーユーザーのステータスを持つこと)が必要です。

### **グループにユーザーを追加する**

ユーザーグループには、好きなだけ多くのユーザーを割り当てることができます。グループ内のすべてのユーザーには、記載された各ProductまたはProduct Typeに対応するロールが付与されますが、ユーザーはグループのロールに優先する個別のロールを持つこともできます。

1. グループページで、**Members**見出しの端にある**☰**ボタンから**\+ Add Users**を選択します。
​
![image](images/Create_a_User_Group_for_shared_permissions_4.png)

2. これにより**Add Some Group Members**画面に移動します。Usersのドロップダウンメニューを開き、グループに追加したい各ユーザーにチェックを入れます。
​
![image](images/Create_a_User_Group_for_shared_permissions_5.png)

3. これらのユーザーに割り当てたいグループロールを選択します。これにより、そのユーザーがグループを設定できる範囲が決まります。

グループにメンバーを追加しても、デフォルトではそのメンバー自身のグループページへのアクセス権は付与されない点に注意してください。これは別の設定権限であり、先に有効化しておく必要があります。

### **ユーザーグループのメンバーを編集/削除する**

1. グループページで、グループから編集または削除したいユーザーの名前の隣にある⋮を選択します。

**📝 Edit**を選択すると編集画面に移動し、そのユーザーのロール(Reader、Maintainer、Ownerから別の選択肢へ)を変更できます。

**🗑️ Delete**は、ユーザーのメンバーシップを完全に削除します。そのユーザーがProductまたはProduct Typeに対して行った貢献や変更が削除されることはありません。

![image](images/Create_a_User_Group_for_shared_permissions_6.png)

## グループの権限を管理する

グループの権限は、**Users \> Groups**ページの一覧から選択できる個々のグループページから管理します。編集したいグループページにアクセスするには、ハイライトされたグループ名をクリックします。

グループの権限(Product/Product Type、または設定権限)を編集できるのはスーパーユーザーのみである点に注意してください。
​
### **グループにProductロールまたはProduct Typeロールを追加する**

各グループには、好きなだけ多くのProductロールまたはProduct Typeロールを登録できます。

1. グループページで、該当する見出し(Product Type GroupsまたはProduct Groups)から**\+ Add Product Types**または\+ **Add Product**を選択します。
​
![image](images/Create_a_User_Group_for_shared_permissions_7.png)

2. これにより**Register New Products / Product Types**ページに移動し、ドロップダウンメニューから追加したいProductまたはProduct Typeを選択できます。

![image](images/Create_a_User_Group_for_shared_permissions_8.png)

3. この特定のProductまたはProduct Typeについて、すべてのグループメンバーに持たせたいロールを選択します。

ロールなしでグループをProductまたはProduct Typeに割り当てることはできません。グループにどのロールを持たせるか迷った場合は、Readerが良い「デフォルト」の選択肢です。これにより、グループロールについて最終決定を行うまで、Productの状態を安全に保つことができます。

### **グループに設定権限を割り当てる**

グループ内のメンバーに設定機能へのアクセスを許可し、DefectDojoの特定の側面を制御させたい場合は、グループページからこれらの責任を割り当てることができます。

右下隅のメニューから、View、Add、Edit、Deleteのロールを割り当てます。設定権限にチェックを入れると、そのグループには直ちにその機能へのアクセス権が付与されます。

![image](images/Create_a_User_Group_for_shared_permissions_9.png)
