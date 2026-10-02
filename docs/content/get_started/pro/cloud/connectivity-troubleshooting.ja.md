---
title: 接続に関するトラブルシューティング
description: DefectDojo インスタンスへの接続を復旧する
weight: 2
audience: pro
aliases:
- /ja/en/cloud_management/connectivity-troubleshooting
---

DefectDojo インスタンスへのアクセスに問題がある場合は、以下の手順に従って接続を復旧できます。

## サイトにはアクセスできるが、ログインできない

1. ログインページ（**yourcompanyinstance.cloud.defectdojo.com/login**）からアカウントのパスワードをリセットできます。手続きを開始するには「I forgot my password」をクリックしてください。  
​

![image](images/Connectivity_Troubleshooting.png)

2. メールアドレスを入力し、「Reset my password」をクリックします。  
​
3. 件名が「`Password reset on yourcompanyinstance.cloud.defectdojo.com`」のメールが届きます。このメールには、新しいパスワードを設定するためにクリックできるリンクが含まれています。  
  

![image](images/Connectivity_Troubleshooting_2.png)

メールが届かない場合は、迷惑メールフォルダを確認してください。それでも見つからない場合は、チームの DefectDojo 管理者に、あなたのインスタンスにアカウントが登録されているかを確認してもらってください。  



## 自社のcloud.defectdojoサイトにアクセスできない

自社の cloud.defectdojo サイトがブラウザで読み込まれない、またはタイムアウトする場合、接続を受け入れるために自社のファイアウォールルールを変更する必要がある可能性があります。

ファイアウォールルールは、Cloud Manager（<https://cloud.defectdojo.com/accounts/manage_subscriptions>）で変更できます。

自社で共有 VPN、プロキシサーバー、または類似のツールを使用している場合は、それが DefectDojo への接続を許可されており、その IP アドレスが DefectDojo のファイアウォールルールに含まれていることを確認してください。

問題が解決しない場合は、[support@defectdojo.com](mailto:support@defectdojo.com) までご連絡ください。



## Cloud Managerにログインできない

Cloud Manager にアクセスできない場合は、ログインページ（<https://cloud.defectdojo.com/accounts/login/>）に移動し、**「Forgot your password?」**をクリックしてください。


![image](images/Connectivity_Troubleshooting_3.png)  
メールアドレスの入力を求められ、当社チームからパスワードをリセットして新しいパスワードを設定するためのリンクが記載されたメールが送信されます。

この方法でログインできるのは**Cloud Manager**（チームの全員がアクセス権を持っているとは限らない管理サイト）に対してのみである点にご注意ください。DefectDojo を使用するためにインスタンスへ直接ログインするには、**yourcompanyinstance.cloud.defectdojo.com/login** に直接接続する必要があります。



## MFAコードにアクセスできなくなった

* **Cloud Manager の場合:** MFA コードや認証アプリにアクセスできなくなった場合は、[support@defectdojo.com](mailto:support@defectdojo.com) の DefectDojo サポートまでご連絡ください。
* **DefectDojo インスタンスの場合:** まず、MFA 設定時に発行された**リカバリーコード**のいずれかを、ログイン時に 6 桁のコードの代わりに入力してみてください。それらが利用できない場合、サーバーへのアクセス権を持つ管理者が `python manage.py remove_mfa --username <username>` を使用して、アカウントから MFA を解除できます。その後、ユーザーはパスワードでログインし、再登録を行うことで、既存の権限と履歴をすべて保持したまま利用を続けられます。DefectDojo Cloud では、このコマンドを実行してもらうためにサポートまでご連絡ください。すべての選択肢については、[多要素認証](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device)を参照してください。
