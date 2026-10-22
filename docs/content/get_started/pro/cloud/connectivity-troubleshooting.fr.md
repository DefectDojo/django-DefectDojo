---
title: Dépannage de la connectivité
description: Reconnectez-vous à votre instance DefectDojo
weight: 2
audience: pro
aliases:
- /fr/en/cloud_management/connectivity-troubleshooting
---

Si vous avez des difficultés à accéder à votre instance DefectDojo, voici quelques étapes à suivre pour vous reconnecter :

## J'arrive à accéder au site, mais je ne peux pas me connecter

1. Vous pouvez réinitialiser le mot de passe de votre compte depuis la page de connexion : **yourcompanyinstance.cloud.defectdojo.com/login**. Cliquez sur « I forgot my password » pour démarrer le processus.  
​

![image](images/Connectivity_Troubleshooting.png)

2. Saisissez votre adresse e-mail, puis cliquez sur « Reset my password ».  
​
3. Vous devriez recevoir un e-mail dont l'objet est « `Password reset on yourcompanyinstance.cloud.defectdojo.com` ». Cet e-mail contient un lien sur lequel vous pouvez cliquer pour définir un nouveau mot de passe.  
  

![image](images/Connectivity_Troubleshooting_2.png)

Si vous ne recevez pas d'e-mail, veuillez vérifier votre dossier Spam. Si cela ne fonctionne pas, demandez à l'administrateur DefectDojo de votre équipe de confirmer qu'un compte est bien enregistré pour vous sur votre instance.  



## Je ne peux pas accéder au site cloud.defectdojo de mon entreprise

Si le site cloud.defectdojo de votre entreprise ne se charge pas dans votre navigateur, ou si un délai d'expiration se produit, il peut être nécessaire que votre entreprise modifie ses règles de pare-feu afin d'accepter votre connexion.

Les règles de pare-feu peuvent être modifiées dans votre Cloud Manager à l'adresse <https://cloud.defectdojo.com/accounts/manage_subscriptions>.

Si votre entreprise utilise un VPN partagé, un serveur proxy ou un outil similaire, assurez-vous qu'il est autorisé à se connecter à DefectDojo et que son adresse IP est incluse dans les règles de pare-feu de DefectDojo.

Si le problème persiste, veuillez contacter [support@defectdojo.com](mailto:support@defectdojo.com) .



## Je ne peux pas me connecter au Cloud Manager

Si vous ne parvenez pas à accéder au Cloud Manager, accédez à la page de connexion à l'adresse <https://cloud.defectdojo.com/accounts/login/> et cliquez sur **« Forgot your password? »**


![image](images/Connectivity_Troubleshooting_3.png)  
Vous serez invité à saisir votre adresse e-mail, et notre équipe vous enverra un e-mail contenant un lien pour réinitialiser votre mot de passe et en saisir un nouveau. 

Veuillez noter que cette méthode de connexion ne fonctionne que pour le **Cloud Manager**, un site d'administration auquel tous les membres de votre équipe n'ont pas forcément accès. Pour vous connecter directement à votre instance afin d'utiliser DefectDojo, vous devez vous connecter directement à **yourcompanyinstance.cloud.defectdojo.com/login**.



## J'ai perdu l'accès à mes codes MFA

* **Pour le Cloud Manager :** Si vous perdez l'accès à vos codes MFA, ou à votre application d'authentification, veuillez contacter le support DefectDojo à l'adresse [support@defectdojo.com](mailto:support@defectdojo.com).
* **Pour une instance DefectDojo :** Essayez d'abord l'un des **codes de récupération** délivrés lors de la configuration du MFA — à saisir à la place du code à six chiffres lors de la connexion. Si ceux-ci ne sont pas disponibles, un administrateur ayant accès au serveur peut désactiver le MFA du compte à l'aide de `python manage.py remove_mfa --username <username>` ; l'utilisateur se connecte alors avec son mot de passe et se réinscrit, en conservant l'ensemble de ses permissions et de son historique existants. Sur DefectDojo Cloud, contactez le support pour faire exécuter cette commande. Voir [Authentification multifacteur](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) pour connaître toutes les options.
