---
title: Utiliser le Cloud Manager
description: Gérer votre abonnement et les paramètres de votre compte
weight: 1
collapsed: true
audience: pro
aliases:
- /fr/en/cloud_management/using-cloud-manager
---

Se connecter au Cloud Manager de DefectDojo vous permet de configurer les paramètres de votre compte et de gérer votre abonnement à DefectDojo Cloud.

## **Nouvel abonnement**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

Cette page vous permet de demander une nouvelle instance Cloud, [ou une instance supplémentaire](../additional-cloud-instance/), auprès de DefectDojo.

## **Gérer les abonnements**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

La page de gestion des abonnements affiche toutes vos instances Cloud actuellement actives, et vous permet de configurer les paramètres de pare-feu pour chaque instance.

### Modifier vos paramètres de pare-feu
![image](images/using_the_cloud_manager.png)

Une fois sur la page **Edit Subscription**, saisissez l'adresse IP, le masque et le libellé de la règle que vous souhaitez ajouter. Si plusieurs règles de pare-feu sont nécessaires, cliquez sur **Add New Range** pour créer une nouvelle règle vide.

![image](images/using_the_cloud_manager_2.png)

Vous pouvez également ouvrir votre pare-feu à des services externes (GitHub et Jira Cloud) depuis cet écran.  Vous pouvez aussi désactiver entièrement votre pare-feu, si vous le souhaitez, en sélectionnant **Proceed Without Firewall** dans le menu.

## Ajouter des utilisateurs supplémentaires au Cloud Portal

Si vous avez plusieurs utilisateurs auxquels vous souhaitez donner le contrôle de votre Cloud Portal / abonnement DefectDojo, vous pouvez les ajouter à l'aide de ce formulaire.  Les utilisateurs que vous souhaitez ajouter doivent avoir créé leur propre compte Cloud Portal sur cloud.defectdojo.com ; posséder un compte sur votre instance DefectDojo ne suffit pas.

![image](images/using_the_cloud_manager_5.png)

Saisissez l'adresse e-mail associée au compte Cloud Portal de l'utilisateur, puis cliquez sur Submit pour l'ajouter à votre liste d'utilisateurs liés.  Cet utilisateur pourra désormais gérer le Cloud Portal et votre abonnement DefectDojo.

## Ressources
<https://cloud.defectdojo.com/resources/>

La page Resources contient un formulaire Contact Us, que vous pouvez utiliser pour joindre notre équipe Support.

![image](images/using_the_cloud_manager_3.png)

## Outils
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

La page Tools est l'un des endroits où vous pouvez télécharger des outils Pro externes, tels que Universal Importer ou DefectDojo CLI.  Ces outils sont des add-ons externes qui permettent de construire rapidement un pipeline d'import en ligne de commande dans votre réseau. Pour en savoir plus sur ces outils, consultez la documentation [External Tools](/import_data/pro/specialized_import/external_tools/).

![image](images/using_the_cloud_manager_6.png)


## Paramètres du compte
<https://cloud.defectdojo.com/accounts/settings>

La page des paramètres du compte comporte quatre sections :

* **User Contact** vous permet de définir votre nom d'utilisateur, votre adresse e-mail, votre prénom et votre nom.
* **Email Accounts** vous permet d'ajouter des adresses e-mail supplémentaires à votre compte. L'ajout d'un compte e-mail supplémentaire envoie un e-mail de vérification à la nouvelle adresse.
* **Manage Social Accounts** vous permet de connecter DefectDojo Cloud à vos identifiants GitHub ou Google, qui peuvent alors être utilisés pour vous connecter au lieu d'un nom d'utilisateur et d'un mot de passe.
* **MFA Settings** vous permet d'ajouter un code MFA à Google Authenticator, 1Password ou une application similaire. Ajouter une étape supplémentaire à votre processus de connexion est une bonne mesure proactive pour empêcher les accès non autorisés.

### Ajouter la MFA à votre connexion au Cloud Portal
<https://cloud.defectdojo.com/settings/mfa/configure/>

Notez que cela n'ajoutera la MFA qu'à votre connexion DefectDojo Cloud, pas à la connexion de votre application DefectDojo.

![image](images/using_the_cloud_manager_4.png)

1. Commencez par installer une application d'authentification prenant en charge l'authentification par code QR sur votre smartphone ou votre ordinateur.
2. Une fois cela fait, cliquez sur **Generate QR Code**.
3. Scannez le code QR fourni dans DefectDojo à l'aide de votre application d'authentification, puis saisissez le code à six\-chiffres fourni par votre application.
4. Cliquez sur **Enable Multi\-Factor Authentication**.
