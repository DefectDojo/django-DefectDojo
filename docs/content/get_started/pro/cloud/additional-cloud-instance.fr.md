---
title: Configurer une instance Cloud supplémentaire
description: Ajoutez une instance de test, de développement ou toute autre instance
  DefectDojo à votre compte
weight: 3
audience: pro
aliases:
- /fr/en/cloud_management/additional-cloud-instance
---

Le processus d'ajout d'une deuxième instance Cloud est plus ou moins le même que celui de l'ajout de votre première instance. Ce guide suppose que vous avez déjà configuré votre serveur DefectDojo initial et que vous avez un accord avec notre équipe commerciale pour ajouter une autre instance.

Si vous n'avez pas encore demandé d'instance Cloud supplémentaire, veuillez contacter [info@defectdojo.com](mailto:info@defectdojo.com) avant de continuer.

## Étape 1 : Ouvrir le processus de nouvel abonnement

Vous pouvez démarrer ce processus depuis le lien suivant : <https://cloud.defectdojo.com/accounts/onboarding/step_1>, ou en cliquant sur 🛒 **New Subscription** depuis la page Cloud Manager (cloud.defectdojo.com).

![image](images/request_a_trial.png)

## Étape 2 : Définissez votre Server Label

Saisissez le **Name** de votre entreprise et le **Server Label** que vous souhaitez utiliser avec DefectDojo. Un domaine personnalisé sera ensuite créé pour votre instance DefectDojo sur nos serveurs.

Conservez le même nom d'entreprise qu'auparavant, mais créez un nouveau Server Label et cochez le bouton « **Use Server Label in Domain** », afin de pouvoir facilement différencier vos serveurs.

![image](images/request_a_trial_2.png)

## Étape 3 : Sélectionnez un Server Location

Sélectionnez un Server Location dans le menu déroulant. Comme précédemment, nous recommandons de choisir un serveur géographiquement le plus proche possible de vos utilisateurs afin de réduire la latence.

![image](images/request_a_trial_3.png)

## Étape 4 : Configurez vos règles de pare-feu

Saisissez les plages d'adresses IP, le masque de sous-réseau et les libellés que vous souhaitez autoriser à accéder à DefectDojo. Des adresses IP et des règles supplémentaires peuvent être ajoutées ou modifiées par votre équipe une fois votre instance opérationnelle.

Si vous le souhaitez, ces règles de pare-feu peuvent être différentes des règles de votre instance DefectDojo principale.

![image](images/request_a_trial_4.png)

Si vous souhaitez utiliser des services externes avec cette instance (GitHub ou JIRA), cochez les cases appropriées répertoriées sous **Select External Services.**

Vous pouvez également continuer sans pare-feu en sélectionnant **Proceed Without Firewall**.  Votre pare-feu pourra être réactivé ultérieurement.

## Étape 5 : Confirmez votre type de plan et la fréquence de facturation

À la fin de notre processus, vous serez mis en relation avec notre équipe commerciale, qui pourra établir un devis précis pour votre nouveau serveur. Nous vous recommandons de sélectionner le Plan Type correspondant aux spécifications de serveur dont vous avez besoin pour la nouvelle instance. 

![image](images/request_a_trial_5.png)

Un second serveur peut ne pas nécessiter les mêmes exigences de stockage, de CPU et de RAM que votre instance « principale », mais cela dépendra des besoins techniques de votre équipe.

## Étape 6 : Vérifiez et envoyez votre demande

Nous vous inviterons à relire votre demande une dernière fois. Une fois celle-ci envoyée, seules les règles de pare-feu pourront être modifiées par votre équipe sans l'aide du support.

![image](images/request_a_trial_6.png)

Après avoir consulté et accepté le contrat de licence et de support de DefectDojo, vous pouvez procéder au **Checkout With Stripe**, ou, si vous disposez déjà d'un accord de facturation, cliquer sur **Contact Sales**.

Notre équipe de support vous contactera avec vos identifiants de connexion une fois votre serveur approuvé et provisionné.
