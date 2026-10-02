---
title: Authentification multifacteur (MFA)
description: Configurez la MFA sur votre propre compte, rendez-la obligatoire sur
  l'ensemble de votre instance, et récupérez un utilisateur ayant perdu son appareil
audience: pro
weight: 3
---

L'authentification multifacteur ajoute une seconde étape à la connexion : après votre mot de passe, DefectDojo demande un code à six chiffres provenant d'une application d'authentification. Nous recommandons fortement de l'exiger pour tous les utilisateurs sur les instances qui ne sont pas protégées par le SSO.

La MFA de DefectDojo Pro utilise une **application d'authentification TOTP** — Google Authenticator, 1Password, Authy, ou toute autre application capable de scanner un code QR standard. Il n'existe pas d'option par e-mail ou par SMS.

## Configurer la MFA sur votre compte

1. Accédez à **Connect \> Authorization \> MFA Settings**.
2. Sous **Personal Multi-Factor Authentication Settings**, cliquez sur **Set Up MFA**.
3. Scannez le code QR avec votre application d'authentification. Si vous ne pouvez pas le scanner, l'écran de configuration affiche également la clé sous forme de texte, que vous pouvez saisir manuellement dans votre application.
4. Saisissez le code à six chiffres affiché par votre application, puis cliquez sur **Verify & enable**.
5. DefectDojo affiche vos **codes de récupération**. Enregistrez-les en lieu sûr avant de continuer — voir ci-dessous. Cliquez sur **Copy codes**, conservez-les, puis cliquez sur **I've saved them. Continue**.

La MFA est active à partir de ce moment. Lors de votre prochaine connexion, DefectDojo vous demandera un code après votre mot de passe.

### Codes de récupération

Vous recevez **dix codes de récupération à usage unique** lorsque vous activez la MFA. Chacun peut être utilisé une seule fois, à la place d'un code de votre application d'authentification, et est consommé après utilisation.

Ils ne sont affichés **qu'une seule fois**, sur l'écran final de configuration. La page des paramètres MFA n'indique ensuite que le nombre de codes restants, pas les codes eux-mêmes.

Si vous perdez vos codes de récupération — ou souhaitez un nouveau jeu après en avoir utilisé plusieurs — cliquez sur **Regenerate Recovery Codes** sur la page des paramètres MFA. Cette action **remplace tous vos codes existants** : tous ceux que vous aviez enregistrés précédemment cessent de fonctionner immédiatement, alors enregistrez le nouveau jeu sans attendre.

Les codes de récupération sont ce qui vous permet de retrouver l'accès lorsque vous perdez votre téléphone ; conservez-les donc dans un endroit distinct de l'appareil exécutant votre application d'authentification.

### Désactiver la MFA

**Disable MFA** sur la page des paramètres MFA la désactive pour votre propre compte. Il vous suffit d'être connecté — aucun code ne vous est demandé pour confirmer.

Si votre administrateur a rendu la MFA obligatoire, vous serez invité à la reconfigurer lors de votre prochaine connexion.

## Se connecter avec la MFA

Après avoir saisi votre nom d'utilisateur et votre mot de passe, DefectDojo vous demande votre code à six chiffres. Si vous n'avez pas votre application d'authentification, saisissez à la place l'un de vos **codes de récupération** dans le même champ — ce code est alors consommé.

## Exiger la MFA pour tout le monde

Les superutilisateurs peuvent rendre la MFA obligatoire sur l'ensemble de l'instance :

1. Accédez à **Connect \> Authorization \> MFA Settings**.
2. Dans le bloc **MFA Settings** — visible uniquement par les superutilisateurs — cochez **Require Multi-Factor Authentication Globally**.
3. Envoyez.

Cette option est **désactivée par défaut**.

Une fois activée, tout utilisateur qui ne s'est pas encore inscrit est redirigé vers l'écran de configuration de la MFA lors de sa prochaine connexion, et **ne peut pas l'ignorer**. Il termine l'inscription, enregistre ses codes de récupération, puis arrive à la destination initialement prévue.

### Utilisateurs SSO

La MFA est appliquée par DefectDojo, et non déléguée à votre fournisseur d'identité. Lorsque la MFA globale est exigée, les utilisateurs qui se connectent via le SSO sont également redirigés vers la configuration de la MFA une fois que leur fournisseur les renvoie vers DefectDojo, puis un code leur est demandé lors des connexions suivantes.

Il n'existe aucun paramètre permettant d'exempter les utilisateurs SSO. Si votre fournisseur d'identité applique déjà sa propre MFA, décidez délibérément si vous souhaitez cumuler les deux — activer la MFA globale entraînera deux invites pour les utilisateurs SSO.

## Récupérer un utilisateur ayant perdu son appareil MFA

Procédez dans cet ordre :

1. **Utiliser un code de récupération.** Si l'utilisateur possède encore ses codes de récupération, il en saisit un à la place d'un code d'application lors de la connexion, puis reconfigure la MFA depuis le début.
2. **S'il est encore connecté quelque part,** il peut se rendre dans **MFA Settings** et cliquer sur **Disable MFA** sans avoir besoin d'un code, puis se réinscrire.
3. **Demander à un administrateur de réinitialiser sa MFA.** Avec un accès serveur, un administrateur peut retirer la MFA d'un compte :

   ```
   python manage.py remove_mfa --username <username>
   ```

   La commande accepte également `--user-id` ou `--email` à la place de `--username` (un seul est requis ; `--email` ne tient pas compte de la casse). Elle demande une confirmation avant d'effectuer la modification. L'utilisateur peut ensuite se connecter avec son seul mot de passe et s'inscrire à nouveau.

   Il s'agit d'une commande shell, qui nécessite donc un accès au conteneur ou à l'hôte DefectDojo. Il n'existe aucun bouton équivalent dans l'interface ni de point de terminaison dans l'API. Sur **DefectDojo Cloud**, contactez le [support DefectDojo](mailto:support@defectdojo.com) pour la faire exécuter.

Créer un compte de remplacement n'est **pas** nécessaire — la réinitialisation de la MFA préserve les autorisations, l'historique et les attributions existants de l'utilisateur.

## La MFA et l'API

Lorsqu'un utilisateur a activé la MFA, les requêtes vers `/api/v2/api-token-auth/` — le point de terminaison qui échange un nom d'utilisateur et un mot de passe contre un jeton API — doivent également inclure un code MFA, dans un champ `mfa_code` aux côtés des identifiants. Un code TOTP actuel ou un code de récupération non utilisé est accepté ; transmettre un code de récupération ici le **consomme**.

Un code manquant ou incorrect renvoie la même erreur générique *« Unable to log in with provided credentials »* qu'un mot de passe erroné ; c'est donc la première chose à vérifier si les demandes de jeton commencent à échouer après qu'un utilisateur a activé la MFA.

**Les jetons API existants continuent de fonctionner.** Activer ou désactiver la MFA ne révoque ni ne renouvelle les jetons déjà émis — la vérification MFA s'applique au moment de l'émission d'un jeton, pas à chaque requête effectuée avec celui-ci. Une automatisation de longue durée qui détient déjà un jeton n'est pas affectée par l'inscription d'un utilisateur à la MFA.
