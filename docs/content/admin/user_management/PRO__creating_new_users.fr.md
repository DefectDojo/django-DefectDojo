---
title: Créer un nouvel utilisateur
description: Comment intégrer un nouvel utilisateur sur votre instance DefectDojo
audience: pro
weight: 1
---

Cette page décrit le flux de travail d'intégration recommandé pour ajouter de nouveaux utilisateurs à une instance DefectDojo.  Les utilisateurs DefectDojo peuvent être utilisés à la fois comme des comptes standard, opérés par des humains, et comme des comptes de service.

L'administrateur qui crée le compte est responsable de la transmission des identifiants initiaux (nom d'utilisateur et mot de passe) au nouvel utilisateur.

## Flux de travail recommandé

1. **Créez le compte utilisateur** dans DefectDojo (superutilisateur uniquement) :
   * Accédez à **👤 Utilisateurs → ➕ Nouvel utilisateur**.
   * Saisissez le nom et l'adresse e-mail du nouvel utilisateur.
   * Définissez un mot de passe temporaire.
   * Envoyez le formulaire.

2. **Attribuez les autorisations** appropriées — appartenance à un Produit/Type de produit, Autorisations de configuration, Rôle global, ou statut de superutilisateur. Consultez [Définir les autorisations d'un utilisateur](../set_user_permissions/) pour plus de détails. Un nouvel utilisateur sans aucune attribution ne pourra voir aucun Produit ni aucune Constatation.

3. **Envoyez les identifiants au nouvel utilisateur par un canal séparé** (par e-mail, via l'outil de discussion de votre équipe, ou toute autre méthode que vous utilisez habituellement pour partager des secrets). Incluez :
   * L'URL de l'instance DefectDojo.
   * Le nom d'utilisateur (généralement son adresse e-mail).
   * Le mot de passe temporaire que vous venez de définir.
   * Une note indiquant qu'il doit changer le mot de passe et activer la MFA (si votre instance utilise la MFA) lors de la première connexion.

4. **Le nouvel utilisateur se connecte et renouvelle ses identifiants.** Il peut soit :
   * Se connecter avec le mot de passe temporaire, puis le modifier depuis son menu de profil, soit
   * Utiliser le lien **J'ai oublié mon mot de passe** sur la page de connexion pour définir directement un mot de passe sans utiliser le mot de passe temporaire. Le mot de passe temporaire reste nécessaire pour que l'enregistrement initial du compte existe, mais l'utilisateur n'a pas besoin de s'en souvenir s'il utilise le flux de réinitialisation du mot de passe.

5. **Le nouvel utilisateur configure la MFA** depuis son menu de profil. Nous recommandons fortement d'exiger la MFA pour tous les utilisateurs sur les instances qui ne sont pas protégées par le SSO.

## Utilisateurs SSO

Si votre instance est configurée avec le [SSO](../configure_sso/), le flux de travail est différent — les utilisateurs sont généralement créés lors de leur première connexion depuis le fournisseur d'identité, et il vous suffit ensuite de leur accorder une appartenance à un groupe ou des rôles.

## Récupération après la perte d'un jeton MFA

Si un utilisateur perd l'accès à son appareil MFA, il peut se connecter à l'aide de l'un des codes de récupération émis lors de son inscription. Si ceux-ci ont également été perdus, un administrateur disposant d'un accès serveur peut retirer la MFA du compte avec `python manage.py remove_mfa --username <username>`, après quoi l'utilisateur se connecte avec son mot de passe et s'inscrit à nouveau — ses autorisations et son historique sont conservés, il n'est donc pas nécessaire de créer un compte de remplacement.

Consultez [Authentification multifacteur](../pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) pour connaître toutes les options de récupération, et notez que l'accès au **Cloud Manager** lui-même est une question distincte — consultez le [guide de dépannage de la connectivité](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes).
