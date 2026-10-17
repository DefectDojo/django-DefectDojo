---
title: Créer un nouvel utilisateur
description: Comment intégrer un nouvel utilisateur sur votre instance DefectDojo
audience: opensource
weight: 1
---

Cette page décrit le flux d'intégration recommandé pour ajouter de nouveaux utilisateurs à une instance DefectDojo.  Les utilisateurs DefectDojo peuvent être utilisés à la fois comme des comptes standards, exploités par des humains, et comme des comptes de service.

L'administrateur qui crée le compte est responsable de la transmission des identifiants initiaux (nom d'utilisateur et mot de passe) au nouvel utilisateur.

## Flux recommandé

1. **Créez le compte utilisateur** dans DefectDojo (Superuser uniquement) :
   * Accédez à **👤 Users → Users** pour ouvrir le tableau All Users.
   * Cliquez sur l'icône 🛠️ (clé et tournevis croisés).
   * Saisissez le nom et l'adresse e-mail du nouvel utilisateur.
   * Définissez un mot de passe temporaire.
   * Validez le formulaire.

2. **Accordez l'accès** selon les besoins. Ajoutez l'utilisateur à la liste Authorized Users de chaque Actif ou Organisation dont il a besoin, ou marquez-le comme staff ou superuser. Voir [Permissions Open Source](../os__authorized_users/) pour plus de détails. Un nouvel utilisateur sans aucune attribution ne pourra voir aucun Actif ni aucune Constatation.

3. **Envoyez les identifiants au nouvel utilisateur par un canal séparé** (e-mail, outil de discussion de votre équipe, ou tout autre moyen que vous utilisez habituellement pour partager des secrets). Incluez :
   * L'URL de l'instance DefectDojo.
   * Le nom d'utilisateur (généralement son adresse e-mail).
   * Le mot de passe temporaire que vous venez de définir.
   * Une note indiquant qu'il doit changer le mot de passe dès la première connexion.

4. **Le nouvel utilisateur se connecte et change l'identifiant.** Il peut soit :
   * Se connecter avec le mot de passe temporaire, puis le changer depuis son menu de profil, soit
   * Utiliser le lien **I forgot my password** sur la page de connexion pour définir directement un mot de passe sans utiliser le temporaire. Le mot de passe temporaire reste nécessaire pour que l'enregistrement initial du compte existe, mais l'utilisateur n'a pas besoin de s'en souvenir s'il utilise le flux de réinitialisation du mot de passe.

## Utilisateurs qui se sont connectés avec le SSO

DefectDojo open source ne prend en charge que les comptes locaux. Le SSO (SAML, OIDC, OAuth), LDAP et la MFA sont disponibles dans [DefectDojo Pro](/admin/sso/).

Si vous êtes passé à DefectDojo open source 3.x et que les utilisateurs SSO existants ne peuvent plus se connecter, consultez [Réactiver la connexion pour les utilisateurs SSO](../os__sso_user_local_login_fallback/).
