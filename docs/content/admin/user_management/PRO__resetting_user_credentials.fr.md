---
title: Réinitialisation groupée des identifiants utilisateur
description: Faire pivoter les jetons API et forcer la réinitialisation des mots de
  passe pour de nombreux utilisateurs à la fois depuis la liste des utilisateurs
audience: pro
weight: 2
---

La liste des **Utilisateurs** de DefectDojo Pro vous permet de faire pivoter les jetons API et de forcer la réinitialisation des mots de passe pour de nombreux utilisateurs à la fois — utile pour l'hygiène périodique des identifiants ou pour répondre à une exposition d'identifiants suspectée.

Ces actions groupées ne sont disponibles que pour les **Superusers** et les utilisateurs disposant du rôle **Global Owner**. Si vous n'avez pas l'un de ces statuts, les cases à cocher de sélection et les boutons d'action groupée n'apparaissent pas.

## Sélection des utilisateurs

Dans la liste des **Utilisateurs**, utilisez les cases à cocher pour sélectionner un ou plusieurs utilisateurs. Une barre d'actions groupées apparaît avec les boutons de réinitialisation. Chaque action vous demande de confirmer dans une boîte de dialogue avant de s'exécuter.

L'action s'applique aux utilisateurs que vous avez explicitement cochés. Vous **ne pouvez pas inclure votre propre compte** dans une réinitialisation groupée : si votre compte figure parmi les lignes sélectionnées, les boutons d'action groupée sont désactivés et un avertissement s'affiche.

## Réinitialiser les jetons API

**Réinitialiser les jetons API** fait pivoter le jeton API de chaque utilisateur sélectionné : DefectDojo supprime le jeton existant de l'utilisateur et en émet un nouveau. **Le jeton actuel de l'utilisateur cesse immédiatement de fonctionner**, donc tout script ou toute intégration utilisant l'ancien jeton doit être mis à jour avec le nouveau.

* Les nouvelles valeurs de jeton ne vous sont **pas** montrées en tant qu'administrateur. Chaque utilisateur concerné reçoit une notification **« API Token Reset »** lui indiquant de récupérer son nouveau jeton depuis l'interface (envoyée selon les paramètres de notification de cet utilisateur).

## Forcer la réinitialisation du mot de passe

**Forcer la réinitialisation du mot de passe** active l'indicateur *force-password-reset-on-next-login* sur chaque utilisateur sélectionné. La prochaine fois que cet utilisateur effectuera une requête, DefectDojo le redirigera vers la page **Change Password** et ne le laissera pas continuer tant qu'il n'aura pas défini un nouveau mot de passe. L'indicateur se réinitialise automatiquement une fois cela fait.

Gardez à l'esprit ce que cette action ne fait **pas** :

* Elle ne définit ni ne génère de façon aléatoire un mot de passe temporaire, et elle ne vous retourne aucun identifiant.

* Elle n'envoie **pas** d'e-mail ni de notification aux utilisateurs concernés. Comme il n'y a pas d'avis automatique, informez les utilisateurs concernés par un autre moyen qu'ils seront invités à changer leur mot de passe lors de leur prochaine connexion.

> **Utilisateurs SSO :** Contrairement au formulaire d'édition d'un utilisateur unique (qui désactive l'indicateur de réinitialisation forcée pour les comptes autorisés par SSO), l'action groupée applique l'indicateur à **tous** les utilisateurs sélectionnés, quel que soit leur mode d'authentification. Comme les utilisateurs SSO se connectent via votre fournisseur d'identité plutôt qu'avec un mot de passe DefectDojo, forcer une réinitialisation de mot de passe pour eux n'a généralement pas de sens — évitez d'inclure des utilisateurs exclusivement SSO dans la sélection.
