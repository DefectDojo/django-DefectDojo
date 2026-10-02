---
title: Réactiver la connexion pour les utilisateurs SSO
description: Donner un mot de passe local aux utilisateurs provisionnés via SSO après
  un passage à Open Source, où le SSO est une fonctionnalité réservée à Pro
audience: opensource
weight: 2
---

## Quand cela s'applique

SSO (SAML, OIDC, OAuth) est une fonctionnalité de [DefectDojo Pro](https://defectdojo.com). Si vous effectuez une mise à niveau vers DefectDojo open source 3.x (ou si vous quittez Pro d'une autre manière), les options de connexion SSO sont supprimées, et les utilisateurs provisionnés via SSO ne peuvent plus se connecter. Leurs comptes n'ont jamais reçu de mot de passe local, et l'interface comme l'API ne vous permettent pas d'en définir un pour eux : DefectDojo les détecte comme des comptes SSO et bloque le changement.

Il n'est **pas** nécessaire de supprimer et de recréer ces utilisateurs (ce qui ferait perdre leur historique, leurs permissions et la propriété de leurs objets). À la place, donnez à chaque compte un mot de passe local côté backend et forcez une réinitialisation du mot de passe à la prochaine connexion.

Consultez la [section SSO](/admin/sso/) et les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only) pour comprendre le contexte du SSO réservé à Pro.

## Pourquoi cela se produit

DefectDojo open source s'authentifie uniquement par rapport à la base de données d'utilisateurs locale de Django. Il détermine si un compte est un « utilisateur SSO » uniquement selon que le compte dispose ou non d'un mot de passe utilisable. Les comptes provisionnés via SSO ont été créés avec un mot de passe *inutilisable*, donc :

* la connexion locale échoue (il n'y a pas de mot de passe à vérifier), et
* le contrôle **Force password reset** dans l'interface et l'API est bloqué, avec un message indiquant que l'utilisateur est autorisé via le SSO.

Définir un véritable mot de passe lève les deux conditions à la fois : le compte peut se connecter localement, et l'indicateur de réinitialisation forcée devient modifiable.

## La solution de contournement

Exécutez ces étapes depuis le shell Django à l'intérieur du conteneur `uwsgi` :

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### Exemple pour un seul utilisateur

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

## Ce que fait l'utilisateur ensuite

Transmettez le mot de passe temporaire à chaque utilisateur par un canal séparé (e-mail, discussion d'équipe, ou tout autre moyen habituel de partage de secrets). À sa prochaine connexion, DefectDojo le redirige vers la page **Change Password** et ne le laisse aller nulle part ailleurs tant qu'il n'a pas défini son propre mot de passe. L'indicateur de réinitialisation forcée se réinitialise automatiquement une fois cela fait.

Si votre instance a le flux « I forgot my password » activé (`DD_FORGOT_PASSWORD`, activé par défaut) et l'e-mail configuré, les utilisateurs peuvent à la place utiliser le lien **I forgot my password** sur la page de connexion une fois que leur compte dispose d'un mot de passe utilisable, et définir un mot de passe sans avoir besoin du temporaire.

## Remarques

* **Kubernetes :** exécutez plutôt le shell dans le pod Django, par exemple `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell` (ajustez les noms de déploiement et de conteneur à votre version).
* Choisissez un mot de passe jetable robuste. Avec `force_password_reset = True`, l'utilisateur ne peut pas le conserver, il n'a donc besoin de survivre qu'à une seule connexion.
* Conservez au moins un compte administrateur local fonctionnel afin de ne jamais être bloqué.
