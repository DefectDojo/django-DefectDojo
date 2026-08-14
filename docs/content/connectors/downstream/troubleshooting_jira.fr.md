---
title: Dépannage des erreurs Jira (ancienne version)
description: Résoudre les problèmes d'intégration Jira
weight: 2
aliases:
- /fr/issue_tracking/jira/troubleshooting_jira/
- /fr/en/share_your_findings/troubleshooting_jira/
---

Voici quelques problèmes courants liés à l'intégration Jira, ainsi que des solutions pour les résoudre.

## Je ne trouve aucun paramètre Jira dans DefectDojo

S'il n'y a aucun menu Jira dans la barre latérale, aucune section Jira dans les formulaires Produit / Engagement, et aucune option **Push to Jira** sur les Constatations, l'intégration Jira est très probablement encore désactivée dans les Paramètres système.  DefectDojo masque tous les contrôles Jira tant qu'elle n'est pas activée.

Vérifiez **Enable Jira Integration** sur la page des Paramètres système :

* Open Source : ⚙️ **Configuration \> System Settings**, puis cochez **Enable JIRA integration**.  Un **Jira webhook secret** est également requis avant que le formulaire puisse être enregistré, cliquez donc sur l'icône 🔄 pour en générer un.  Consultez le [Guide d'intégration Jira](/connectors/os_jira/os__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).
* Pro : **\<Your Edition\> Settings \> System Settings**, puis cochez **Enable Jira Integration** sous **Jira Integration Settings**.  Consultez le [Guide d'intégration Jira](/connectors/downstream/pro__jira_guide/#step-1-enable-the-jira-integration-in-system-settings).

Si le paramètre est déjà activé et que vous ne voyez toujours pas le menu Jira, il se peut que votre utilisateur ne dispose pas de la permission de configuration **View Jira Instance**, également nécessaire pour que le menu apparaisse.  Elle peut être attribuée directement sur la page Utilisateur ou via un Groupe d'utilisateurs.  Consultez [À propos des permissions et des rôles](/admin/user_management/about_perms_and_roles/#configuration-permissions).

## DefectDojo ne parvient pas du tout à atteindre Jira (ni les autres services sortants)

Si l'intégration Jira de DefectDojo échoue avec des erreurs de connexion du type « connection refused », « no route to host » ou des échecs génériques de négociation TLS — et que les identifiants eux-mêmes sont valides — il se peut que votre instance DefectDojo se trouve derrière un pare-feu qui exige que le trafic sortant transite par un proxy HTTPS sortant.

Pour les déploiements Pro sur site, définissez les variables d'environnement `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` sur le déploiement.  `dojo-compose-cli` les propage automatiquement aux conteneurs `uwsgi`, `celeryworker` et Connector.  Consultez [Exécuter DefectDojo derrière un proxy HTTPS sortant](/onprem_deployment/forward_proxy/) pour la procédure de configuration complète.

> Remarque : la définition de `HTTPS_PROXY` configure uniquement le trafic **sortant** depuis DefectDojo.  Cela n'affecte pas la capacité de Jira à délivrer des webhooks **entrants** vers DefectDojo — consultez [Les modifications apportées aux tickets Jira ne mettent pas à jour les Constatations dans DefectDojo](#changes-made-to-jira-issues-are-not-updating-findings-in-defectdojo) ci-dessous pour ce cas.

## Impossible de configurer Jira dans DefectDojo en raison d'erreurs 404, 401 ou 403
Jira Cloud :
- Consultez la documentation de l'API REST Jira Cloud sur l'authentification : https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- Vérifiez en ligne de commande que les identifiants fournis peuvent accéder aux tickets nécessaires dans Jira :

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Par exemple :
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center ou Server :
- Consultez la documentation de l'API REST Jira Data Center sur l'authentification :
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ (nom d'utilisateur + mot de passe)
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html (jeton d'accès personnel)
- Vérifiez en ligne de commande que les identifiants fournis peuvent accéder aux tickets nécessaires dans Jira :

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Par exemple :
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Lors de l'utilisation de jetons d'accès personnels :
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

Par exemple :
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

## Les comptes de service Jira ne sont pas pris en charge

Les comptes de service Jira Cloud (créés via la console d'administration Atlassian) utilisent un hôte d'API différent de celui des comptes utilisateur standards et ne sont **actuellement pas pris en charge** par l'intégration Jira de DefectDojo. Toute tentative d'utiliser un jeton d'API de compte de service ou des identifiants OAuth 2.0 provenant d'un compte de service entraînera des erreurs HTTP 403.

Pour configurer l'intégration Jira, créez un compte utilisateur Jira standard (avec une adresse e-mail valide) et générez un jeton d'API à partir de ce compte. Si vous souhaitez identifier clairement les tickets créés par DefectDojo, créez un utilisateur dédié nommé par exemple « DefectDojo » et utilisez son jeton d'API pour l'intégration.

## Je ne trouve pas d'Epic Name ID pour mon Space
Certains Spaces dans Jira, comme les Team-Managed Spaces, n'utilisent pas d'Epics et n'ont donc pas d'Epic Name ID.  Dans ce cas, définissez Epic Name ID sur 0 dans DefectDojo.

## Les Constatations sur lesquelles j'utilise « Push To Jira » n'apparaissent pas dans Jira
L'utilisation du workflow « Push To Jira » déclenche un processus asynchrone ; un ticket devrait néanmoins être créé dans Jira assez rapidement après le déclenchement de « Push To Jira ».

* Consultez vos notifications DefectDojo pour vérifier si le processus a réussi.  En cas d'échec du push, vous recevrez une réponse d'erreur de Jira dans vos notifications.

Raisons courantes pour lesquelles les tickets ne sont pas créés :
* Le Default Issue Type sélectionné n'est pas utilisable avec le Jira Space
* Les tickets du Space ont des attributs obligatoires qui empêchent leur création via DefectDojo (ce qui peut être géré via les Custom Fields dans Jira)


## Erreur : Product Misconfigured or no permissions in Jira ?

Ce message d'erreur peut apparaître lorsque vous essayez d'ajouter une configuration Jira créée à un Produit.  DefectDojo tente de valider une connexion à Jira et, si cette connexion échoue, il génère ce message d'erreur.

* Vérifiez que vos identifiants Jira sont autorisés à créer des tickets dans le Jira Space sélectionné.
* Le champ « Project Key » doit correspondre à un Jira Space valide. Les tickets Jira peuvent utiliser de nombreuses Keys différentes au sein d'un même Space ; le moyen le plus simple de confirmer votre Project Key est de consulter l'URL de ce Jira Space en particulier : elle ressemble généralement à `https://xyz.atlassian.net/jira/core/projects/JTV/board`.  Dans cet exemple, `JTV` est la Space Key.

## Les modifications apportées aux tickets Jira ne mettent pas à jour les Constatations dans DefectDojo

* Commencez par vérifier que le récepteur de webhook DefectDojo est correctement configuré et peut recevoir des mises à jour avec succès.

* Assurez-vous que le certificat SSL utilisé par DefectDojo est approuvé par JIRA. Pour JIRA Cloud, vous devez utiliser [un certificat SSL/TLS valide, signé par une autorité de certification mondialement reconnue](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

* Si vous essayez de pousser des changements de statut, vérifiez que les mappages de transition Jira sont correctement configurés (Reopen / Close Transition IDs).

* [Testez](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/) votre webhook JIRA à l'aide d'un point de terminaison public tel que Pipedream ou Beeceptor :

* Vérifiez que la Constatation est bien liée au ticket Jira. Si le ticket n'est pas lié à une Constatation DefectDojo, la requête webhook est tout de même acceptée (HTTP `200`) mais aucune Constatation n'est mise à jour.

* N'oubliez pas que le point de terminaison **renvoie toujours HTTP `200`**, qu'une mise à jour ait été appliquée ou non. Un `200` côté expéditeur (un webhook système ou une règle Jira Automation) ne confirme pas que la modification a atteint une Constatation — vérifiez le corps de la réponse et les journaux DefectDojo pour connaître le résultat réel.

* Si vous utilisez **Jira Automation** (*Send web request*) au lieu d'un webhook système, vérifiez les points suivants :
    * Le **Body** de la requête est défini sur **Custom data** et inclut un `webhookEvent` de premier niveau valant soit `"jira:issue_updated"` soit `"comment_created"`. Les options de corps **Empty** et **Jira issue data** omettent ce champ, et DefectDojo ignore toute requête dont il ne reconnaît pas le `webhookEvent`.
    * `Content-Type: application/json` est défini sur la requête — DefectDojo rejette tout autre type de contenu.
    * Pour les mises à jour de tickets, `issue.id` est l'ID **numérique** du ticket Jira (`{{issue.id}}`), et non la clé du ticket, et les champs `resolution` et `updated` sont tous deux présents (`resolution` peut être `null`). L'absence de `resolution`/`updated` entraîne l'ignorance silencieuse de la requête.
    * Pour les commentaires, l'URL `comment.self` contient le `{{issue.id}}` numérique dans son segment `.../issue/<id>/comment/...`, et les champs `body` et `updateAuthor` sont tous deux présents.
    * Si les commentaires n'apparaissent pas, vérifiez la **prévention des boucles** (loop prevention) : DefectDojo ignore un commentaire lorsque son auteur correspond au compte Jira que DefectDojo utilise pour publier des commentaires. Exécutez la règle Automation avec un autre utilisateur Jira si vous souhaitez que ces commentaires soient ingérés.
    * Utilisez l'aperçu du payload d'Automation pour vérifier que les smart values se résolvent comme prévu — leurs noms peuvent varier d'une instance Jira à l'autre.

## Les Epics Jira ne sont pas créées

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

L'intégration Jira de DefectDojo a besoin d'une valeur de customfield pour 'Epic Name'.  Cependant, il se peut que vos paramètres de Projet n'utilisent pas réellement 'Epic Name' comme champ lors de la création d'Epics.  Atlassian a effectué un changement en [août 2023](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562) qui a fusionné les champs 'Epic Name' et 'Epic Summary'.

Les Jira Spaces plus récents peuvent ne pas utiliser ce champ par défaut lors de la création d'Epics, ce qui entraîne ce message d'erreur.

Pour corriger ce problème, vous pouvez ajouter le champ 'Epic Name' à l'écran de création de tickets de votre Projet :

1. Essayez de créer une Epic dans Jira manuellement (via l'interface Jira).
2. Ouvrez le menu « … »
3. Cliquez sur 'Find Your Field'
4. Saisissez 'Epic Name'
5. Ajoutez Epic Name comme champ à cet écran en suivant les instructions de Jira.

![image](images/epic_name_error.png)

## Configuration des tentatives de reconnexion et des délais d'expiration JIRA

L'intégration JIRA de DefectDojo inclut des paramètres configurables de tentatives de reconnexion et de délais d'expiration pour gérer la limitation de débit et les problèmes de connexion. Ces paramètres sont importants pour maintenir la réactivité du système, en particulier lors de l'utilisation de workers Celery.

### Variables de configuration disponibles

Les variables d'environnement suivantes contrôlent le comportement de la connexion JIRA :

- **`DD_JIRA_MAX_RETRIES`** (par défaut : `3`) : nombre maximal de tentatives pour les erreurs récupérables. L'intégration retentera automatiquement en cas d'erreurs HTTP 429 (Too Many Requests), HTTP 503 (Service Unavailable) et d'erreurs de connexion. Consultez la [documentation sur la limitation de débit JIRA](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/) pour plus d'informations.

- **`DD_JIRA_CONNECT_TIMEOUT`** (par défaut : `10` secondes) : délai d'expiration de connexion pour établir une connexion au serveur JIRA.

- **`DD_JIRA_READ_TIMEOUT`** (par défaut : `30` secondes) : délai d'expiration de lecture pour attendre une réponse du serveur JIRA une fois la connexion établie.

**Remarque sur la limitation de débit** : la bibliothèque jira a un temps d'attente maximal intégré de 60 secondes pour les tentatives liées à la limitation de débit. Si l'en-tête `Retry-After` de JIRA indique un temps d'attente supérieur à 60 secondes, la requête échouera et ne sera pas retentée. Il s'agit d'une limitation de la version de la bibliothèque jira actuellement utilisée.

### Pourquoi des valeurs prudentes sont importantes

**Important** : il est recommandé d'utiliser des valeurs prudentes (plus basses) pour ces paramètres. Voici pourquoi :

1. **Blocage des tâches Celery** : les opérations JIRA dans DefectDojo s'exécutent sous forme de tâches Celery asynchrones. Lorsqu'une tâche attend un délai avant une nouvelle tentative, elle empêche ce worker Celery de traiter d'autres tâches.

2. **Épuisement du pool de workers** : si plusieurs opérations JIRA retentent avec de longs délais, vous pouvez rapidement épuiser votre pool de workers Celery, ce qui entraîne la mise en file d'attente d'autres tâches (pas seulement celles liées à JIRA).

3. **Réactivité du système** : des délais de nouvelle tentative longs peuvent donner l'impression que le système ne répond plus, en particulier lors de pannes JIRA ou d'événements de limitation de débit.

La limitation de débit JIRA est une fonctionnalité récente ; n'hésitez pas à nous faire savoir sur Slack ou GitHub ce qui fonctionne le mieux pour vous.

## Jira et DefectDojo sont désynchronisés

Il arrive que Jira soit hors service, que DefectDojo soit hors service, ou qu'un bug se produise dans un webhook. Dans ce cas, Jira peut se désynchroniser de DefectDojo. Si cela concerne un grand nombre de tickets, une réconciliation manuelle peut ne pas être réalisable. Pour ce scénario, il existe la commande de gestion 'jira_status_reconciliation'.

Comme cette commande nécessite un accès au backend, elle n'est pas disponible pour les utilisateurs Cloud de DefectDojo Pro ; veuillez plutôt contacter notre équipe Support pour obtenir de l'aide sur ce problème.

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

Cela peut être exécuté depuis le conteneur docker uwsgi avec la commande suivante :

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

La sortie DEBUG peut être obtenue via `-v 3`, mais seulement après avoir augmenté le niveau de journalisation à DEBUG dans votre fichier settings.dist.py ou local_settings.py

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

À la fin de la commande, un résumé CSV séparé par des points-virgules sera affiché. Celui-ci peut être capturé en redirigeant stdout vers un fichier :

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}
