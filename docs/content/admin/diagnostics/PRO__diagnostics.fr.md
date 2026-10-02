---
title: Diagnostics
description: 'Consultez le registre inter-sous-systèmes des tentatives d''intégration
  : ce qui est enregistré, comment le filtrer, comment les identifiants en sont exclus,
  et qui peut voir le détail technique'
weight: 1
audience: pro
---

Diagnostics est un registre unique de chaque tentative de DefectDojo pour communiquer avec quelque chose en dehors de lui-même — et des tentatives d'autres systèmes pour communiquer avec lui. Lorsqu'un ticket n'apparaît jamais, qu'un scan n'est jamais importé, ou qu'un utilisateur n'a pas pu se connecter, c'est cette page qui indique ce qui s'est passé, quand, pour quelle configuration, et qui en est à l'origine.

Diagnostics est une fonctionnalité de **DefectDojo Pro**. Vous la trouverez sous **Connect > Diagnostics**.

![Le registre Diagnostics, vue Errors](images/diagnostics_errors.png)

## Ce qui est enregistré

Une ligne est écrite par tentative, pour chaque sous-système qui communique en dehors de DefectDojo :

| Source | Ce qui génère des lignes |
| --- | --- |
| **Connector** | Les exécutions de découverte et de synchronisation des connecteurs en amont (upstream) |
| **Downstream integrator** | Les envois vers Jira, GitHub, GitLab, ServiceNow, et les autres connecteurs en aval (downstream) |
| **Jira** | L'intégration Jira historique : envois, commentaires et aperçus |
| **SSO (OIDC/OAuth2)** | Les tentatives de connexion via un fournisseur OAuth |
| **SAML** | Les assertions SAML, y compris les échecs de signature et d'attribut |
| **LDAP** | Les liaisons (binds) et recherches LDAP |
| **Import / Reimport** | Les imports de scans, que ce soit via l'interface, l'API ou une planification |
| **Rules engine** | Les évaluations de règles et les actions qu'elles tentent |
| **Scheduling** | Les exécutions planifiées, y compris celles qui n'ont jamais démarré |
| **Sensei** | Les analyses de dépôts et les exécutions de correctifs |
| **Notification** | La livraison des notifications sortantes |
| **System** | L'activité au niveau de l'instance qui n'appartient à aucun produit |

Les lignes sont écrites *en parallèle* du sous-système, jamais à sa place. Chaque adaptateur est rattaché à l'enregistrement d'origine et est délibérément conçu pour échouer sans danger (fail-safe) : si l'écriture d'une ligne de diagnostic déclenche une erreur, celle-ci est absorbée et l'opération d'origine se poursuit. Diagnostics ne peut donc jamais être la cause de l'échec d'un envoi, d'un import ou d'une connexion.

Comme les lignes sont indexées sur l'enregistrement qui les a produites, le fait de réenregistrer un enregistrement d'origine met à jour sa ligne de diagnostic existante plutôt que d'en ajouter une nouvelle. Une tentative correspond à une ligne pour toute sa durée de vie, de `Queued` à `Running` jusqu'à son résultat final.

### Champs d'une ligne

| Champ | Signification |
| --- | --- |
| **When** | Le moment où la ligne a été enregistrée ; **Started**, **Finished** et **Duration** décrivent la tentative elle-même |
| **Source** | Le sous-système, parmi ceux du tableau ci-dessus |
| **Provider** | L'outil ou le fournisseur spécifique au sein de cette source (`jira`, `github`, `okta`, un nom de scanner) |
| **Operation** | Ce qui a été tenté (`push`, `sync`, `login`, `reimport`, `rule_run`) |
| **Status** | `Queued`, `Running`, `Success`, `Failed`, `Timed out`, `Skipped`, ou `Dry run` |
| **Severity** | `Info`, `Warning`, `Error`, ou `Critical` |
| **Summary** | Un résultat en une ligne, sûr à lire d'un coup d'œil |
| **Trigger** | Ce qui a déclenché la tentative : `UI`, `API`, `Scheduled`, `Webhook`, `Automatic`, `Command line`, ou `System` |
| **Triggered by** | L'utilisateur responsable, ou `System` pour un travail sans supervision |
| **Asset** | Le produit auquel appartient la tentative ; vide signifie qu'elle est au niveau de l'instance |
| **Related object** | La constatation, l'engagement ou tout autre enregistrement concerné par la tentative |
| **Configuration** | La configuration utilisée, par son libellé |
| **External reference** | L'identifiant renvoyé par l'autre système, comme la clé d'un ticket créé |
| **Correlation ID** | Relie entre elles les lignes issues d'une même opération logique |
| **Reported detail** et **Context** | Le détail technique complet (restreint, voir [Qui voit quoi](#who-sees-what)) |

## Les quatre vues

Les onglets au-dessus du tableau sont des points de départ enregistrés, et non des filtres à reconstruire à chaque fois :

* **Errors** — échecs et délais dépassés. Celui à ouvrir en premier.
* **Successes** — la preuve qu'une intégration fonctionnelle fonctionne, utile lorsque quelqu'un signale que « rien ne se synchronise ».
* **Never completed** — les tentatives toujours `Queued` ou `Running` bien après le moment où elles auraient dû se terminer. Ce sont les silencieuses : rien n'a échoué, donc rien n'a été signalé, mais rien n'est arrivé non plus.
* **All events** — tout, sans filtre.

![All events, montrant chaque source](images/diagnostics_all_events.png)

La vue active fait partie de l'URL de la page, elle est donc partageable par lien et survit à une actualisation.

## Restreindre la liste

* **Time range** — 24 heures, 7 jours, 30 jours ou 90 jours, depuis les boutons de l'en-tête.
* **Source counts** — les compteurs colorés sous les cartes de synthèse sont aussi des filtres rapides. Cliquez sur l'un d'eux pour n'afficher que cette source ; cliquez à nouveau dessus (ou sur **Clear source filter**) pour revenir en arrière. Un seul est actif à la fois, ou aucun.
* **Filtres et tri par colonne** — chaque colonne se filtre et se trie, y compris Severity et Source. Severity se trie par gravité (`Critical` → `Info`) plutôt qu'alphabétiquement, et Source se trie selon le libellé affiché plutôt que la valeur stockée en interne.
* **Keyword Search** — recherche simultanément dans tous les champs texte.
* **Préférences de colonnes** — le sélecteur de colonnes et ses dispositions enregistrées se comportent comme sur toute autre liste Pro.

![Un compteur de source utilisé comme filtre rapide](images/diagnostics_chip_filter.png)

Cliquez sur la loupe au début d'une ligne pour ouvrir la tentative dans son intégralité :

![Un événement unique, avec la mention de rédaction](images/diagnostics_detail.png)

## Les identifiants sont supprimés avant l'écriture de la ligne

Les erreurs d'intégration citent la requête qui a échoué, et ces citations contiennent des secrets : un en-tête `Authorization`, un jeton dans une chaîne de requête, un mot de passe dans une URL de connexion. Diagnostics les supprime **à l'entrée**, de sorte que la valeur d'origine n'atteint jamais la base de données et qu'aucun changement d'avis ultérieur ne peut l'exposer.

Deux choses sont nettoyées :

* **Les valeurs sous des clés ayant la forme d'un identifiant** — tout ce dont la clé ressemble à un secret (`password`, `token`, `secret`, `api_key`, `authorization`, `private_key`, et similaires, quelle que soit la casse ou avec des tirets ou des espaces). Un petit ensemble de clés est exempté car seule leur *présence* compte, jamais leur contenu.
* **Les valeurs qui ressemblent à des identifiants où qu'elles apparaissent** — en-têtes d'autorisation bearer et basic, JWT, identifiants intégrés dans des URL (`https://user:pass@host`), préfixes de jetons de fournisseurs reconnaissables, et blocs PEM.

Chacune est remplacée par `[redacted]`. Le message environnant est conservé, afin que l'erreur reste lisible :

```text
401 Unauthorized: Authorization: [redacted]
upload rejected: https://svc:[redacted]@sftp.example/out/…
```

Les valeurs longues sont tronquées, et le contexte profondément imbriqué est aplati, afin qu'une charge utile énorme ne puisse pas alourdir le tableau.

Lorsque quelque chose a été retiré d'une ligne, la ligne l'indique, plutôt que de vous laisser deviner si le champ était vide ou vidé.

> **La rédaction est faite au mieux, par conception.** Le nettoyeur reconnaît des *formes* d'identifiants. Un secret qui ressemble à du texte ordinaire, sous une clé qui ne paraît pas sensible, peut malgré tout être enregistré. Considérez Diagnostics comme un journal opérationnel, pas comme un endroit où l'absence de secrets est garantie — et réservez le détail technique aux personnes qui en ont besoin.

## Qui voit quoi

Diagnostics est hiérarchisé, car le résumé d'un échec est utile à un propriétaire de produit, alors que la requête brute qui se cache derrière ne l'est pas.

| | Superuser | Tous les autres |
| --- | --- | --- |
| Lignes pour les produits sur lesquels ils sont autorisés | Oui | Oui |
| Lignes au niveau de l'instance (sans produit) | Oui | Non |
| Summary, source, status, severity, timings, configuration | Oui | Oui |
| **Reported detail**, **Context**, **Remote IP** | Oui | Masqués, et signalés comme tels |

Un utilisateur non superuser voit qu'un détail existe et qu'il est masqué, plutôt qu'un champ vide qui ressemblerait à une donnée manquante. Les lignes au niveau de l'instance — SSO, SAML, LDAP et autres activités n'appartenant à aucun produit — sont réservées aux superusers, puisqu'aucune appartenance à un produit ne pourrait y donner accès.

## Durée de conservation des enregistrements

Une tâche planifiée réduit le registre afin qu'il ne puisse pas croître sans limite :

| Severity | Conservé pendant |
| --- | --- |
| `Info` | 30 jours |
| `Warning`, `Error`, `Critical` | 180 jours |

Les deux fenêtres sont configurables via les paramètres `DIAGNOSTIC_EVENT_INFO_RETENTION_DAYS` et `DIAGNOSTIC_EVENT_RETENTION_DAYS`. La suppression s'exécute par lots, afin qu'une purge volumineuse ne maintienne pas une transaction longue ouverte.

## API

Le registre est en lecture seule via l'API, à `/api/v2/diagnostic_events/` :

| Endpoint | Retourne |
| --- | --- |
| `GET /api/v2/diagnostic_events/` | La liste, avec les filtres ci-dessous |
| `GET /api/v2/diagnostic_events/{id}/` | Un événement |
| `GET /api/v2/diagnostic_events/summary/` | Les compteurs derrière les cartes de l'en-tête, y compris les totaux par source |
| `GET /api/v2/diagnostic_events/choices/` | Les valeurs valides pour `source`, `status`, `severity` et `trigger` |

Paramètres utiles :

| Paramètre | Effet |
| --- | --- |
| `source`, `status`, `severity`, `trigger` | Acceptent plusieurs valeurs séparées par des virgules à la fois |
| `failures_only=true` | Échecs et délais dépassés |
| `unresolved_only=true` | Tentatives encore en file d'attente ou en cours |
| `product_name` | Filtrer par nom de produit |
| `object_model` | Filtrer par type d'enregistrement concerné par la tentative |
| `o=` | Tri, préfixé par `-` pour inverser (`o=-created_at`) |

Les mêmes règles d'accès s'appliquent : un utilisateur non superuser obtient des lignes limitées au périmètre de ses produits, avec les champs restreints masqués.

## Comprendre ce qui n'a pas fonctionné

* **Un ticket n'est jamais apparu.** Filtrez Source sur l'intégrateur (ou Jira), puis lisez Status. `Failed` vous donne la raison dans Summary ; `Queued` longtemps après coup signifie que la tâche n'a jamais été exécutée, ce qui relève d'un problème de worker ou de planification plutôt que d'identifiants.
* **Un utilisateur ne peut pas se connecter.** Filtrez Source sur SSO, SAML ou LDAP, et lisez l'échec de sa tentative — une signature d'assertion invalide, une liaison (bind) rejetée, un attribut incohérent. Ces lignes sont au niveau de l'instance, donc réservées aux superusers.
* **Un scan n'est pas apparu.** Filtrez Source sur Import / Reimport. Regardez Trigger pour distinguer un envoi planifié sans supervision d'un envoi manuel, et Triggered by pour savoir à qui demander.
* **Quelque chose retente indéfiniment.** Triez par Correlation ID, ou filtrez sur un identifiant précis, pour voir ensemble toutes les tentatives d'une même opération logique.
* **« Rien ne fonctionne ».** Ouvrez d'abord Successes pour la même période. Une liste saine à cet endroit transforme une panne vague en une panne précise.

## Voir aussi

* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — activer et désactiver les fonctionnalités Pro optionnelles
* [Connectors](/connectors/upstream/about/) — récupérer des constatations
* [Pro Integrations](/connectors/downstream/about/) — envoyer des constatations vers l'extérieur
* [Single Sign-On](/admin/sso/) — les fournisseurs d'identité dont les tentatives de connexion apparaissent ici
