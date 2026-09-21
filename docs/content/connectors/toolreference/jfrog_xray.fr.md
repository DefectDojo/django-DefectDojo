---
title: "JFrog Xray"
description: "Comment configurer le Connecteur Upstream JFrog Xray pour DefectDojo"
weight: 81
audience: pro
---
Le connecteur JFrog Xray utilise l'API REST JFrog Xray pour récupérer les données de vulnérabilité de vos dépôts Artifactory. DefectDojo découvrira tous les dépôts de votre instance JFrog et générera des rapports de vulnérabilité via Xray, en important les constatations de façon planifiée.

#### Prérequis

Vous aurez besoin d'un jeton API ayant accès aux API Artifactory et Xray. Nous recommandons de créer un compte de service dédié pour DefectDojo. Le compte nécessite :

* Un accès en lecture aux dépôts Artifactory
* La permission de générer et consulter les rapports de vulnérabilité Xray (permission `Apply on Watches` dans Xray, ou équivalent)

#### Mappages du connecteur

1. Saisissez l'URL de base de votre instance JFrog dans le champ **Location**. Il doit s'agir de l'URL racine de votre instance JFrog, par exemple `https://your-instance.jfrog.io`. N'incluez pas de chemin final — DefectDojo construira automatiquement les chemins d'API appropriés.
2. Saisissez un **Reference Token** valide dans le champ **Secret**. Les jetons peuvent être générés sous **User Management > Access Tokens** dans l'interface JFrog Platform.
Vous devrez générer un **Reference Token** et utiliser cette valeur.

Portées de jeton requises pour JFrog Xray :

- **All Services**, car DefectDojo a besoin d'accéder à la fois aux services XRay et Artifactory
- **Manage Reports + Manage Resources** au minimum.

Par défaut, DefectDojo mappe chaque **dépôt** Artifactory comme un Enregistrement distinct. Chaque synchronisation génère un rapport de vulnérabilité complet par dépôt via Xray, de sorte que les statuts des constatations dans DefectDojo reflètent toujours l'état actuel du dépôt.

#### Filtre de dépôt (optionnel)

Par défaut, le connecteur découvre **tous** les dépôts de votre instance JFrog. Sur les instances comptant un grand nombre de dépôts — dont beaucoup peuvent ne pas être pertinents pour la revue de sécurité —, la découverte peut être limitée avec le champ optionnel **Repository Filter**, sous **Import Filters** sur le formulaire du connecteur.

Le filtre est appliqué pendant la découverte, **avant que tout travail par dépôt ne soit effectué**. Un dépôt en dehors du filtre ne coûte rien : aucun rapport Xray n'est généré pour lui et, en mode artefact, aucun de ses artefacts de premier niveau n'est énuméré. C'est donc le moyen le plus efficace de réduire à la fois le temps de synchronisation et la charge que DefectDojo impose à votre instance JFrog — plus que tout paramètre appliqué plus tard dans la synchronisation. Il est particulièrement recommandé en complément des **Artifact-Level Records** sur les grandes instances.

**Syntaxe :** une liste de clés de dépôt séparées par des virgules. Chaque entrée peut utiliser des jokers `*` :

* Une entrée contenant `*` est traitée comme un motif — `releases-*` correspond à toute clé de dépôt commençant par `releases-`, et `*docker-pr-local*` correspond à toute clé contenant `docker-pr-local`. Un `*` correspond à toute suite de caractères, y compris `/`.
* Une entrée sans `*` doit correspondre **exactement** à une clé de dépôt.
* Un dépôt est découvert s'il correspond à **n'importe quelle** entrée de la liste. Les espaces autour des virgules sont ignorés.

```
releases-*, snapshots
```

L'exemple ci-dessus découvre tous les dépôts dont la clé commence par `releases-`, plus le seul dépôt nommé exactement `snapshots`.

Remarques :

* Le filtre est une **liste d'autorisation** — une correspondance sélectionne un dépôt. Il n'existe pas de syntaxe d'exclusion ou de négation, vous ne pouvez donc pas exprimer directement « tout sauf X ».
* La correspondance est **sensible à la casse**, aussi bien pour les entrées exactes que pour les jokers. `*` est le seul caractère joker ; `?` et les plages de caractères ne sont pas pris en charge.
* **Laissez-le vide pour découvrir tous les dépôts.** Une valeur composée uniquement d'espaces ou de virgules est traitée comme vide.
* Un filtre qui ne correspond à rien ne découvre simplement rien — il n'y a pas d'erreur. Si une synchronisation ne trouve inopinément aucun dépôt, vérifiez l'entrée `repository filter scoped discovery` dans le journal du connecteur, qui indique combien de dépôts sur le total ont correspondu.
* Le champ peut être modifié après la création de la connexion.

**Modifier le filtre ultérieurement :** les dépôts qu'un filtre nouvellement restreint exclut désormais ne sont plus découverts, et leurs Enregistrements existants suivent le cycle de vie normal des produits que l'outil ne signale plus — les Enregistrements **mappés** sont marqués `MISSING` lors de la synchronisation suivante, et les Enregistrements `NEW` non mappés sont supprimés. Les constatations déjà importées dans DefectDojo ne sont pas supprimées ; le filtre régit uniquement la découverte.

#### Enregistrements au niveau des artefacts

Le bouton **Artifact-Level Records** modifie la découverte pour descendre d'un niveau sous le dépôt : chaque entrée de premier niveau sous la racine d'un dépôt (pour les dépôts Docker, chaque image ; pour les dépôts génériques, chaque fichier ou dossier de premier niveau) devient son propre Enregistrement. Chaque synchronisation génère toujours un seul rapport Xray par dépôt — DefectDojo attribue chaque vulnérabilité aux artefacts qu'elle impacte, de sorte que la charge sur votre instance JFrog n'augmente pas.

> **Vérifiez dans quel mode vous vous trouvez avant votre première synchronisation.** Artifact-Level Records est **activé par défaut pour les nouvelles installations**. Les installations antérieures à cette fonctionnalité conservent leur disposition existante au niveau du dépôt, le bouton est donc désactivé pour elles jusqu'à ce que quelqu'un l'active. Dans les deux cas, le bouton peut être modifié à tout moment — voir *Basculer une connexion existante* ci-dessous.

Avec Artifact-Level Records activé :

* Les dépôts restent des Enregistrements et deviennent des **actifs parents** : ils ne portent aucune constatation eux-mêmes, mais lorsque la fonctionnalité Asset Hierarchy est activée, DefectDojo relie automatiquement chaque actif artefact à son actif dépôt avec une relation `parent`. Les actifs peuvent alors être filtrés par parent/enfant, et les constatations remontent la hiérarchie.
* Une vulnérabilité qui impacte plusieurs artefacts est importée dans l'actif de chaque artefact affecté, de sorte que chaque actif affiche l'ensemble complet des constatations qui le concernent.
* Les constatations sont limitées à la **dernière build** de chaque artefact, de sorte que les constatations d'un artefact décrivent sa build actuelle plutôt que d'accumuler les résultats de toutes les builds que Xray a jamais analysées.
* Les relations hiérarchiques créées par le connecteur n'écrasent jamais les relations que vous avez créées manuellement. Si un actif a déjà un parent que vous avez attribué, le connecteur le laisse tel quel.
* Le jeton nécessite en plus un accès en lecture à l'API de stockage Artifactory (inclus dans les portées ci-dessus).

**Basculer une connexion existante vers Artifact-Level Records :** le bouton peut être modifié à tout moment. Lors de la synchronisation suivante, de nouveaux Enregistrements d'artefacts apparaissent pour le mappage — activez **Auto Map** sur la connexion lors du basculement pour que les constatations soient transférées sans interruption. Les actifs au niveau du dépôt cessent de recevoir des constatations et leurs constatations précédemment importées sont fermées lors de leur prochaine synchronisation (les mêmes constatations sont réimportées sous les nouveaux actifs artefacts, avec un statut actualisé) ; les notes et l'historique des anciennes constatations au niveau du dépôt restent sur l'actif dépôt. Revenir en arrière inverse ce processus : les Enregistrements de dépôt recommencent à porter des constatations (les constatations précédemment fermées se rouvrent lorsqu'elles correspondent à nouveau), et les Enregistrements d'artefacts sont marqués MISSING — leurs actifs et constatations sont conservés mais cessent d'être mis à jour, afin que vous puissiez les archiver à votre convenance.

Consultez la [documentation de l'API REST JFrog Xray](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) pour plus d'informations.
