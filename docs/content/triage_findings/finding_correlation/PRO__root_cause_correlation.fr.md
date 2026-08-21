---
title: Corrélation de cause racine
description: Regrouper les Constatations qui partagent une cause racine -- le même
  composant vulnérable, le même CVE, la même ressource d'infrastructure ou la même
  faiblesse sur une URL -- afin qu'un correctif unique puisse être relié à chaque
  Constatation qu'il résout
weight: 1
audience: pro
---

Une bibliothèque vulnérable intégrée dans quarante services produit quarante Constatations. Chacune est réelle, chacune
est triée séparément, et chacune est corrigée par la même mise à jour de version unique. La **Corrélation de cause
racine** rend cette relation explicite : DefectDojo Pro regroupe les Constatations qui partagent une cause
racine dans une liste classée de **Causes racines**, afin que vous puissiez voir le correctif unique et tout ce qu'il résout.

La corrélation est **additive et non destructive**. Chaque Constatation reste visible indépendamment,
conserve son propre statut, et est triée exactement comme avant. La corrélation ne fait qu'ajouter des liens entre
les Constatations, les nœuds de cluster dans lesquels ces liens se regroupent, et les preuves qui ont produit chaque lien.

> **La corrélation n'est pas la déduplication.** La [déduplication](/triage_findings/finding_deduplication/)
> détermine que deux rapports décrivent la *même* Constatation et en marque une comme doublon. La corrélation
> relie des Constatations *différentes* qui partagent une cause, et ne marque jamais rien comme
> doublon. Les deux fonctionnent indépendamment et peuvent être activées toutes les deux.

## Activer la corrélation de cause racine

La corrélation de cause racine est en **Bêta**, elle est contrôlée par un indicateur de fonctionnalité (feature flag) et elle est **désactivée par défaut**.
Un superutilisateur peut l'activer depuis **Paramètres > Indicateurs de fonctionnalité** sur les instances Cloud comme On-Premise.
Voir [Indicateurs de fonctionnalité](/admin/feature_flags/pro__feature_flags/).

Tant que l'indicateur est désactivé, le moteur ne fait absolument rien : aucun cluster n'est construit, aucun lien n'est
créé, et rien n'est déclenché après un import.

Après avoir activé l'indicateur, les Constatations existantes ne sont **pas** corrélées rétroactivement tant qu'elles
n'ont pas été réimportées ou que vous n'avez pas exécuté un remplissage rétroactif (voir
[Remplissage rétroactif des Constatations existantes](#backfilling-existing-findings)).

## Ce qui est corrélé

La corrélation regroupe sur quatre signaux. Trois d'entre eux sont **exacts** -- un lien n'est créé que lorsque
deux Constatations désignent réellement la même chose -- et un est une heuristique signalée comme telle.

| Type de cause racine | Les Constatations sont regroupées lorsqu'elles... | Exemple | Correspondance |
|---|---|---|---|
| **Composant** | référencent le même composant logiciel à la même version | `log4j-core 2.14.1` | Exacte |
| **CVE** | référencent le même identifiant CVE | `CVE-2021-44228` | Exacte |
| **Ressource** | nomment le même objet d'infrastructure | `aws_s3_bucket.logs` | Exacte |
| **Point de terminaison** | signalent la même classe de faiblesse à la même URL | `CWE-79 at example.com/search` | Heuristique |

Une Constatation rejoint **tous** les clusters qui s'appliquent à elle, pas seulement un. Une Constatation SCA pour
`log4j-core 2.14.1` portant trois CVE rejoint quatre Causes racines : son cluster de composant et un
cluster par CVE. C'est ce qui permet à une Constatation d'image de conteneur qui ne signale qu'un CVE de se corréler
avec la Constatation SCA qui signale le composant.

### Correspondance des composants

Lorsque le modèle de données Locations est utilisé, les composants sont indexés sur l'**URL de paquet (purl)**,
avec les qualificatifs et les sous-chemins supprimés, de sorte que le même paquet signalé sur différentes distributions
ou architectures forme un seul cluster plutôt que plusieurs. Les Constatations qui ne portent que les champs hérités
`component_name` / `component_version` sont indexées sur ceux-ci à la place.

Les Constatations sans composant exploitable sont ignorées plutôt que regroupées : une version manquante, ou
l'espace réservé `unknown-package` que certains formats SBOM émettent, ferait sinon s'effondrer chaque
ligne sans composant dans un cluster dénué de sens.

### Correspondance des CVE

Les identifiants CVE sont mis en majuscules et nettoyés, de sorte que `cve-2021-44228` et `CVE-2021-44228` atterrissent dans
le même cluster. Seuls les identifiants CVE correspondent — GHSA, GO, RUSTSEC et les autres préfixes d'avis sont
reconnus comme des identifiants de vulnérabilité ailleurs dans DefectDojo, mais ne forment pas encore de Causes racines.

### Correspondance des ressources

Les outils de posture cloud (CSPM) et d'infrastructure en tant que code (IaC) signalent une **ressource** plutôt qu'un
paquet : un bucket S3, un espace de noms Kubernetes, un bloc de ressource Terraform. Ces Constatations portent un
nom mais pas de version, elles ne sont donc pas des composants logiciels et ne sont pas mises en correspondance comme tels.

La correspondance des ressources les regroupe sur l'identifiant de la ressource, normalisé en casse afin que les
outils qui l'orthographient différemment concordent malgré tout. C'est une jointure exacte, et c'est ce qui permet à
une Constatation IaC concernant `aws_s3_bucket.logs` de se retrouver dans la même Cause racine que la Constatation
CSPM d'exécution concernant le bucket déployé.

Seuls les identifiants qualifiés sont mis en correspondance -- un nom de ressource porte un séparateur de type ou
de chemin (`.`, `/`, `:`). Un simple mot isolé est ignoré, de sorte qu'une Constatation dont le scanner a simplement
omis la version du composant n'est pas entraînée dans un cluster de ressources avec lequel elle n'a rien à voir.

### Correspondance des points de terminaison

Deux outils DAST analysant la même application signalent souvent tous deux la même faiblesse à la même URL. La
correspondance des points de terminaison les regroupe : la Cause racine est une **classe de faiblesse à un
emplacement**, par exemple `CWE-79 at example.com/search`.

C'est le seul signal **heuristique**, et il est indiqué comme tel partout où il apparaît. Un purl ou un CVE partagé
est une identité ; « même CWE, même URL » est un jugement, et un examinateur doit pouvoir l'apprécier différemment.
Le détail du cluster indique le type de correspondance de chaque membre.

Le CWE est obligatoire. Une URL à elle seule est un lieu, pas une cause -- regrouper chaque Constatation à
`/search` quel que soit le problème produirait de grands clusters dénués de sens.

Les chaînes de requête, les fragments et les ports sont ignorés lors de la comparaison des URL, de sorte que
`/search?q=a` et `/search?q=b` désignent le même endroit, tout comme le même service sur les ports 443 et 8443.

> **Cela ne corrèle pas le SAST avec le DAST.** Les constatations statiques identifient un fichier source et les
> constatations dynamiques identifient une URL ; établir une correspondance entre les deux nécessite une carte de
> routes que DefectDojo ne possède pas.
> La correspondance des points de terminaison relie les constatations dynamiques entre elles.

### Lorsqu'un CVE est déjà couvert par un composant

Une Constatation rejoint sa cause de composant *et* chacune de ses causes CVE, de sorte qu'une Constatation SCA pour
`log4j-core 2.14.1` portant deux CVE produit trois Causes racines. Livrées à elles-mêmes, les trois se disputent le
haut de la liste classée — mais une seule d'entre elles représente un vrai travail. Mettre à jour `log4j-core`
vers une version corrigée résout les deux CVE d'un coup ; il n'existe pas d'action distincte « corriger CVE-2021-44228 ».

Une Cause racine de type CVE est donc marquée **couverte** lorsque *chacune* de ses Constatations membres actives
est également membre actif d'une seule cause de composant ou de ressource. Les causes couvertes sont masquées par
défaut de la page des Causes racines, ce qui limite la liste aux éléments sur lesquels vous pouvez réellement agir.

Dès qu'**un seul** membre se trouve en dehors de ce composant, le CVE redevient autonome. C'est le cas de la
Constatation d'image de conteneur qui ne signale qu'un CVE sans composant associé : aucun correctif de composant ne
l'atteint, donc le CVE représente réellement un travail distinct. C'est exactement le cas transversal que la
corrélation existe pour mettre en évidence, et il n'est jamais masqué.

Activez **Afficher les CVE couverts** au-dessus du tableau pour les voir. Chacun est étiqueté avec la cause qui le
couvre, afin qu'il soit clair quel correctif le résout. Les causes couvertes sont uniquement masquées de la liste
par défaut — elles conservent leurs membres, leurs preuves et leurs retours, elles restent accessibles depuis le
panneau des Causes racines d'une Constatation, et un lien enregistré vers l'une d'elles s'ouvre toujours.

La couverture est réévaluée à chaque exécution, dans les deux sens : un CVE cesse d'être couvert dès qu'une
Constatation non couverte apparaît, et redevient couvert une fois que cette Constatation est corrigée ou triée.
Rejeter un lien retire également ce membre du calcul, puisque vous avez indiqué qu'il n'a pas sa place.

Les causes de composant et de ressource ne sont jamais marquées comme couvertes, même lorsque leurs membres
chevauchent ceux d'une autre. Chacune a sa propre version à mettre à jour, donc chacune représente un travail réel.

### Quelles Constatations sont éligibles

Seules les Constatations actives et exploitables sont corrélées. Une Constatation est exclue tant qu'elle est
inactive, Atténué, Doublon, Faux positif, Hors périmètre, ou Risque accepté. Les Constatations sortent de leurs
clusters au fur et à mesure qu'elles sont triées, de sorte que les décomptes d'une Cause racine décrivent toujours
le travail restant.

## Lecture de la page des Causes racines

Ouvrez **Causes racines** dans la section **Gérer** de la barre latérale. La page répertorie toutes les Causes
racines auxquelles vous avez accès, classées de sorte que les plus importantes et les plus risquées apparaissent
en premier.

| Colonne | Ce qu'elle indique |
|---|---|
| **Cause racine** | Le composant et sa version, ou le CVE |
| **Type** | Composant, CVE, Ressource ou Point de terminaison |
| **Correctif** | La version qui le corrige, lorsque les membres du cluster s'accordent sur une seule |
| **CVE** | Chaque CVE observé parmi les membres du cluster (clusters de composants) |
| **Constatations actives** | Le nombre de Constatations en cours que cette cause représente |
| **Produits** | Rayon d'impact — combien de Produits sont affectés |
| **Risque** | Risque agrégé, cumulé à partir des sévérités des membres actifs |
| **Muet** | Si le cluster a été mis en sourdine |

Les causes CVE qu'une cause de composant ou de ressource couvre déjà entièrement sont masquées sauf si
**Afficher les CVE couverts** est activé ; voir
[Lorsqu'un CVE est déjà couvert par un composant](#when-a-cve-is-already-covered-by-a-component).

Sélectionner une ligne ouvre le cluster, qui répertorie chaque Constatation membre avec sa sévérité, son Produit,
son domaine, son type de **correspondance**, et la **preuve** qui l'associe. Chaque preuve est enregistrée par
lien, de sorte qu'un cluster peut toujours s'expliquer lui-même : un lien de composant enregistre le purl sur
lequel il correspond, un lien CVE enregistre l'identifiant, un lien de point de terminaison enregistre l'URL et
le CWE. La colonne **Correspondance** indique `exact` pour les liens de composant, de CVE et de ressource, et
`heuristic` pour les liens de point de terminaison, afin qu'un jugement ne soit jamais présenté comme une identité.

Le risque agrégé est une somme déterministe des sévérités des membres actifs (Critique 100, Élevée 70, Moyenne 40,
Faible 10, Info 1). Il ne dépend pas de l'activation du moteur de priorisation.

**Correctif** est tiré des versions de correctif propres à chaque membre, et n'est affiché que lorsque tous les
membres qui en signalent une signalent la même. Les scanners ne sont pas toujours d'accord, et un cluster de CVE
peut couvrir des composants corrigés chacun à une version différente ; lorsqu'il n'y a pas de réponse unique, la
colonne est laissée vide plutôt que d'en choisir une.

### Ce que vous voyez est limité à vos droits d'accès

Les membres, les décomptes et le rayon d'impact sont filtrés en fonction des Constatations que vous êtes autorisé
à voir, et le classement est calculé après ce filtrage. Deux utilisateurs disposant d'accès différents aux
Produits verront donc des décomptes différents pour la même Cause racine, et un cluster dont vous ne pouvez voir
aucun membre n'apparaît tout simplement pas pour vous.

## Où d'autre la corrélation apparaît

### Sur une Constatation

La page d'une Constatation comporte un panneau **Causes racines** répertoriant chaque cluster auquel elle
appartient, réparti entre le composant vulnérable (ou la ressource) et les CVE qu'elle partage. C'est généralement
là que la corrélation est la plus utile : vous êtes déjà en train de trier une Constatation et elle vous indique
que le correctif est partagé. Les liens que vous avez rejetés n'y réapparaissent pas.

### Dans la priorité des constatations

Une Cause racine qui s'étend sur de nombreux Produits rend chacune de ses Constatations membres plus urgente, car
le correctif unique les résout toutes. La priorité augmente donc avec le **rayon d'impact de la Cause racine la
plus étendue à laquelle une Constatation appartient** :

- Un cluster confiné à un seul Produit n'ajoute rien -- il n'y a pas d'histoire du type « un correctif en résout
  beaucoup ».
- Chaque Produit affecté supplémentaire ajoute un peu plus, jusqu'à un plafond, de sorte qu'un cluster très étendu
  ne peut pas l'emporter sur la sévérité.
- C'est le cluster le plus étendu qui compte, pas la somme de tous, de sorte qu'une Constatation n'est pas
  priorisée simplement parce qu'elle porte de nombreux identifiants CVE.
- Les liens que vous avez **rejetés** cessent de compter. Un cluster **mis en sourdine** continue de compter : la
  mise en sourdine le masque de la liste classée, elle ne signifie pas que les Constatations ne sont pas liées.

Le poids est réglable par Produit via le multiplicateur **Corrélation** dans le moteur de priorisation, aux côtés
de la Sévérité, l'Exploitabilité, les Points de terminaison et l'Accessibilité. Le terme entier disparaît lorsque
l'indicateur de fonctionnalité est désactivé, de sorte que les scores restent inchangés sur une instance qui
n'utilise pas la corrélation.

### Sur un tableau de bord

**Top Root Causes** (meilleures causes racines) est disponible comme widget de tableau de bord, répertoriant les
clusters les mieux classés avec leur nombre de constatations, les Produits affectés et le risque. Ajoutez-le
depuis le sélecteur de widgets ; il n'y apparaît que lorsque la fonctionnalité est activée. Ses décomptes sont
limités à votre accès de la même manière que la page.

## Donner un retour sur un cluster

La corrélation est un jugement porté sur vos données, vous pouvez donc le corriger.

- **Confirmer** un membre pour indiquer que le lien est correct.
- **Rejeter** un membre pour indiquer qu'il ne l'est pas, ce qui le retire de la liste des membres actifs du
  cluster.
- **Mettre en sourdine** une Cause racine entière pour qu'elle cesse de concurrencer les autres dans la liste
  classée. **Réactiver le son** la restaure.

Les retours sont durables. Les variations habituelles liées à un réimport — une Constatation atténuée puis
réactivée — n'effacent pas une confirmation ou un rejet, et un cluster mis en sourdine n'est jamais nettoyé même
s'il n'a temporairement plus de membres. Seuls les liens que le système a créés de lui-même sont réconciliés
lorsqu'ils cessent de s'appliquer.

## Comment et quand la corrélation s'exécute

La corrélation s'exécute **automatiquement et de manière asynchrone après chaque import et réimport**, sur les
Constatations affectées par cet import. Elle fonctionne au mieux (best-effort) : un échec au sein de la
corrélation est journalisé et absorbé, et ne fait jamais échouer l'import qui l'a déclenché.

Étant idempotente, sa réexécution sur les mêmes Constatations converge vers le même résultat plutôt que de
dupliquer quoi que ce soit. Lorsque les Constatations changent, le moteur effectue également une réconciliation :
une mise à jour de version de composant déplace la Constatation vers le nouveau cluster et supprime l'ancien une
fois qu'il est vide.

### Remplissage rétroactif des Constatations existantes

Pour corréler les Constatations antérieures à l'activation de la fonctionnalité, exécutez la commande de gestion.
Omettez l'argument pour recalculer l'ensemble du portefeuille, ou limitez-la à un seul Produit :

```bash
python manage.py recompute_correlations
python manage.py recompute_correlations --product-id 42
```

## Ce que l'API expose

Les Causes racines sont accessibles en lecture via l'API standard, ce qui vous permet de les intégrer dans un
rapport, d'ouvrir des tickets à partir d'elles, ou de les suivre comme métrique sans passer par l'interface
utilisateur.

- `GET /api/v2/root_causes/` les répertorie, classées de la même manière que sur la page.
- `GET /api/v2/root_causes/{id}/` renvoie une Cause racine ainsi que ses Constatations membres, chacune avec la
  preuve qui la relie et si la correspondance était exacte ou heuristique.

Les deux sont en lecture seule. Confirmer, rejeter et mettre en sourdine se font depuis l'interface utilisateur
pour l'instant ; ces actions ne sont délibérément pas publiées tant que la fonctionnalité est en Bêta, afin que
leur ajout ultérieur ne puisse rien casser de ce que vous avez déjà construit.

Filtres sur la liste : `cause_type` (`exact` ou `in`), `muted`, `identity_key` (`exact` ou `icontains`) et
`display_name__icontains`.

Deux comportements à connaître avant d'écrire des scripts contre cette API :

- **Les décomptes sont limités à l'accès du jeton**, exactement comme dans l'interface utilisateur. Deux jetons
  disposant d'accès différents aux Produits signaleront des `active_member_count`, `product_count` et
  `risk_score` différents pour la même Cause racine. Ceci est intentionnel -- les chiffres décrivent ce que
  *cet* appelant peut voir -- ne les traitez donc pas comme des totaux portant sur l'ensemble du portefeuille.
- **Les causes CVE couvertes sont exclues de la liste**, mais restent toujours récupérables par id. Passez
  `?include_subsumed=true` pour les inclure ; un id de Cause racine que vous avez stocké précédemment continue de
  fonctionner via `GET /api/v2/root_causes/{id}/` même après qu'elle devient couverte. Chaque cause couverte
  porte les champs `subsumed_by_id` et `subsumed_by_name` afin que vous puissiez voir quel correctif la résout.

Si l'indicateur de fonctionnalité est désactivé, les deux points de terminaison renvoient **403**, pas 404 -- le
point de terminaison existe, il n'est simplement pas activé.

## Interaction avec la déduplication globale des composants

La [déduplication globale des composants](/triage_findings/finding_deduplication/pro__global_component_deduplication/)
marque les Constatations SCA inter-Produits comme des doublons, et les doublons ne sont pas corrélés. Avec les
deux fonctionnalités activées, le nombre de membres d'une Cause racine reflète donc les originaux survivants
plutôt que chaque occurrence. Les deux s'appuient également sur des éléments différents — la déduplication
globale des composants se base sur le nom et la version du composant, tandis que la corrélation utilise l'URL de
paquet complète — l'activation simultanée des deux est donc prise en charge, mais les décomptes qu'elles
produisent ne sont pas directement comparables.
