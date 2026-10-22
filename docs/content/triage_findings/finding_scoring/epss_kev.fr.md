---
title: EPSS / KEV
description: Comment DefectDojo Pro enrichit les Constatations avec les données EPSS
  et CISA KEV, quand la synchronisation a lieu, et comment cela détermine la priorité
audience: pro
weight: 2
aliases:
- /fr/triage_findings/epss_kev/
---

DefectDojo Pro enrichit automatiquement vos Constatations à l'aide de deux sources externes de renseignement sur les menaces — **EPSS** et **CISA KEV** — afin que la priorisation reflète la probabilité qu'une vulnérabilité soit exploitée, et pas seulement sa sévérité CVSS. Les deux sources se rattachent aux Constatations par **CVE**, sont actualisées selon une **planification quotidienne**, et alimentent directement le score de **priorité** calculé pour chaque Constatation.

Les données d'enrichissement sont stockées **une seule fois par vulnérabilité**, puis appliquées à chaque Constatation qui y fait référence. Cela signifie qu'un CVE observé sur dix mille Constatations n'est consulté qu'une seule fois, et que vous pouvez examiner ses valeurs EPSS et KEV directement dans l'**Explorateur de vulnérabilités** — pas seulement Constatation par Constatation.

Sur DefectDojo Cloud, l'enrichissement est entièrement géré : DefectDojo maintient les données de renseignement sur les menaces sous-jacentes et les livre à votre instance. Il n'y a rien à installer, aucune URL de flux à configurer, et aucune tâche quotidienne à planifier — cela s'exécute pour vous.

## Les deux sources

### EPSS — Exploit Prediction Scoring System

[EPSS](https://www.first.org/epss/) est un modèle piloté par les données, publié par FIRST, qui estime la probabilité qu'un CVE donné soit exploité en conditions réelles dans les 30 prochains jours. DefectDojo Pro stocke deux valeurs EPSS sur chaque Constatation correspondante :

| Field | Meaning |
| --- | --- |
| **EPSS Score** | Probabilité d'exploitation dans les 30 prochains jours, de `0.0` à `1.0` (par ex. `0.94` = 94 %). |
| **EPSS Percentile** | Le classement de ce CVE par rapport à tous les CVE notés, de `0.0` à `1.0` (par ex. `0.99` = dans le top 1 % des plus susceptibles d'être exploités). |

Lorsqu'une seule Constatation comporte **plusieurs CVE**, DefectDojo conserve le **score EPSS le plus élevé** parmi eux et l'associe au percentile de ce même CVE. Le percentile appartient toujours au même CVE que le score — les deux ne sont jamais mélangés entre différents CVE, car un percentile n'a de sens qu'associé à son propre score.

### KEV — CISA Known Exploited Vulnerabilities

Le [catalogue CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) est la liste officielle du gouvernement américain des vulnérabilités confirmées comme ayant été exploitées en conditions réelles. Contrairement à l'EPSS (une prédiction), le KEV constate une exploitation réelle observée. DefectDojo Pro stocke trois valeurs KEV sur chaque Constatation correspondante :

| Field | Meaning |
| --- | --- |
| **Known Exploited** | `True` lorsque le CVE figure dans le catalogue CISA KEV. |
| **Ransomware Used** | `True` lorsque la CISA indique que le CVE a été exploité dans des campagnes de ransomware. |
| **KEV Date** | La date à laquelle la vulnérabilité a été ajoutée au catalogue KEV. |

Lorsqu'une Constatation comporte **plusieurs CVE**, elle est marquée **Known Exploited** si **au moins un** de ses CVE figure dans le catalogue, **Ransomware Used** si au moins un y correspond, et la **KEV Date** correspond à la date d'ajout au catalogue la plus ancienne parmi eux.

Un signal KEV n'est jamais masqué par un autre CVE ayant un score EPSS plus élevé. Si une Constatation comporte un CVE avec un score EPSS élevé qui n'*est pas* listé au KEV, et un autre avec un score EPSS faible qui *l'est*, la Constatation prend le score EPSS élevé **et** est marquée Known Exploited — chaque champ reflète indépendamment le pire cas parmi les CVE de la Constatation.

> **Les Constatations sans CVE ne sont pas enrichies.** Les deux sources se rattachent strictement à des identifiants CVE (`CVE-YYYY-NNNNN`). Une Constatation sans CVE — ou avec uniquement un identifiant spécifique à un éditeur ou de type GHSA — ne reçoit aucune donnée EPSS ou KEV.

## Quand la synchronisation a lieu

L'enrichissement s'exécute **une fois par jour, automatiquement**. Chaque exécution se déroule en deux étapes :

1. **Actualiser les données de vulnérabilité.** Chaque CVE connu de DefectDojo est revérifié par rapport aux dernières données EPSS et KEV, et l'enregistrement propre à cette vulnérabilité est mis à jour.
2. **Appliquer les changements aux Constatations.** Seules les vulnérabilités dont les valeurs ont réellement *changé* sont répercutées sur les Constatations qui y font référence, et seules ces Constatations sont recalculées.

Comme la seconde étape est pilotée par ce qui a changé, une journée calme ne coûte presque rien : si aucune des deux sources n'a publié de nouveauté, l'exécution se termine sans réécrire vos Constatations. Lorsqu'un changement survient — un score EPSS évolue, ou un CVE est ajouté au catalogue KEV — chaque Constatation concernée le récupère lors de l'exécution suivante.

Quelques conséquences à bien comprendre :

- **Les Constatations sont généralement enrichies dès leur import.** Depuis la **v3.2.0**, l'enrichissement EPSS/KEV est appliqué au moment de l'import, si bien qu'une Constatation avec un CVE nouvellement importée n'a normalement pas à attendre le prochain cycle quotidien pour afficher des valeurs. Le délai réel dépend du fait que DefectDojo ait déjà ou non consulté ce CVE — voir [Ce que couvre « enrichi au moment de l'import »](#what-enriched-at-import-time-covers) ci-dessous. L'exécution quotidienne continue de s'appliquer par-dessus, pour maintenir ces valeurs à jour à mesure que les scores EPSS évoluent et que le catalogue KEV change. Si une Constatation que vous attendiez enrichie ne l'est pas, vous pouvez [lancer une synchronisation à la demande](#running-a-sync-on-demand).
- **Les valeurs sont maintenues à jour, pas figées.** Un CVE ajouté au catalogue KEV fera basculer une Constatation existante vers **Known Exploited** lors de l'exécution suivante — aucun réimport n'est nécessaire.
- **Les retraits du KEV sont respectés.** Si les CVE d'une Constatation ne sont plus listés au KEV, l'exécution efface les valeurs obsolètes **Known Exploited** / **Ransomware Used** / **KEV Date** au lieu de les laisser telles quelles.

### Ce que couvre « enrichi au moment de l'import »

Comme les données d'enrichissement sont stockées une seule fois par vulnérabilité, un import ne peut appliquer instantanément que ce que DefectDojo a déjà consulté. Il existe trois cas :

| At import, the CVE is… | When the Finding shows EPSS/KEV |
| --- | --- |
| **Déjà enrichi** — DefectDojo a déjà consulté ce CVE auparavant, pour n'importe quelle Constatation dans n'importe quel Produit | **Immédiatement**, dans le cadre de l'import. C'est le cas le plus courant : les CVE reviennent d'un scan à l'autre et d'une équipe à l'autre, donc la plupart des CVE d'un import type sont déjà connus. |
| **Nouveau pour DefectDojo**, et l'import n'introduit qu'un nombre modeste de nouveaux CVE | **Peu après l'import**, en arrière-plan. Rien n'est encore stocké à appliquer, donc l'import demande une consultation pour ces seuls CVE et applique les résultats à leur retour. |
| **Nouveau pour DefectDojo**, et l'import introduit un très grand nombre de nouveaux CVE — un premier import, ou un rattrapage massif | **Lors de l'exécution quotidienne suivante**, ou lors de la prochaine [synchronisation à la demande](#running-a-sync-on-demand). Consulter des milliers de CVE totalement nouveaux pendant que l'import est encore en cours dupliquerait le travail de l'exécution quotidienne, c'est pourquoi cela lui est délibérément laissé. |

Dans tous les cas, les valeurs arrivent sans réimport, et l'exécution quotidienne reste le filet de sécurité — rien n'est jamais définitivement ignoré.

> **Les synchronisations de connecteurs sont enrichies de la même manière**, à une exception près : une **synchronisation de connecteur très volumineuse est importée par lots**, et les imports par lots ne sont pas enrichis au moment de l'import. Ces Constatations reçoivent leurs valeurs EPSS/KEV lors de l'exécution quotidienne suivante, ou lors d'une synchronisation à la demande.

## Afficher KEV/EPSS dans l'Explorateur de vulnérabilités

L'**Explorateur de vulnérabilités** liste une ligne par identifiant de vulnérabilité, avec les cinq mêmes colonnes KEV/EPSS que dans le tableau des Constatations — **EPSS Score**, **EPSS Percentile**, **Known Exploited**, **Ransomware Used** et **KEV Date** :

![image](images/Pro_EPSS_KEV_Explorer_Columns.png)

Ces valeurs décrivent la vulnérabilité elle-même, elles sont donc identiques quel que soit le nombre de Constatations qui y font référence. EPSS Score, EPSS Percentile, Known Exploited et KEV Date sont tous triables, ce qui en fait le moyen le plus rapide de répondre à la question « quelles vulnérabilités de mon environnement sont réellement exploitées ? » — triez par **EPSS Score** décroissant, ou par **Known Exploited** pour faire remonter les CVE listés au catalogue en tête.

Le nombre **Total Findings** de chaque ligne renvoie vers la liste des Constatations filtrée sur cette vulnérabilité, ce qui permet de passer de « ce CVE est listé au KEV » à « voici tout ce qu'il affecte » en un clic.

## Distinguer « aucune donnée » de « non exploité »

Une colonne KEV/EPSS vide et un ✗ rouge ne signifient pas la même chose :

- **✗ rouge / un score** — cette vulnérabilité *a bien* été vérifiée. Un ✗ sous Known Exploited signifie que la CISA ne la liste pas.
- **Vide** — cette vulnérabilité n'a **jamais été enrichie**, son statut d'exploitation est donc simplement inconnu.

Ici, ce même Explorateur n'a jamais été synchronisé, si bien que chaque colonne KEV/EPSS est vide plutôt que d'afficher des zéros ou des ✗ :

![image](images/Pro_EPSS_KEV_Explorer_Unenriched.png)

La même distinction apparaît sur la Constatation elle-même. Une Constatation dont les CVE n'ont pas encore été enrichis l'indique clairement, avec un lien vers l'Explorateur où vous pouvez lancer une synchronisation :

![image](images/Pro_EPSS_KEV_Not_Enriched.png)

Une fois l'enrichissement effectué, ce même panneau indique ce qui a réellement été trouvé :

![image](images/Pro_EPSS_KEV_Finding_Panel.png)

Cela compte car « nous n'avons pas encore vérifié » et « nous avons vérifié et ce n'est pas exploité » seraient sinon indiscernables, et un seul de ces deux cas est une raison de se rassurer.

## Lancer une synchronisation à la demande

Vous n'êtes pas obligé d'attendre le cycle quotidien. Le bouton **Sync KEV/EPSS data** en haut de l'Explorateur de vulnérabilités démarre une synchronisation immédiatement :

![image](images/Pro_EPSS_KEV_Sync_Started.png)

Pendant qu'une synchronisation est en cours, le bouton est désactivé et une barre de progression apparaît à sa place, accompagnée d'une estimation du temps restant dès qu'assez de travail a été effectué pour en projeter une. La ligne de statut au-dessus indique ce qui se passe — d'abord que DefectDojo vérifie quelles vulnérabilités ont changé, puis combien de Constatations ont déjà été mises à jour. Une fois l'exécution terminée, la ligne indique le résultat : combien de Constatations ont changé, que tout était déjà à jour, ou — si aucune source n'est configurée — que la synchronisation ne s'est pas exécutée.

Une seule synchronisation s'exécute à la fois. Cliquer sur le bouton pendant qu'une synchronisation est déjà en cours se contente de s'attacher à l'exécution déjà en cours plutôt que d'en démarrer une seconde ; il est donc sans risque de cliquer si vous n'êtes pas sûr qu'une synchronisation soit en cours. Il est également sans risque de répéter une synchronisation : si rien n'a changé depuis la dernière exécution, elle ne réécrit rien.

C'est le moyen le plus rapide de récupérer les changements EPSS et KEV publiés depuis le dernier cycle quotidien, et de compléter les Constatations qui n'affichent encore aucune donnée d'enrichissement.

## Impact sur la priorité et le risque

EPSS et KEV ne sont pas de simples badges informatifs — ce sont des entrées directes du **moteur de priorisation** de DefectDojo Pro. Le score `priority` de chaque Constatation combine plusieurs composantes (sévérité, exposition, contexte de l'actif, et plus encore) ; EPSS et KEV alimentent la composante **score externe**, qui valorise les vulnérabilités susceptibles d'être — ou connues pour être — exploitées.

Le score externe est dérivé du signal **le plus fort** parmi les suivants :

- **EPSS** contribue proportionnellement à son score — une probabilité d'exploitation plus élevée contribue davantage.
- **La présence au KEV** contribue d'un poids fixe : être **Known Exploited** *ou* utilisé dans un **ransomware** applique un bonus notable, et un CVE qui est **à la fois** Known Exploited **et** utilisé dans un ransomware applique le bonus le plus important.

Le plus grand des deux signaux l'emporte, si bien qu'une Constatation reçoit tout le crédit d'un score EPSS élevé ou d'une présence au KEV sans être pénalisée pour l'absence de l'autre. Ce score externe est ensuite intégré à la priorité globale de la Constatation, aux côtés de sa sévérité et de son exposition. Effet net : **une Constatation listée au KEV ou avec un EPSS élevé passe devant une Constatation par ailleurs comparable qui n'a ni l'un ni l'autre**, ce qui concentre la remédiation sur ce qui est réellement le plus susceptible d'être attaqué.

> **EPSS et KEV constituent la base — [Threat Intelligence](/asset_modelling/pro_hierarchy/threat_intelligence/) l'étend.** Lorsque l'enrichissement Threat Intelligence est activé, ce même score externe reconnaît également les exploits publics armés, les modèles de détection Nuclei, le code de preuve de concept, et l'exploitation active confirmée, chacun agissant comme un *plancher* sur l'échelle EPSS. Il ajoute en outre le [plancher de risque pour exploitation active](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor), qui empêche une Constatation activement exploitée en conditions réelles de rester dans une bande de Risque basse simplement parce que sa sévérité de base est Faible. Comme EPSS et KEV, ces signaux ne font jamais qu'augmenter un score.

Cela se propage automatiquement — la priorité est recalculée exactement pour les Constatations mises à jour par chaque exécution d'enrichissement, de sorte que la priorisation reste alignée sur les dernières données de renseignement sur les menaces.

> **Remarque :** EPSS et KEV influencent le score de **priorité**. Ils ne modifient pas le champ **Severity** d'une Constatation. Ils peuvent en revanche affecter le délai de **SLA** : si votre configuration SLA a l'option **Cap by KEV due date** activée, l'échéance SLA d'une Constatation listée au KEV est ramenée à la date d'échéance de remédiation fixée par la CISA pour ce CVE. Lorsqu'une Constatation comporte plusieurs CVE listés au KEV, la date d'échéance la plus proche s'applique.

## Filtrer et afficher les Constatations enrichies

Une fois les Constatations enrichies, les valeurs EPSS et KEV sont disponibles dans toute l'interface Pro :

- **Sur la Constatation** — le score EPSS, le percentile EPSS, Known Exploited, Ransomware Used et KEV Date s'affichent tous sur le détail de la Constatation.
- **Tri** — les tableaux de Constatations peuvent être triés par score / percentile EPSS pour faire remonter en premier les Constatations les plus susceptibles d'être exploitées.
- **Filtrage** — la liste des Constatations propose des filtres **Known Exploited** et **Ransomware Used**, permettant de construire des vues ou des rapports limités aux vulnérabilités confirmées comme exploitées en conditions réelles.

Un flux de travail courant consiste à filtrer sur **Known Exploited = true**, puis à trier par priorité, afin de produire une file « à corriger en premier » appuyée sur une exploitation confirmée.

## Configuration

Sur **DefectDojo Cloud**, l'enrichissement EPSS et KEV est activé et maintenu pour vous — il n'y a aucun interrupteur de source, aucune URL de flux, ni aucun seuil à définir, et la synchronisation quotidienne est gérée par DefectDojo. Les pondérations qui traduisent EPSS et KEV en priorité sont intégrées au moteur de priorisation.

Si les données EPSS ou KEV n'apparaissent pas sur des Constatations où vous les attendiez (et que ces Constatations comportent bien des CVE), commencez par vérifier la ligne de statut de l'Explorateur de vulnérabilités — elle indique le résultat de la synchronisation la plus récente, y compris lorsqu'aucune source n'est configurée. Si tout semble en ordre et que des données manquent toujours, contactez le support DefectDojo, qui pourra confirmer si la synchronisation quotidienne livre bien des données à votre instance.

> *Les installations sur site* configurent l'enrichissement différemment — chaque source peut être activée ou désactivée et pointée vers une URL de flux personnalisée dans les paramètres d'enrichissement des constatations du Tuner. Cette configuration ne s'applique pas à Cloud, où les données sont livrées par DefectDojo.
