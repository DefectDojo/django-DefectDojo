---
title: À propos des connecteurs
description: L'espace unifié pour les connecteurs amont et aval dans l'interface Pro
summary: ''
date: 2026-07-14 00:00:00+00:00
lastmod: 2026-07-14 00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les connecteurs sont une fonctionnalité réservée à DefectDojo Pro.</span>

**Connecteurs** est l'espace unique de l'interface DefectDojo Pro pour tous les outils avec lesquels DefectDojo communique, dans les deux sens. Il regroupe deux fonctionnalités auparavant configurées séparément :

* Les **Connecteurs Amont** (**Upstream Connectors**, anciennement **Connecteurs API**) importent les constatations et l'inventaire des actifs *depuis* vos scanners et outils de sécurité.
* Les **Connecteurs Aval** (**Downstream Connectors**, anciennement **Intégrations**) exportent les constatations *vers* vos gestionnaires de tickets et systèmes de suivi.

Si vous considérez DefectDojo comme le point central de vos données de sécurité, les Connecteurs Amont sont la façon dont les données arrivent, et les Connecteurs Aval la façon dont le travail de remédiation repart.

## Où trouver les connecteurs

Dans la barre latérale de l'interface Pro, ouvrez le groupe **Connectors** sous l'en-tête **Import** :

* **Connectors > Upstream Connectors** — remplace l'ancienne entrée **API Connectors** (auparavant sous Import).
* **Connectors > Downstream Connectors** — remplace l'ancienne entrée **Integrations** (auparavant sous Settings). Ce sens est actuellement en **version bêta**.

Les anciens favoris et liens profonds continuent de fonctionner : les URL historiques **API Connectors** et **Integrations** redirigent automatiquement vers les nouvelles pages **Upstream Connectors** et **Downstream Connectors**.

## Qui peut voir quoi

* Les **Upstream Connectors** sont visibles par les utilisateurs disposant d'un rôle global Lecteur ou supérieur.
* Les **Downstream Connectors** sont visibles uniquement par les superutilisateurs, et sont actuellement en **version bêta** pour les instances DefectDojo Pro hébergées dans le Cloud.

Le groupe **Connectors** apparaît dans la barre latérale si au moins l'une des deux pages vous est visible.

## Les pages Connectors

Les deux sens partagent la même présentation actualisée :

* Chaque outil est présenté sous forme de **vignette** pleine largeur — le logo à gauche, le nom de l'outil et une courte description au centre, et un bouton d'action à droite.
* Chaque section dispose d'une **zone de recherche** qui filtre les vignettes par nom d'outil au fur et à mesure de la saisie.

Sur la page **Upstream Connectors** :

* **Configured Connectors** répertorie les connecteurs que vous avez déjà configurés. Chaque vignette affiche un résumé de l'état de santé opérationnel (statut de santé, dernière opération, et nombre total / d'enregistrements mappés) ainsi qu'un menu **Manage Configuration** proposant les actions **Manage Records & Operations**, **Edit Configuration** et **Delete Configuration**.
* **Available Connectors** répertorie les outils pris en charge que vous n'avez pas encore configurés, chacun avec un bouton **Add Configuration**.
* Un filtre dans l'en-tête de la page réduit les deux sections par type de connecteur : **All**, **Asset** (ou **Product**, selon le vocabulaire de votre instance) pour les connecteurs qui importent l'inventaire des actifs, et **Finding** pour les connecteurs qui importent des données de vulnérabilité.

Sur la page **Downstream Connectors** :

* **Available Integrations** répertorie tous les gestionnaires de tickets pris en charge. Les vignettes des intégrations que vous avez configurées affichent un nombre d'instances d'intégration existantes.

## Prochaines étapes

* Consultez [À propos des connecteurs amont](/connectors/upstream/about/) et [ajoutez votre premier connecteur amont](/connectors/upstream/add_edit/) pour commencer à importer automatiquement des constatations.
* Consultez le [guide des connecteurs aval](/connectors/downstream/about/) pour envoyer des constatations vers vos gestionnaires de tickets.
