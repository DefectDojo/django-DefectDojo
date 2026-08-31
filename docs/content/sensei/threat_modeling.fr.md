---
title: Modélisation des menaces
description: Générez un modèle de menaces, des chemins d'attaque et des exigences
  de sécurité à partir de la conception d'une fonctionnalité, avant même que le code
  existe
draft: false
audience: pro
weight: 4
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note : la modélisation des menaces est une fonctionnalité réservée à DefectDojo Pro et se trouve actuellement en BÊTA.</span>

La **modélisation des menaces** transforme la conception d'une fonctionnalité en un modèle de menaces revu. Vous fournissez la conception — texte collé, document de conception, et éventuellement un diagramme d'architecture — et DefectDojo produit les composants et les flux de données qu'elle décrit, les menaces qui pèsent sur eux, et les exigences de sécurité qui atténuent ces menaces. Les exigences peuvent ensuite être poussées dans DefectDojo sous forme de constatations, afin que le travail au stade de la conception passe par les mêmes mécanismes de triage, de SLA, de Jira et de reporting que tout le reste.

Il s'agit de la capacité **pré-code** de Sensei. Là où [l'analyse et la correction](/sensei/about_sensei/) fonctionnent sur un dépôt qui existe déjà, la modélisation des menaces fonctionne sur la conception, avant même qu'il y ait du code à analyser.

> **🔎 BÊTA :** la modélisation des menaces est en développement actif et est signalée **BÊTA** dans toute l'interface. Le comportement et les écrans peuvent changer d'une version à l'autre. Pendant la BÊTA, elle est activée par instance par DefectDojo — contactez votre représentant DefectDojo pour l'activer.

> **📍 Où la trouver :** ouvrez **Threat Modeling** depuis la navigation de gauche, juste en dessous de Sensei.

## Ce dont vous avez besoin

- La fonctionnalité sous licence **Sensei**. La modélisation des menaces est livrée sous le même droit d'utilisation que l'analyse et la correction.
- Un rôle global **Mainteneur** ou **Propriétaire**. Les utilisateurs qui ne l'ont pas ne voient pas la page.
- Un produit auquel rattacher le modèle de menaces. Les instances utilisant la nomenclature 3.0 voient les produits appelés **assets** ; cette page utilise le terme *produit* partout, et l'interface suit la nomenclature configurée sur votre instance.

Rien n'est installé et aucun dépôt n'est connecté. La modélisation des menaces ne lit que la conception que vous fournissez.

## Générer un modèle de menaces

Choisissez **New threat model**, sélectionnez le produit, donnez-lui un nom, et fournissez la conception sous la forme dont vous disposez :

- **Collez la description** directement, ou
- **Téléversez un document de conception** — `.md`, `.markdown`, `.txt`, `.text` ou `.pdf`. L'extraction du texte à partir d'un PDF se fait au mieux ; si un PDF est essentiellement composé d'images, collez plutôt le texte.
- **Ajoutez éventuellement un diagramme d'architecture** — PNG, JPEG, WebP ou GIF. Le diagramme est lu en complément du texte, de sorte qu'un composant qui n'apparaît que dans l'image est tout de même pris en compte.

Vous pouvez les combiner : un court résumé collé associé à un diagramme produit souvent un meilleur modèle que l'un ou l'autre seul.

La génération s'exécute en arrière-plan et passe par quatre étapes, affichées sur l'exécution au fur et à mesure de sa progression :

1. **Extraction de l'architecture** — composants, limites de confiance, actifs de données et flux de données.
2. **Recensement des menaces** — menaces par catégorie STRIDE.
3. **Rédaction des exigences de sécurité** — exigences testables, chacune liée aux menaces qu'elle atténue.
4. **Assemblage des résultats** — le diagramme et les vérifications de cohérence finales.

Une exécution prend généralement plusieurs minutes. Vous pouvez quitter la page ; la progression et les résultats sont conservés sur l'exécution.

## Lire les résultats

### Architecture

L'onglet **Architecture** affiche ce qui a été extrait sous forme de diagramme de flux de données : les composants regroupés par limite de confiance, avec des flux étiquetés par protocole. Les flux qui **franchissent une limite de confiance** sont dessinés différemment, car ce sont les plus intéressants. Sélectionner un composant affiche les menaces qui le ciblent.

Le modèle enregistre également ce qu'il n'a **pas** pu déterminer — les hypothèses qu'il a dû formuler, et les points restés flous dans la conception. Lisez-les en premier : ils indiquent où la conception elle-même est ambiguë, ce qui est souvent le résultat le plus utile de l'exercice.

### Menaces

Chaque menace comporte :

- Sa **catégorie STRIDE** (usurpation, altération, répudiation, divulgation d'informations, déni de service, élévation de privilèges) et une **sévérité**.
- Le **profil de l'attaquant** — par exemple un attaquant externe non authentifié, une personne interne, ou une compromission de la chaîne d'approvisionnement — et le niveau de compétence requis.
- Un **chemin d'attaque** ordonné : les étapes qu'un attaquant suivrait, avec leurs prérequis.
- Un **CWE**, lorsqu'il s'applique, tiré d'une liste fixe plutôt qu'inventé.
- Les **composants, flux et actifs de données** qu'elle cible.

### Exigences de sécurité

Chaque exigence est rédigée comme une affirmation testable, avec une étape de **vérification** décrivant comment confirmer qu'elle est respectée, une catégorie (authentification, autorisation, validation des entrées, cryptographie, etc.), et une priorité. Chaque exigence nomme les menaces qu'elle atténue.

La couverture est comptabilisée explicitement : une menace est soit atténuée par au moins une exigence, soit listée comme un **écart de couverture**. Les écarts sont affichés plutôt que masqués, afin qu'une menace ne soit jamais abandonnée silencieusement.

## Preuves, et ce en quoi avoir confiance

Chaque composant, menace et exigence porte la **preuve** dont elle provient, et la preuve est étiquetée par source :

- **Provenant du texte de conception** — une citation qui a été mise en correspondance, mot pour mot, avec le texte que vous avez fourni.
- **Provenant du diagramme** — lue depuis l'image, il n'y a donc pas de texte à citer.
- **Déduite** — non énoncée dans la conception.

Une citation qui n'a pas pu être mise en correspondance avec le texte fourni est conservée mais **signalée comme non vérifiée**, avec la citation revendiquée affichée afin que vous puissiez en juger vous-même. Les éléments sont signalés plutôt que supprimés, car une menace écartée silencieusement est un risque dont personne n'entend parler. Les éléments structurellement corrompus — une menace faisant référence à un composant qui n'a jamais été extrait — sont supprimés, et le nombre d'éléments supprimés est enregistré sur l'exécution.

**Considérez le résultat comme un brouillon à examiner, et non comme un livrable final.** Il est généré à partir d'un document de conception par un modèle de langage ; les étiquettes de preuve existent pour que vous puissiez voir quelles parties sont ancrées dans ce que vous avez écrit et lesquelles relèvent de la déduction.

## Pousser les exigences en constatations

Les exigences deviennent exploitables via **Push to findings**. Sélectionnez les exigences souhaitées et DefectDojo crée une constatation par exigence, dans un engagement dédié nommé **Sensei Threat Modeling** sur ce produit, avec un test par version de modèle de menaces.

Chaque constatation comporte :

- L'énoncé de l'exigence, plus le récit de chaque menace qu'elle atténue — catégorie STRIDE, attaquant, et le chemin d'attaque numéroté — afin que quiconque prend en charge le ticket dispose du contexte sans avoir à ouvrir le modèle de menaces.
- L'étape de vérification comme mesure d'atténuation.
- La sévérité et le CWE de l'exigence.
- L'étiquette `sensei-threat-model`, une étiquette `tm-v<version>`, et une étiquette STRIDE.

Les constatations sont créées **actives mais non vérifiées** : une exigence générée est une proposition à confirmer par un humain.

La poussée est **idempotente**. Chaque exigence possède sa propre constatation, donc pousser à nouveau le même modèle met à jour sur place au lieu de créer des doublons — et si vous modifiez une exigence puis la poussez à nouveau, la constatation suit. Pousser à nouveau ne réécrit pas qui a soulevé la constatation en premier.

## Versions et remplacement

Les modèles de menaces sont **versionnés par produit**. Régénérer à partir d'une conception mise à jour crée une nouvelle version au lieu d'écraser l'ancienne, de sorte que vous conserviez l'historique de ce à quoi ressemblait la conception au moment où une décision a été prise.

Lorsque vous poussez une version plus récente, les constatations de la version précédente qui ne correspondent plus à une exigence actuelle sont **atténuées** plutôt que laissées ouvertes, afin que l'engagement reflète la conception actuelle.

## Exportation

Un modèle de menaces peut être téléchargé au format **Markdown** pour une revue de conception ou un ticket, ou au format **JSON** pour tout usage programmatique. Les deux sont disponibles depuis le modèle de menaces lui-même.

## Activité de génération

L'onglet **Activity** liste chaque génération, son statut et l'étape atteinte. Les exécutions en cours peuvent être **annulées**. Une exécution en échec indique **pourquoi** elle a échoué — un problème de configuration, une entrée trop longue, ou une erreur de service temporaire — et les étapes terminées font l'objet d'un point de contrôle, de sorte qu'une nouvelle tentative reprend au lieu de repartir du début.

## Coûts

La modélisation des menaces fait appel à un grand modèle de langage, et chaque génération a un coût. Une génération effectue environ huit appels, et l'usage est enregistré par exécution aux côtés de l'autre usage LLM de Sensei, afin que vous puissiez voir ce qu'un modèle a coûté à produire. Annuler une exécution arrête les appels suivants à la prochaine limite d'étape.
