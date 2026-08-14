---
title: Générateur de rapports
description: Créez des rapports personnalisés et réutilisables dans DefectDojo Pro
  à l'aide de Thèmes, de Blocs et de Modèles
draft: false
audience: pro
weight: 20
slug: report-builder
aliases:
- /fr/en/share_your_findings/pro_reports/using_the_report_builder
- /fr/metrics_reports/reports/using_the_report_builder
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : le Générateur de rapports réutilisable (Thèmes, Blocs, Modèles et Rapports générés enregistrés) est une fonctionnalité de DefectDojo Pro, actuellement en version bêta.</span>

Le Générateur de rapports de DefectDojo Pro vous permet de composer des rapports soignés à partir d'éléments réutilisables, afin que vous puissiez créer les composants une seule fois et les réutiliser partout, au lieu de reconstruire un rapport à partir de zéro à chaque fois. Vous y accédez depuis la zone **📄 Rapports** de la barre latérale.

## Comparaison avec la version open source

DefectDojo open source permet de créer un rapport, de l'exécuter et d'en récupérer le résultat, mais il **n'enregistre pas** les modèles de rapport ni ne conserve les rapports générés. Chaque rapport est un exercice ponctuel.

DefectDojo Pro transforme la création de rapports en blocs de construction réutilisables. Vous enregistrez des **Thèmes**, des **Blocs** et des **Modèles** que vous pouvez combiner, assortir et réutiliser, et chaque rapport que vous exécutez est conservé sous la forme d'un **Rapport généré** que vous pouvez télécharger ou réexécuter ultérieurement. Pro expose également l'ensemble du flux de travail via une API REST complète et prend en charge la rédaction assistée par LLM, de sorte que les rapports peuvent être créés et exécutés de manière programmatique.

> **💡 Astuce :** Si vous utilisez DefectDojo open source, consultez plutôt le [générateur de rapports open source](../using-the-report-builder/).

## Concepts fondamentaux

Le Générateur de rapports se compose de quatre éléments, chacun disponible comme ressource REST sous `/api/v2/` : `report_themes`, `report_blocks`, `report_templates` et `generated_reports`. Comprendre comment ils s'articulent est la clé pour créer des rapports efficacement.

### Thèmes

Un **Thème** contrôle le style visuel et l'image de marque d'un rapport : les couleurs, les images d'en-tête et de pied de page, ainsi que le texte de pied de page. En définissant un Thème une seule fois, vous pouvez appliquer une image de marque corporative cohérente à chaque rapport que vous produisez.

Un Thème comporte les paramètres suivants :

| Paramètre | Objet | Par défaut |
|---------|---------|---------|
| Name | Libellé du Thème | — |
| Primary color | Couleur principale de la marque | `#1e3a5f` |
| Secondary color | Couleur secondaire de la marque | `#4a90a4` |
| Accent color | Couleur de mise en valeur | `#e67e22` |
| Text color | Couleur du texte principal | `#333333` |
| Background color | Couleur de fond de la page | `#ffffff` |
| Footer text | Texte affiché dans le pied de page | — |
| Show page numbers | Indique si les numéros de page doivent être imprimés | Activé |
| Header image | Image affichée dans l'en-tête | — |
| Footer image | Image affichée dans le pied de page | — |

> **💡 Astuce :** Les cinq couleurs sont exprimées sous forme de valeurs hexadécimales à 7 caractères (par exemple `#1e3a5f`), afin que vous puissiez faire correspondre exactement la palette de couleurs de votre organisation.

Vous pouvez créer ceci dans l'interface utilisateur (voir ci-dessous) ou l'automatiser avec l'[API](../report-builder-api/).

### Blocs

Un **Bloc** est une unité de contenu réutilisable. Vous créez un Bloc une seule fois, vous configurez ce qu'il affiche, puis vous le déposez dans autant de Modèles que vous le souhaitez. Il existe quatre types de blocs :

| Type de bloc | Ce qu'il produit |
|------------|------------------|
| **Stock** | Contenu non lié aux données, comme une page de couverture, une table des matières, un saut de page, une image ou un bloc de texte. |
| **Tabular** | Un tableau d'enregistrements provenant d'une seule entité. |
| **Detail** | Une mise en page par enregistrement, idéale pour les champs longs affichés en markdown (par exemple, description, impact, atténuation et références). |
| **Chart** | Graphiques visuels. *Bientôt disponible* — ce type de bloc est défini dans le modèle de données mais n'est pas encore disponible dans l'API ou l'interface utilisateur. |

Un bloc **Stock** se configure en choisissant l'un des cinq types de stock, ainsi qu'un titre, un sous-titre, un contenu textuel ou une image, selon le cas :

- **Cover page**
- **Table of contents**
- **Page break**
- **Image**
- **Text block**

**Tabular** et **Detail** sont deux types de blocs qui récupèrent tous deux des enregistrements en direct à partir d'une entité. Vous choisissez l'entité via un sélecteur de modèle, puis vous sélectionnez les champs à inclure et l'ordre des enregistrements. Le choix du modèle correspond exactement à l'une de ces sept entités :

- **Organization**
- **Asset**
- **Engagement**
- **Test**
- **Finding**
- **Test type**
- **Risk acceptance**

> **💡 Astuce :** Dans DefectDojo Pro, les **Assets** s'appelaient auparavant des **Products** et les **Organizations** s'appelaient auparavant des **Product Types**. Vous pouvez encore rencontrer cette terminologie héritée dans certains noms de champs et de filtres sous-jacents.

La différence réside dans la présentation : un bloc **Tabular** dispose les enregistrements sous forme de tableau de colonnes, ce qui est idéal pour les résumés et les inventaires, tandis qu'un bloc **Detail** affiche un enregistrement à la fois dans une mise en page longue, mieux adaptée aux champs riches en markdown comme la description, l'impact, l'atténuation et les références.

> **💡 Astuce :** Les filtres sont associés au Bloc, et non au Modèle. Un Bloc transporte ses propres filtres avec lui, de sorte que réutiliser un Bloc réutilise ses filtres à l'identique partout où il apparaît. Si vous avez besoin du même contenu avec un filtre différent, dupliquez le Bloc et ajustez la copie.

Vous pouvez créer ceci dans l'interface utilisateur (voir ci-dessous) ou l'automatiser avec l'[API](../report-builder-api/).

### Modèles

Un **Modèle** est une liste ordonnée de Blocs associée à un seul Thème. Le Modèle définit ce qui apparaît dans le rapport et dans quel ordre, tandis que le Thème auquel il est associé contrôle son apparence.

Étant donné qu'un Modèle référence les Blocs par inclusion, un même Bloc peut apparaître plusieurs fois dans un Modèle. Un Bloc de saut de page réutilisable, par exemple, peut être inséré entre plusieurs sections d'un même rapport.

Vous pouvez créer ceci dans l'interface utilisateur (voir ci-dessous) ou l'automatiser avec l'[API](../report-builder-api/).

### Rapports générés

L'exécution d'un Modèle produit un **Rapport généré** : un fichier PDF ou HTML conservé, que vous pouvez télécharger et réexécuter à la demande. Chaque Rapport généré est **figé dans le temps** — il capture les données de DefectDojo au moment de sa génération et ne se met **pas** à jour automatiquement lorsque les données sous-jacentes changent par la suite. Pour obtenir un instantané à jour, réexécutez le Modèle.

Un Rapport généré passe par les statuts suivants pendant sa création :

| Statut | Signification |
|--------|---------|
| En attente | La demande de rapport a été effectuée et le rapport est en file d'attente. |
| En cours de traitement | Le rapport est en cours d'assemblage. |
| Terminé | Le rapport est prêt à être téléchargé. |
| Échec | Le rapport n'a pas pu être généré. |

> **🔑 Important :** La création de rapports est activée par défaut. Un superutilisateur peut l'activer ou la désactiver depuis **Settings > Feature Flags** (voir [Feature Flags](/admin/feature_flags/pro__feature_flags/)). L'affichage respecte le contrôle d'accès basé sur les rôles (RBAC) de DefectDojo — les utilisateurs ne voient jamais que les données qu'ils sont autorisés à consulter, même à l'intérieur d'un rapport.

Vous pouvez créer ceci dans l'interface utilisateur (voir ci-dessous) ou l'automatiser avec l'[API](../report-builder-api/).

## Créer un rapport dans l'interface utilisateur

Les étapes suivantes décrivent la création d'un rapport de bout en bout : créer un Thème, créer les Blocs qui contiennent votre contenu, les assembler dans un Modèle, puis générer le rapport final.

### Étape 1 : Créer un Thème

Commencez dans la zone Thèmes. La liste des Thèmes affiche tous les Thèmes que vous avez définis et vous permet d'en créer un nouveau.

![Liste des Thèmes](images/pro_report_themes_list.png)

Ouvrez un nouveau Thème pour définir son image de marque. Le formulaire de Thème expose les cinq couleurs, une image d'en-tête et de pied de page facultative, le texte de pied de page, ainsi que l'option d'activation des numéros de page. Choisissez des couleurs correspondant à l'image de marque de votre organisation afin que tous vos rapports aient un aspect cohérent.

![Formulaire de modification du Thème](images/pro_report_theme_new.png)

### Étape 2 : Créer des Blocs

Ensuite, créez les Blocs de contenu. La liste des Blocs affiche tous vos Blocs, tous types confondus.

![Liste des Blocs](images/pro_report_blocks_list.png)

Pour créer un Bloc piloté par les données, choisissez son type et configurez-le. L'exemple ci-dessous est un Bloc **Tabular** nommé pour les constatations ouvertes : le Block Type est défini sur Tabular, un en-tête est fourni, le Model est **Finding**, les champs sélectionnés sont Severity, Title, Product, Age (Days) et SLA Days Remaining, et les enregistrements sont triés par Numerical Severity par ordre décroissant. Étant donné que les filtres sont associés au Bloc, les Filter Entries ici déterminent exactement les enregistrements que ce Bloc récupérera partout où il est utilisé.

![Configuration du bloc Tabular](images/pro_report_block_new_tabular.png)

Vous pouvez cliquer sur **Aperçu** pour voir comment un Bloc s'affichera une fois un Thème appliqué, avant de l'intégrer à un Modèle. L'aperçu ci-dessous montre une page de couverture stylisée (« DefectDojo Security Report ») reprenant les couleurs et l'image de marque du Thème.

![Aperçu du Bloc généré](images/pro_report_block_preview.png)

> **💡 Astuce :** Utilisez **Dupliquer** pour copier un Bloc existant lorsque vous avez besoin de la même mise en page avec un filtre différent. Étant donné que les filtres accompagnent le Bloc, la duplication est le bon moyen de produire, par exemple, un tableau « Constatations critiques » et un tableau « Constatations élevées » à partir de la même disposition de colonnes.

### Étape 3 : Assembler un Modèle

Une fois vos Blocs prêts, créez un Modèle. La liste des Modèles affiche les Modèles que vous avez enregistrés.

![Liste des Modèles](images/pro_report_templates_list.png)

Dans l'éditeur de Modèle, vous sélectionnez un Thème et vous organisez les Blocs dans l'ordre dans lequel ils doivent apparaître. L'exemple ci-dessous enchaîne Cover Page → Executive Intro → Open Findings → KEV → Page Break → Asset Inventory. Utilisez **Add Existing Block** pour réutiliser un Bloc déjà créé, ou **Add New Block** pour en créer un directement, et utilisez les poignées de glissement pour réorganiser l'ordre. N'oubliez pas qu'un même Bloc peut apparaître plusieurs fois — un seul Bloc de saut de page peut être inséré entre plusieurs sections.

![Éditeur de Modèle](images/pro_report_template_new.png)

### Étape 4 : Générer et télécharger

Lorsque le Modèle est prêt, générez le rapport. La boîte de dialogue de génération confirme le Modèle et vous permet de choisir le format de sortie — **HTML** ou **PDF**.

![Boîte de dialogue de génération du rapport](images/pro_generate_report_dialog.png)

Les rapports générés sont regroupés dans la liste des Rapports générés, qui affiche le statut de chaque rapport, son format de fichier, l'heure de sa demande et de son achèvement, ainsi qu'un lien de téléchargement.

![Liste des Rapports générés](images/pro_generated_reports_list.png)

Vous pouvez réexécuter un Modèle à tout moment pour produire un nouveau rapport. Gardez à l'esprit que chaque Rapport généré est figé dans le temps — il reflète vos données au moment de sa génération et ne change pas lorsque les données de DefectDojo évoluent ; réexécutez donc le Modèle chaque fois que vous avez besoin d'un instantané à jour.

## Abandon du moteur de rapport classique

Le moteur de rapport classique — les pages **Report Builder**, **Report Templates** et **Generated Reports** répertoriées sous *Classic Report Engine* dans la barre latérale — sera supprimé dans la version **3.3.0 (8 septembre 2026)**. D'ici là, ces pages affichent une bannière vous rappelant cette date, et elles proposent, tout comme ce Générateur de rapports, une migration en un clic.

### Migration de vos modèles enregistrés

Utilisez **Migrate to the new engine** sur n'importe quelle page classique, ou **Import from Classic Engine** sur *All Report Templates* ici. Les deux effectuent la même conversion, peu importe donc celle par laquelle vous commencez, et les deux peuvent être exécutées plus d'une fois sans risque : un modèle classique dont le nom existe déjà ici est signalé comme *déjà migré* plutôt que dupliqué.

Chaque widget classique devient un Bloc :

| Widget classique | Devient |
|----------------|---------|
| Cover Page | Bloc stock Cover Page |
| Table Of Contents | Bloc stock Table of Contents |
| Page Break | Bloc stock Page Break |
| Custom Content / WYSIWYG | Text Block |
| Findings | Bloc Tabular sur les Findings, conservant les filtres du widget |
| Vulnerable Endpoints | Bloc Tabular sur les URLs |
| Severities | Bloc graphique Active Findings by Severity |

Deux widgets ne sont pas repris, et la migration l'indique pour chaque modèle plutôt que de les convertir en quelque chose d'approximatif :

- **Executive Summary** — le moteur classique dérivait ce contenu des widgets Findings présents dans le même rapport. Il n'existe pas de Bloc agrégé équivalent ; reconstruisez-le sous forme de Text Block si nécessaire.
- **Report Options** — ce n'est pas un Bloc. Son *Report name* devient le nom du nouveau Modèle. Les notes de constatation, les images de constatation et les sauts de page par widget sont des paramètres au niveau du Thème dans le nouveau moteur.

### Que deviennent les rapports déjà exécutés

Rien. Les Rapports générés produits par le moteur classique sont des fichiers finalisés, il n'y a donc rien à convertir. Ils restent répertoriés et téléchargeables jusqu'à la suppression du moteur — sauvegardez tout ce que vous souhaitez conserver au-delà de la version 3.3.0.

### Si le Générateur de rapports est désactivé

La migration fonctionne même avec l'indicateur de fonctionnalité **Reporting** désactivé. Les Modèles convertis n'apparaissent tout simplement pas tant que l'indicateur n'est pas réactivé, ce qui vous permet de migrer vos modèles à votre propre rythme.

## Prochaines étapes

- **[API du Générateur de rapports](../report-builder-api/)** — scriptez l'ensemble du flux de travail (Thèmes, Blocs, Modèles et Rapports générés) pour une création de rapports reproductible et automatisée.
- **[Générateur de rapports avec un LLM](../report-builder-llm/)** — utilisez la rédaction assistée par LLM pour concevoir et créer des rapports de manière conversationnelle.
