---
title: Indicateurs de fonctionnalités
description: Activez et désactivez les fonctionnalités optionnelles de DefectDojo
  Pro depuis l'interface de DefectDojo
weight: 1
audience: pro
---

Les indicateurs de fonctionnalités vous permettent d'activer et de désactiver les fonctionnalités optionnelles de DefectDojo Pro sur votre propre instance — des fonctionnalités qu'il fallait auparavant activer en contactant le support DefectDojo peuvent désormais être gérées en libre-service depuis l'interface.

La page Indicateurs de fonctionnalités n'est visible que par les **superutilisateurs**. Les autres utilisateurs, y compris les propriétaires globaux, ne la voient pas.

## Ouvrir la page Indicateurs de fonctionnalités

Accédez à **Settings > Feature Flags** dans la barre latérale gauche.

La page répertorie chaque fonctionnalité optionnelle avec :

* **Nom** — la fonctionnalité, avec une étiquette **BETA** lorsqu'elle est encore en bêta
* **Description** — ce que fait la fonctionnalité
* **Lien vers la documentation** — s'il existe une documentation pour cette fonctionnalité
* **Interrupteur** — indique si la fonctionnalité est actuellement activée

Utilisez le champ de recherche pour filtrer la liste par nom de fonctionnalité ou par description.

### Fonctionnalités non répertoriées

La page répertorie les fonctionnalités que vous pouvez choisir d'adopter. Deux types de fonctionnalités en sont absents.

**Toujours activées.** Une fois qu'une fonctionnalité atteint la disponibilité générale, elle est activée pour toutes les instances et cesse d'être répertoriée, car il n'y a plus de décision à prendre :

* **Downstream Connectors** — voir [Downstream Connectors](/connectors/downstream/about/)
* **Universal Parser** — voir [Universal Parser](/import_data/pro/specialized_import/universal_parser/)
* **Asset Hierarchy** — voir [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **Appearance** et **Feature Flags** — les deux pages de Paramètres portant ce nom

Rien ne change pour votre instance si l'une de ces fonctionnalités était déjà activée. Si l'une d'elles était désactivée, elle est désormais activée : ces fonctionnalités font désormais partie intégrante de DefectDojo Pro plutôt que d'être optionnelles. Contactez le [support DefectDojo](mailto:support@defectdojo.com) si cela pose problème pour votre instance.

**Activées par DefectDojo sur demande.** Quelques fonctionnalités dépendent d'une infrastructure provisionnée par instance ; elles sont donc activées par DefectDojo plutôt que depuis cette page :

* **Scheduling Service** — voir [Scheduling Rules](/automation/rules_engine/scheduling/)

Contactez le [support DefectDojo](mailto:support@defectdojo.com) pour faire activer l'une de ces fonctionnalités. Si elle est déjà activée sur votre instance, elle le reste.

## Activer ou désactiver une fonctionnalité

1. Trouvez la fonctionnalité dans la liste.
2. Cliquez sur son interrupteur.
3. Le changement prend effet immédiatement. Les autres utilisateurs le voient au prochain chargement de la page.

Certaines fonctionnalités affichent une boîte de dialogue de confirmation avant l'application du changement. C'est le cas lors de l'activation d'une fonctionnalité comportant un avertissement (par exemple une fonctionnalité nécessitant un redémarrage ou pouvant affecter des données existantes), ou d'une fonctionnalité qui ne peut plus être désactivée ensuite.

Désactiver une fonctionnalité consiste normalement simplement à inverser son activation. Les exceptions sont signalées dans [Quand un interrupteur est verrouillé](#when-a-toggle-is-locked).

### Renommage Organisation / Actif

**Renommage Organisation / Actif** renomme « Product Type » en « Organization » et « Product » en « Asset ». Cette fonctionnalité est activée par défaut et se bascule depuis cette page comme toute autre fonctionnalité, mais il est utile de savoir quelles parties de DefectDojo elle régit :

* L'**interface Pro** suit cet interrupteur. Les nouveaux libellés apparaissent au prochain chargement de la page.
* Les pages de l'**interface classique**, leurs URL et les rapports générés tirent leur dénomination du paramètre de déploiement `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` (également activé par défaut), qui est lu au démarrage de DefectDojo. Cet interrupteur ne les modifie pas, et un redémarrage ne les fait pas non plus changer.

L'interrupteur enregistré a été initialisé à partir de ce paramètre de déploiement, les deux restent donc synchronisés tant que vous n'en modifiez pas un. Si vous désactivez le renommage ici et que vous utilisez également l'interface classique, définissez `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False` sur votre déploiement et redémarrez afin que les deux interfaces correspondent. Sur [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), contactez le [support DefectDojo](mailto:support@defectdojo.com) pour faire modifier ce paramètre de déploiement.

C'est pour cette raison que la fonctionnalité porte une étiquette **Restart Recommended** sur la page Indicateurs de fonctionnalités : la dénomination utilisée en dehors de l'interface Pro est figée au démarrage du processus. Dans tous les cas, le renommage est purement cosmétique. Les modèles de base de données, les noms de champs et les points de terminaison de l'API restent inchangés, si bien que l'automatisation existante continue de fonctionner. Voir [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/).

## Quand un interrupteur est verrouillé

Une fonctionnalité que vous ne pouvez pas modifier s'affiche avec un badge de verrouillage expliquant pourquoi :

| Badge | Signification | Action à mener |
| --- | --- | --- |
| **Managed by DefectDojo** | DefectDojo a défini cette fonctionnalité de manière centralisée pour votre instance. Votre paramètre ne peut pas la remplacer. | Contactez le [support DefectDojo](mailto:support@defectdojo.com) si vous avez besoin d'un changement. |
| **Unavailable on This Deployment** | La fonctionnalité n'est pas proposée pour votre type d'installation. Voir [Feature availability](#feature-availability) ci-dessous. | Rien. La fonctionnalité ne s'applique pas à votre instance. |
| **Cannot Be Disabled** | La fonctionnalité est déjà activée et l'opération est à sens unique. Il n'existe aucun mécanisme pour revenir en arrière. | Rien. C'est normal. |
| **Managed by deployment** | La fonctionnalité est contrôlée par votre configuration de déploiement plutôt que par cette page. | Voir [DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise) ci-dessous. |

## DefectDojo Pro (Cloud)

Sur [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), **Settings > Feature Flags** est le seul endroit dont vous avez besoin. Activez une fonctionnalité et elle est immédiatement en service.

Deux éléments sont pris en charge par DefectDojo plutôt que par vous :

* **Managed by DefectDojo** — la fonctionnalité est fixée de manière centralisée. Contactez le [support DefectDojo](mailto:support@defectdojo.com) pour la faire modifier.
* **Managed by deployment** — la fonctionnalité fait partie du mode de provisionnement de votre instance. Contactez également le support pour celles-ci, car les instances Cloud n'exposent pas la configuration de déploiement aux clients.

Les instances Cloud ont également accès à des fonctionnalités qui ne sont pas proposées sur site. Voir [Feature availability](#feature-availability).

## DefectDojo Pro (sur site)

Sur [DefectDojo Pro (sur site)](/get_started/pro/onprem/), la plupart des fonctionnalités fonctionnent exactement comme sur le Cloud : ouvrez **Settings > Feature Flags** et activez-les.

Un petit nombre de fonctionnalités sont plutôt lues depuis votre configuration de déploiement. Elles modifient la façon dont l'application démarre, et ne peuvent donc pas être basculées à l'exécution. Elles apparaissent sur la page en lecture seule, étiquetées **Managed by deployment**, avec le nom de la variable d'environnement qui les contrôle, par exemple `DD_V3_FEATURE_LOCATIONS` pour [Locations](/asset_modelling/locations/pro__locations_overview/).

Comme ces fonctionnalités nécessitent un redémarrage, et que certaines d'entre elles ne peuvent pas être annulées une fois activées, consultez la documentation propre à la fonctionnalité avant d'en modifier une. Il est préférable d'activer plusieurs d'entre elles avec l'aide du [support DefectDojo](mailto:support@defectdojo.com).

Pour modifier l'une de ces fonctionnalités :

1. Définissez la variable d'environnement sur votre déploiement DefectDojo. La page vous indique quelle variable définir.
2. Redémarrez DefectDojo afin que la nouvelle valeur soit lue au démarrage.
3. Rechargez la page Indicateurs de fonctionnalités pour confirmer le nouvel état.

Comme ces valeurs sont lues au démarrage, il n'est pas possible de les modifier depuis l'interface, et les basculer dans votre environnement sans redémarrage n'a aucun effet.

Les fonctionnalités proposées uniquement sur le Cloud apparaissent comme **Unavailable on This Deployment** sur une instance sur site. C'est normal et ce n'est pas un problème de licence.

## Disponibilité des fonctionnalités

La plupart des fonctionnalités sont disponibles pour les deux types d'installation. Voici les exceptions :

| Fonctionnalité | Disponibilité | Mode de contrôle |
| --- | --- | --- |
| Request a New Connector | [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) uniquement | Page Indicateurs de fonctionnalités. Affichée comme **Unavailable on This Deployment** sur site. |
| Locations | Les deux | Page Indicateurs de fonctionnalités. Notez que Locations ne peut plus être désactivée une fois activée. Voir [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Les deux | Page Indicateurs de fonctionnalités pour l'interface Pro ; l'interface classique, ses URL et les rapports générés suivent le paramètre de déploiement `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`. Voir [ci-dessus](#organization--asset-relabeling). |

Toutes les autres fonctionnalités optionnelles se basculent directement sur la page Indicateurs de fonctionnalités, aussi bien sur les instances Cloud que sur site.

## Lire les indicateurs de fonctionnalités en dehors de l'interface

Il n'est pas nécessaire d'ouvrir la page Indicateurs de fonctionnalités pour savoir quelles fonctionnalités sont activées — l'état des indicateurs peut aussi être lu par programmation, ce qui est utile lorsqu'une automatisation doit vérifier qu'une fonctionnalité est disponible avant d'en dépendre.

```
GET /api/v2/defectdojo_information/feature_flags/
```

Cela renvoie un tableau JSON contenant un objet par indicateur de fonctionnalité. Outre les champs `key`, `title` et `description` de l'indicateur, chaque objet fournit les valeurs habituellement utiles à l'automatisation : `effective` (indique si la fonctionnalité est réellement activée pour cette instance), `default`, `application_value` (le paramètre propre à l'instance, ou `null` s'il n'est pas défini), `editable`, et `locked_reason` lorsqu'un indicateur ne peut pas être modifié. Les indicateurs retirés du produit sont omis.

Tout utilisateur **authentifié** peut le lire — aucun rôle de superutilisateur n'est requis. Pour le schéma exact de la réponse sur votre version, consultez la documentation API interactive de votre instance à l'adresse `/api/v2/oa3/swagger-ui/`, générée à partir de la version en cours d'exécution. Voir aussi la [documentation de l'API v2](/automation/api/api-v2-docs/).

La même liste en lecture seule est également publiée sur la surface `/api/mcp/` de l'instance, à l'adresse `/api/mcp/defectdojo_information/feature_flags/`.

Ce point de terminaison est en **lecture seule**. L'activation ou la désactivation d'une fonctionnalité se fait toujours depuis la page Indicateurs de fonctionnalités, ou — pour les fonctionnalités configurées au niveau du déploiement mentionnées ci-dessus — dans vos paramètres de déploiement.

## Questions fréquentes

**Une fonctionnalité que je souhaite n'est pas dans la liste.**
La liste ne présente que les fonctionnalités optionnelles. Les fonctionnalités toujours activées n'y figurent pas. Si vous vous attendiez à voir une fonctionnalité manquante, vérifiez que votre licence l'inclut, puis contactez le [support DefectDojo](mailto:support@defectdojo.com).

**J'ai activé une fonctionnalité mais je ne la vois pas.**
Rechargez la page — les entrées de menu et les routes sont évaluées au chargement de la page, si bien qu'une fonctionnalité nouvellement activée apparaît au chargement suivant plutôt qu'instantanément dans la vue actuelle.

**Une mise à niveau modifiera-t-elle mes paramètres ?**
Non. La mise à niveau conserve les fonctionnalités que vous avez activées et celles que vous avez désactivées.
