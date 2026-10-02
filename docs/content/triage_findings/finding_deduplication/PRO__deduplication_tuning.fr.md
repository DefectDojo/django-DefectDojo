---
title: Réglage de la déduplication
description: Configurez la façon dont DefectDojo identifie et gère les constatations
  en double
weight: 4
audience: pro
aliases:
- /fr/en/working_with_findings/finding_deduplication/tune_deduplication
---

Le réglage de la déduplication est une fonctionnalité de DefectDojo Pro qui vous donne un contrôle précis sur la façon dont les constatations sont dédupliquées, ce qui vous permet d'optimiser la détection des doublons pour votre flux de travail spécifique de tests de sécurité.

## Paramètres de déduplication

Dans DefectDojo Pro, vous pouvez accéder au réglage de la déduplication via :
**Settings > Finding Workflow** (**Settings > Pro Settings > Deduplication Settings** sur les instances utilisant encore l'ancienne disposition de menu)

![image](images/deduplication_tuning.png)

La page des paramètres de déduplication propose trois domaines de configuration clés :
- Déduplication par le même outil
- Déduplication entre outils
- Déduplication à la réimportation

## Déduplication par le même outil

La déduplication par le même outil est activée par défaut pour tous les analyseurs d'outils de sécurité. Cela garantit que les constatations provenant d'analyses consécutives utilisant le même outil sont correctement dédupliquées.

Pour ajuster la déduplication par le même outil :

1. Sélectionnez un **outil de sécurité** spécifique dans le menu déroulant
2. Choisissez un **algorithme de déduplication** parmi les options disponibles

![image](images/same_tool_deduplication.png)

### Algorithmes de déduplication disponibles

DefectDojo Pro propose les méthodes de déduplication suivantes pour la déduplication par le même outil :

#### Code de hachage
Utilise une combinaison de champs sélectionnés pour générer un hachage unique. Lorsqu'il est sélectionné, un troisième menu déroulant apparaît, affichant les champs utilisés pour calculer le hachage.

##### Empreinte de contenu

**Empreinte de contenu** est un champ de hachage sélectionnable (disponible dans les trois domaines de configuration) qui fournit une identité *invariante par rapport à l'emplacement* pour les constatations d'analyse statique. Elle est dérivée de l'extrait de code vulnérable que l'outil inclut dans la constatation, normalisé de sorte que l'indentation, les annotations de numéro de ligne et les différences de formatage ne la modifient pas. Deux constatations portant sur le même code vulnérable produisent un hachage identique, même si le code a été déplacé vers une autre ligne ou un autre fichier.

L'empreinte de contenu est calculée pour les outils qui incluent un extrait de code dans la description de la constatation, notamment **Bandit**, **Gosec**, **Brakeman**, **Checkmarx One**, ainsi que tout outil dont la description contient un bloc de code délimité ou un extrait SARIF.

> **Avant de sélectionner l'empreinte de contenu comme champ de hachage**, générez les empreintes des constatations existantes en exécutant `./manage.py backfill_fingerprints`. Les constatations importées après l'activation de la fonctionnalité obtiennent automatiquement une empreinte, mais les constatations préexistantes n'en ont aucune — sélectionner ce champ sans exécuter le remplissage rétroactif fait que les constatations existantes et entrantes produisent des hachages différents, ce qui rompt chaque correspondance jusqu'à l'exécution du remplissage rétroactif.

L'empreinte de contenu se combine bien avec **CWE** pour les outils qui intègrent des chemins de fichiers ou des numéros de ligne dans leurs titres, où les autres champs d'identité changent à chaque déplacement du code. Voir [Correspondance par dérive d'emplacement](/triage_findings/finding_deduplication/pro__location_drift_matching/#choosing-hash-fields-for-tracked-tools).

#### Identifiant unique de l'outil
Exploite l'identifiant interne propre à l'outil de sécurité pour les constatations, garantissant une déduplication parfaite lorsque le scanner fournit des identifiants uniques fiables.

Cet algorithme peut être utile lorsque vous travaillez avec des scanners SAST, ou dans les situations où une constatation peut « se déplacer » dans le code source au fil du développement.

#### Identifiant unique de l'outil ou code de hachage
Tente d'abord d'utiliser l'identifiant unique de l'outil, puis se rabat sur le code de hachage si aucun identifiant unique n'est disponible. Cela offre l'option de déduplication la plus flexible.

#### Composant global
Fait correspondre les constatations par nom et version de composant sur **tous les Produits** de l'instance, plutôt qu'au sein d'un seul Produit ou Engagement. Destiné aux outils SCA où la même dépendance vulnérable apparaît dans de nombreux Produits. Cet algorithme est désactivé par défaut et doit être activé par le support DefectDojo. Voir [Déduplication des composants globaux](/triage_findings/finding_deduplication/pro__global_component_deduplication/) pour plus de détails.

#### Identifiant de vulnérabilité global
Fait correspondre les constatations par leurs **identifiants de vulnérabilité** (CVE, GHSA, …) sur **tous les Produits** de l'instance, plutôt qu'au sein d'un seul Produit ou Engagement. Destiné aux outils qui signalent le même CVE dans de nombreux Produits. Désactivé par défaut et activé par le support DefectDojo.

> **Deux outils utilisant le même algorithme à l'échelle de l'instance deviennent des candidats mutuels à la déduplication.** Lorsque deux outils *différents* sont tous deux configurés avec un algorithme à l'échelle de l'instance (Composant global ou Identifiant de vulnérabilité global), leurs constatations partagent un hachage de regroupement constant, de sorte qu'une constatation de l'un des outils est prise en compte pour la déduplication par rapport à l'autre sur cette dimension partagée (composant ou identifiant de vulnérabilité). Il s'agit du comportement inter-outils prévu — n'activez cette option que si vous souhaitez que ces outils soient dédupliqués ensemble.

### Champs de code de hachage basés sur des ensembles (identifiants de vulnérabilité et CWE)

Deux attributs de constatation contiennent un *ensemble* de valeurs plutôt qu'une valeur unique : les identifiants de vulnérabilité (CVE, GHSA, …) et les CWE. Lorsque vous utilisez l'algorithme **code de hachage** (même outil ou entre outils), vous pouvez ajouter les champs suivants aux **champs de code de hachage** pour contrôler la façon dont ces ensembles sont comparés :

| Champ | Les constatations sont des doublons lorsque… |
|-------|-------------------------------|
| `vulnerability_ids` | elles ont **exactement le même ensemble** d'identifiants de vulnérabilité |
| `vulnerability_ids_partial` | elles partagent **au moins un** identifiant de vulnérabilité |
| `vulnerability_ids_subset` | les identifiants de vulnérabilité d'une constatation sont un **sous-ensemble** de ceux de l'autre |
| `cwes` | elles ont **exactement le même ensemble** de CWE |
| `cwes_partial` | elles partagent **au moins un** CWE |
| `cwes_subset` | les CWE d'une constatation sont un **sous-ensemble** de ceux de l'autre |

Les champs `_partial` et `_subset` sont comparés par paire de constatations plutôt qu'intégrés au hachage : les autres champs de code de hachage regroupent les constatations candidates, puis la comparaison d'ensembles affine ce groupe. (La correspondance exacte — `vulnerability_ids` et `cwes` — est intégrée directement au hachage.)

**Valeurs vides.** Si une constatation n'a pas d'identifiants de vulnérabilité (ou pas de CWE) pour le comparateur configuré :

- Si les champs de code de hachage incluent également un champ ordinaire (par exemple `title`), ce champ porte l'identité — le comparateur d'ensembles est ignoré pour la paire et les constatations peuvent tout de même correspondre sur le reste du hachage.
- Si un comparateur d'ensembles est le **seul** champ, une constatation sans valeurs ne correspond à rien : faute d'autre élément pour l'identifier, un ensemble vide n'est pas considéré comme correspondant à toutes les autres constatations.

**Règles de configuration** (appliquées lors de l'enregistrement des paramètres) :

- Un champ d'identifiants de vulnérabilité (`vulnerability_ids`, `vulnerability_ids_partial` ou `vulnerability_ids_subset`) peut être utilisé seul — un CVE ou un GHSA identifie une instance de vulnérabilité spécifique.
- Les champs CWE (`cwes`, `cwes_partial`, `cwes_subset`) ne peuvent **pas** être l'unique critère. Un CWE est une *classe* de faiblesse, pas une instance spécifique, donc une correspondance basée uniquement sur le CWE fusionnerait des constatations non liées. Associez un comparateur CWE à un champ identifiant tel que `title` ou `file_path`.

## Déduplication entre outils

La déduplication entre outils est désactivée par défaut, car la déduplication entre différents outils de sécurité nécessite une configuration minutieuse en raison des variations dans la façon dont les outils signalent les mêmes vulnérabilités.

![image](images/cross_tool_deduplication.png)

Pour activer la déduplication entre outils :

1. Sélectionnez un **outil de sécurité** dans le menu déroulant
2. Faites passer l'**algorithme de déduplication** de « Désactivé » à « Code de hachage »
3. Sélectionnez les champs à utiliser pour générer le hachage dans le menu déroulant **champs de code de hachage**

La déduplication entre outils prend en charge l'algorithme de code de hachage, adapté à la plupart des flux de travail, car différents outils partagent rarement des identifiants uniques compatibles. Pour les outils SCA signalant les mêmes dépendances, la [déduplication des composants globaux](/triage_findings/finding_deduplication/pro__global_component_deduplication/) est également disponible comme option entre outils (désactivée par défaut).

Notez que la déduplication entre outils est également limitée aux Actifs individuels uniquement.

## Déduplication à la réimportation

**⚠️ Les processus de réimportation peuvent complètement rejeter des constatations avant qu'elles ne soient enregistrées. Cela peut entraîner une perte de données en cas de configuration incorrecte ; les paramètres de déduplication à la réimportation doivent donc être ajustés avec prudence.**

Les paramètres de déduplication à la réimportation permettent de définir un algorithme pour les Universal Parsers, ou pour un Generic Findings Import Parser.

La déduplication à la réimportation ne peut pas être ajustée pour les autres outils par défaut. Les utilisateurs qui souhaitent ajuster l'algorithme de déduplication à la réimportation pour d'autres outils de leur instance doivent contacter le [support DefectDojo](mailto:support@defectdojo.com) pour obtenir de l'aide.

![image](images/reimport_deduplication.png)

Lors de la configuration de la déduplication à la réimportation :

1. Sélectionnez l'**outil de sécurité** (Universal ou Generic Parser)
2. Choisissez l'**algorithme de déduplication** approprié

Les options d'algorithme suivantes sont disponibles pour la déduplication à la réimportation :
- Code de hachage
- Identifiant unique de l'outil
- Identifiant unique de l'outil ou code de hachage

La réimportation peut complètement rejeter des constatations avant qu'elles ne soient enregistrées ; les paramètres de déduplication à la réimportation doivent donc être ajustés avec prudence.

### Suivre les constatations en cas de changement d'emplacement

Lorsque l'algorithme de déduplication à la réimportation d'un outil est **code de hachage**, une bascule supplémentaire apparaît : **suivre les constatations en cas de changement d'emplacement**. Lorsqu'elle est activée, une constatation dont l'emplacement a changé entre deux réimportations — un décalage de ligne ou un renommage de fichier, un déplacement d'URL, ou une mise à jour de version de dépendance — est traitée comme la *même* constatation, même si l'outil a réévalué sa sévérité. Une seule constatation est maintenue en place et son historique d'emplacement est conservé, au lieu que l'ancienne constatation soit clôturée et qu'une nouvelle constatation identique soit créée.

Cette bascule est désactivée par défaut et ne s'applique qu'à l'algorithme de réimportation par code de hachage (les outils disposant d'un identifiant unique de l'outil fiable suivent déjà les déplacements grâce à leurs identifiants stables). L'activer relance automatiquement le hachage des constatations existantes de l'outil en arrière-plan, afin que les données historiques participent immédiatement.

Voir [Correspondance par dérive d'emplacement](/triage_findings/finding_deduplication/pro__location_drift_matching/) pour savoir comment fonctionne la correspondance, ce qui est préservé, et des conseils pour l'activer sur de grandes instances.

## Exécuter la déduplication rétroactivement sur les données existantes

Une situation courante lors de la première activation du réglage de la déduplication est de disposer d'un important arriéré de constatations importées *avant* le changement de configuration de déduplication. Dans DefectDojo Pro, il n'est pas nécessaire d'exécuter une commande distincte pour dédupliquer ces données historiques — **la modification des paramètres de déduplication d'un outil déclenche automatiquement un nouveau hachage en arrière-plan de toutes les constatations existantes associées à ce type de test**.

Concrètement, cela signifie que :

- Lorsque vous modifiez l'**algorithme de déduplication** ou les **champs de code de hachage** d'un outil, DefectDojo met en file d'attente une tâche en arrière-plan pour recalculer les hachages de toutes les constatations de cet outil déjà présentes dans l'instance.
- La tâche s'exécute de manière asynchrone. Sur les grandes instances (des millions de constatations), cela peut prendre un certain temps et vous ne verrez pas de changements immédiats dans le tableau des constatations.
- Les hachages nouvellement calculés s'appliquent aux décisions de déduplication ultérieures pour l'ensemble de l'arriéré.

Si vous effectuez plusieurs modifications de configuration rapprochées, chacune met en file d'attente sa propre tâche de nouveau hachage. Laissez la tâche précédente se terminer avant d'évaluer les résultats, en particulier lorsque vous comparez le nombre de constatations avant et après le changement.

> **Remarque pour Pro auto-hébergé :** la tâche en arrière-plan s'exécute dans le pool de workers Celery. Si vos workers sont sous-alimentés ou surchargés, le nouveau hachage peut prendre plus de temps que prévu — vérifiez l'état des workers si les résultats n'apparaissent pas dans le délai attendu pour la taille de votre instance.

> **Les indicateurs de fonctionnalité ne conditionnent pas une configuration existante.** Les paramètres de déduplication enregistrés d'un outil restent en vigueur tant qu'ils sont configurés ; désactiver un indicateur de fonctionnalité associé **ne** rétablit **pas** rétroactivement la déduplication par défaut pour cet outil. Pour modifier ou arrêter le comportement de déduplication d'un outil, mettez à jour directement ses paramètres de déduplication (ce qui met également en file d'attente le nouveau hachage en arrière-plan décrit ci-dessus).

## Bonnes pratiques de déduplication

Pour des résultats optimaux avec le réglage de la déduplication :

- **Commencez avec les valeurs par défaut** : les paramètres de déduplication préconfigurés fonctionnent bien dans la plupart des scénarios
- **Testez les modifications avec soin** : après avoir ajusté les paramètres de déduplication, surveillez quelques imports pour vous assurer du bon comportement.
- **Planifiez les nouveaux hachages rétroactifs** : la modification des paramètres de déduplication relance le hachage de toutes les constatations existantes de cet outil en arrière-plan. Voir [Exécuter la déduplication rétroactivement sur les données existantes](#running-deduplication-retroactively-on-existing-data) ci-dessus.
- **Utilisez le code de hachage pour la déduplication entre outils** : lors de l'activation de la déduplication entre outils, sélectionnez des champs qui identifient de manière fiable la même constatation entre différents outils (comme le nom de la vulnérabilité, l'emplacement et la sévérité). **IMPORTANT** chaque outil activé pour la déduplication entre outils **DOIT** avoir les mêmes champs sélectionnés.
- **Gardez les sources entre outils dans le même Actif** : la déduplication entre outils est limitée à l'Actif. Les constatations réparties entre différents Actifs ne seront pas dédupliquées, même avec des champs de hachage correspondants. Voir [Déduplication entre outils](#cross-tool-deduplication) ci-dessus.
- **Évitez une déduplication trop large** : une déduplication entre outils avec trop peu de champs de hachage peut entraîner de faux doublons
- **Effectuez le remplissage rétroactif avant de sélectionner l'empreinte de contenu** : exécutez d'abord `./manage.py backfill_fingerprints`, puis sélectionnez le champ — le nouveau hachage déclenché dispose alors d'empreintes à exploiter. Voir [Empreinte de contenu](#content-fingerprint) ci-dessus.
- **Activez le suivi d'emplacement entre les analyses** : le nouveau hachage automatique déclenché par la bascule couvre tout l'arriéré de l'outil ; sur les grandes instances, laissez-le se terminer avant la prochaine réimportation planifiée. Voir [Correspondance par dérive d'emplacement](/triage_findings/finding_deduplication/pro__location_drift_matching/#enabling-on-existing-data-upgrades).

En ajustant les paramètres de déduplication à vos outils spécifiques, vous pouvez réduire considérablement le bruit lié aux doublons.

## Constatations verrouillées

Chaque fois que les paramètres de déduplication sont modifiés pour un outil donné, les hachages de déduplication sont recalculés pour cet outil sur l'ensemble de l'instance DefectDojo.
