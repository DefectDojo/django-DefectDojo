---
title: Reimport
description: Découvrez comment importer des données manuellement, via l'API, ou via
  un connecteur
weight: 2
aliases:
- /fr/en/connecting_your_tools/import_scan_files/using_reimport
---

Lorsqu'un Test est créé dans DefectDojo (soit à l'avance, soit en important un fichier de scan), le Test peut être étendu avec de nouvelles données de Constatation.

Par exemple, imaginons que vous disposiez d'un pipeline CI/CD conçu pour envoyer chaque jour un nouveau rapport à DefectDojo. Plutôt que de créer un nouveau Test ou Engagement pour chaque « exécution » du pipeline, vous pourriez faire en sorte que chaque rapport alimente le même Test grâce au **Reimport**.

## Reimport : résumé du processus

La réimportation de données ne remplace aucune ancienne donnée du Test ; elle compare plutôt le fichier de scan entrant avec les données de scan existantes dans un test afin de prendre des décisions éclairées :

* D'après le dernier fichier, quelles vulnérabilités sont encore présentes ?
* Quelles vulnérabilités ne sont plus présentes ?
* Quelles vulnérabilités avaient été précédemment résolues, mais ont depuis été réintroduites ?

Le Test suit et distingue chaque version de scan via l'**historique d'import,** afin que vous puissiez consulter dans le temps les changements de Constatations de votre Test.

![image](images/using_reimport.png)

## Logique du Reimport : créer, ignorer, clôturer ou rouvrir

Lors de l'utilisation du Reimport, DefectDojo compare les données de scan entrantes avec les données de scan existantes, puis applique les changements suivants aux Constatations contenues dans votre Test :

### Créer des Constatations

Toute vulnérabilité qui n'était pas présente dans l'import précédent sera automatiquement ajoutée au Test en tant que nouvelle Constatation.

### Ignorer les Constatations existantes

Si des Constatations entrantes correspondent à des Constatations déjà existantes, les Constatations entrantes seront écartées plutôt qu'enregistrées comme Doublons. Ces Constatations ont déjà été enregistrées \- il n'est pas nécessaire d'ajouter un nouvel objet Constatation. La page du Test affichera ces Constatations comme **Left Untouched**.

### Champs fix_available et fix_version

Si des Constatations entrantes correspondent à des Constatations déjà existantes, DefectDojo vérifie si les champs `fix_available` et `fix_version` de la Constatation entrante diffèrent, et les met à jour le cas échéant. Ces Constatations ont déjà été enregistrées \- il n'est pas nécessaire d'ajouter un nouvel objet Constatation. La page du Test affichera ces Constatations comme **Left Untouched**.

### Clôturer des Constatations

S'il existe des Constatations déjà présentes dans le Test mais absentes du rapport entrant, vous pouvez choisir de les définir automatiquement comme Inactives et Atténuées (en supposant que ces vulnérabilités ont été résolues depuis le précédent import). La page du Test affichera ces Constatations comme **Closed**.

Si vous **ne souhaitez pas** que d'anciennes Constatations soient clôturées, vous pouvez désactiver ce comportement sur le Reimport :

* Décochez la case **Close Old Findings** si vous utilisez l'interface
* Définissez `close_old_findings` sur `False` si vous utilisez l'API (sur ce point de terminaison, `close_old_findings` vaut `True` par défaut)

**Remarque sur le périmètre :** contrairement à l'Import, le Reimport ne peut jamais examiner d'autres Tests de l'Engagement lorsqu'il détermine quelles Constatations clôturer. Le périmètre de clôture des Constatations est toujours limité au Test cible.

La fonctionnalité `close_old_findings` respecte également le champ `service` : seules les Constatations ayant une valeur `service` identique (ou aucune valeur `service`, si aucune n'a été spécifiée) seront prises en compte pour la clôture.

### Rouvrir des Constatations

* Si des Constatations clôturées réapparaissent lors d'un Reimport, elles seront automatiquement rouvertes. L'hypothèse est que ces vulnérabilités se sont reproduites, malgré une atténuation antérieure. La page du Test suivra ces Constatations comme **Reactivated**.

Si vous utilisez un scanner sans triage, ou si vous ne souhaitez pas que les Constatations clôturées soient réactivées, vous pouvez désactiver ce comportement sur le Reimport :

* Définissez **do\_not\_reactivate** sur **True** si vous utilisez l'API
* Cochez la case **Do Not Reactivate** si vous utilisez l'interface

### Comportement Force Active et Force Verified

Définir `active=true` (interface : **Force Active**) ou `verified=true` (interface : **Force Verified**) lors d'un Reimport applique le statut correspondant à chaque Constatation correspondante, **y compris les constatations qui seraient autrement Inactives car Atténuées**. Il s'agit du même comportement de réactivation décrit ci-dessus, simplement rendu explicite pour chaque Constatation entrante.

Force Active et Force Verified ne remplacent **pas** les statuts qui représentent une décision explicite d'un utilisateur ou du système quant à la raison pour laquelle une Constatation ne devrait pas être Active :

| Statut | Force Active la réactive-t-elle ? | Pourquoi |
|---|---|---|
| Atténué / Clôturé | Oui | Identique au comportement de réactivation par défaut |
| Risque accepté | Non | La Constatation est Inactive car un utilisateur a explicitement accepté le risque ; le reimport ne doit pas révoquer silencieusement cette décision |
| Doublon | Non | La Constatation est Inactive car la déduplication l'a marquée comme doublon d'une autre Constatation ; c'est la Constatation d'origine (et non le doublon) qui doit être active |
| Faux positif | Non | Même raisonnement que pour Risque accepté — une décision de triage explicite |
| Hors périmètre | Non | Même raisonnement que pour Risque accepté — une décision de triage explicite |

Si vous souhaitez qu'une Constatation Risque accepté ou Doublon redevienne Active, vous devez d'abord supprimer l'Acceptation du risque ou le marqueur de Doublon. Force Active seul ne suffit pas.

## Ouvrir le formulaire de Reimport

Le formulaire **Re\-Import Findings** est accessible depuis n'importe quelle page de Test, sous le menu déroulant **⚙️Gear**.

![image](images/using_reimport_2.png) 

Le **Re\-import Findings** **Form** ne vous permettra **pas** d'importer un Type de scan différent, ni de changer la destination des Constatations que vous essayez de téléverser. Si vous souhaitez effectuer l'une de ces actions, vous devrez utiliser le **formulaire d'importation de scan**.

## Utiliser l'historique d'import

L'historique d'import d'un Test donné est répertorié sous l'en-tête **Test Overview** sur la page du **Test**.

Ce tableau affiche chaque Import ou Reimport sur une seule ligne avec un **horodatage**, ainsi que les colonnes **Branch Tag, Build ID, Commit Hash** et **Version**, si celles-ci ont été spécifiées.

![image](images/using_reimport_3.png)

### Actions

Cet en-tête indique les actions effectuées par un Import/Reimport.

* **\# created indique le nombre de nouvelles Constatations créées au moment de l'Import/Reimport**
* **\# closed indique le nombre de Constatations qui ont été clôturées par un Reimport (car absentes du rapport entrant).**
* **\# left untouched indique le nombre de Constatations ouvertes qui n'ont pas été modifiées par un Reimport (car elles existaient également dans le rapport entrant).**
* **\#** **reactivated** indique les Constatations clôturées qui ont été rouvertes par un Reimport entrant.

## Déduplication du Reimport

Le Reimport détermine si un élément entrant correspond à une Constatation existante à l'aide des paramètres de **[déduplication du Reimport](/triage_findings/finding_deduplication/about_deduplication/)**. Ceci est distinct de la « déduplication même outil » et de la « déduplication multi-outils », qui interviennent une fois que les Constatations existent déjà.

Si vous constatez que le Reimport clôture d'anciennes Constatations et en crée de nouvelles alors qu'un seul attribut mineur a changé (par exemple, un décalage de numéro de ligne), ajustez la **déduplication du Reimport** de cet outil pour utiliser des identifiants stables qui ignorent ces attributs (comme Unique ID From Tool).

**DefectDojo Pro** peut résoudre ce problème directement pour les outils dépourvus d'identifiants uniques fiables : l'activation du **[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/)** permet au Reimport de reconnaître une Constatation dont l'emplacement a changé — décalage de ligne, renommage de fichier, déplacement d'URL ou changement de version de dépendance — comme étant la *même* Constatation, en la mettant à jour sur place et en conservant son historique d'emplacement.

## Reimport via l'API - remarque particulière

Notez que le point de terminaison API /reimport peut à la fois **étendre un Test existant** (en appliquant la méthode décrite dans cet article) **ou créer un nouveau Test** avec de nouvelles données \- un appel initial à `/import`, ou la création préalable d'un Test, n'est pas nécessaire.

Pour en savoir plus sur la création d'un pipeline CI/CD automatisé avec DefectDojo, consultez notre guide [ici](/automation/api/api-v2-docs/).
