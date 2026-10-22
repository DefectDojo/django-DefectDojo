---
title: Modifier les constatations
description: Modifier le statut d’une constatation, ou ajouter des métadonnées supplémentaires
  en résolvant un problème
weight: 2
aliases:
- /fr/en/working_with_findings/findings_workflows/editing_findings
---

Si vous souhaitez ajouter des notes ou mettre à jour le texte d’une constatation pour qu’il soit plus pertinent par rapport à la situation actuelle, vous pouvez le faire via le formulaire Modifier la constatation.

## Ouvrir le formulaire Modifier la constatation

Vous pouvez mettre à jour une constatation en ouvrant le **menu ⚙️ Engrenage** en haut, puis en cliquant sur **Modifier la constatation**.

![image](images/Editing_Findings.png)

Cela ouvre le formulaire **Modifier la constatation**, où vous pouvez modifier les métadonnées, changer le statut de la constatation et ajouter des informations supplémentaires.

![image](images/Editing_Findings_2.png)

### Formulaire Modifier la constatation : champs

* **« Test » ne peut pas être modifié :** les constatations doivent toujours être associées à un objet Test et ne peuvent pas être déplacées hors de ce contexte. Cependant, l’engagement contenant un test peut être déplacé vers un autre produit.  
​
* **Found By** est l’outil d’analyse qui a découvert cette constatation. Notez que vous pouvez ajouter d’autres outils d’analyse en plus de celui associé au test.  
​
* **Titre** est généré à partir du rapport d’analyse, mais vous pouvez modifier ce titre pour le rendre plus explicite si nécessaire. Notez que cela peut affecter la déduplication, car la déduplication utilise généralement les titres des constatations pour identifier les doublons.  
​
* **Date** est censée représenter la date à laquelle la constatation a été découverte par le scanner, et non nécessairement la date à laquelle la constatation a été importée dans DefectDojo. Cette date est extraite du rapport d’analyse, mais vous pouvez la mettre à jour pour plus de précision si nécessaire (par exemple, si vous travaillez avec des données historiques, ou si vous utilisez un outil d’analyse qui n’enregistre pas les dates de découverte).  
​
* **Description** est la description d’une constatation fournie par l’outil d’analyse. Vous pouvez ajouter ou supprimer des informations de la description de la constatation si vous le souhaitez.  
​
* **Sévérité** est calculée en fonction de plusieurs facteurs. À la base, il s’agit de la sévérité signalée par un outil, mais la sévérité d’une constatation peut être affectée par des changements EPSS. Vous pouvez également ajuster manuellement la sévérité de la constatation au niveau approprié.  
​
* **Étiquettes** sont des libellés textuels génériques que vous pouvez utiliser pour organiser vos constatations via des filtres, ou simplement comme raccourci pour identifier une constatation spécifique.  
​
* **Actif / Vérifié** sont les principaux statuts de constatation utilisés par un outil. Les constatations Actif sont des constatations actuellement actives dans votre réseau et signalées par un outil. Vérifié signifie que l’existence de cette constatation a été confirmée par un membre de l’équipe.  
​
* **SAST / DAST** sont des libellés utilisés pour organiser vos constatations selon le contexte dans lequel elles ont été découvertes. En général, ce libellé est renseigné en fonction de l’outil d’analyse utilisé, mais vous pouvez l’ajuster pour plus de précision (par exemple, si la constatation a été détectée à la fois par un outil SAST et un outil DAST).

### Modifier la date d’atténuation et l’auteur de l’atténuation

Par défaut, les valeurs **Date d’atténuation** et **Atténué par** d’une constatation ne sont **pas modifiables**. Ces champs sont masqués à la fois dans le formulaire Modifier la constatation et dans la boîte de dialogue Fermer la constatation, et la date d’atténuation est toujours définie automatiquement au moment où la constatation est fermée. Toute tentative de définir ou d’antidater ces valeurs via l’API est rejetée pour la même raison.

La modification peut être activée via le paramètre serveur `DD_EDITABLE_MITIGATED_DATA`. Lorsqu’il est activé, les champs **Date d’atténuation** et **Atténué par** apparaissent dans le formulaire Modifier la constatation et dans la boîte de dialogue Fermer la constatation, et peuvent également être définis via l’API — mais uniquement pour les utilisateurs ayant le statut **superuser**. Autrement dit, la modification nécessite *à la fois* que le paramètre soit activé *et* que l’utilisateur effectuant l’action soit superuser.

* **Pourquoi ce paramètre est désactivé par défaut :** permettre d’antidater une atténuation peut fausser la conformité au SLA — une constatation réellement corrigée *en dehors* de sa fenêtre SLA pourrait être enregistrée comme si elle avait été atténuée *dans les délais* du SLA. L’activation du paramètre n’est prospective que pour l’avenir ; elle **ne** modifie **pas** la date d’atténuation ni l’ancienneté des constatations existantes.
* **Tout reste auditable :** chaque modification apportée à une constatation, y compris les modifications de la date d’atténuation et de l’auteur de l’atténuation, est enregistrée dans l’historique de la constatation — qui a effectué la modification, quand, ainsi que les valeurs précédentes et nouvelles.
* **Appliquer le paramètre :** `DD_EDITABLE_MITIGATED_DATA` est une variable d’environnement au niveau du serveur (voir [Configuration](/get_started/open_source/configuration/)). Sa modification nécessite un redémarrage du service pour prendre effet.
* **DefectDojo Cloud / Pro :** ce paramètre ne peut pas être modifié depuis l’interface. Contactez le support DefectDojo pour le faire activer sur votre instance.

## Modifier les constatations en masse

Les constatations peuvent être modifiées en masse depuis une liste de constatations, disponible soit sur la page Constatations elle-même, soit depuis un test.

### Sélectionner des constatations pour une modification en masse

Lorsque vous consultez un tableau contenant plusieurs constatations, comme le tableau « Findings From \[tool\] » sur une page de test ou la liste Toutes les constatations, vous pouvez utiliser les cases à cocher situées à côté des constatations pour les marquer en vue d’une modification en masse.

Sélectionner une ou plusieurs constatations de cette manière ouvre le menu (masqué) Modification en masse, qui contient les quatre options suivantes :

* **Actions de mise à jour groupée** : appliquer des modifications de métadonnées aux constatations sélectionnées.
* **Actions d’acceptation du risque : créer une acceptation du risque complète pour régir les constatations sélectionnées, ou ajouter les constatations à une acceptation du risque complète existante**
* **Actions de groupe de constatations : créer un groupe de constatations composé des constatations sélectionnées. Notez que les groupes de constatations ne peuvent être créés qu’au sein d’un test individuel.**
* **Supprimer : supprimer les constatations sélectionnées. Vous devrez confirmer cette action dans une nouvelle fenêtre.**

![image](images/Bulk_Editing_Findings.png)

### Actions de mise à jour groupée

Depuis le menu Actions de mise à jour groupée, vous pouvez appliquer les modifications suivantes aux constatations sélectionnées :

* Mettre à jour la **Sévérité**
* Appliquer un nouveau **statut de constatation**
* Modifier la date de découverte ou la date de correction planifiée des constatations
* Ajouter une **acceptation du risque simple**, si l’option est activée au niveau du produit
* Appliquer des **Étiquettes** ou des **Notes** à toutes les constatations sélectionnées.

![image](images/Bulk_Editing_Findings_2.png)

### Actions d’acceptation du risque

Cette page vous permet d’ajouter une **acceptation du risque complète** aux constatations sélectionnées. Vous pouvez soit créer une nouvelle **acceptation du risque complète**, soit ajouter les constatations à une acceptation existante.

![image](images/Bulk_Editing_Findings_3.png)

### Actions de groupe de constatations

Cette page vous permet de créer un nouveau groupe de constatations à partir des constatations sélectionnées, ou de les ajouter à un groupe de constatations existant.

Cependant, les groupes de constatations ne peuvent être créés qu’au sein d’un **test** individuel - les constatations provenant de tests, d’engagements ou de produits différents ne peuvent pas être ajoutées au même groupe de constatations.

![image](images/Bulk_Editing_Findings_4.png)

### Supprimer des constatations en masse

Vous pouvez également supprimer les constatations sélectionnées en cliquant sur le bouton rouge **Supprimer**. Une fenêtre contextuelle apparaîtra pour vous demander de confirmer cette décision.

![image](images/Bulk_Editing_Findings_5.png)
