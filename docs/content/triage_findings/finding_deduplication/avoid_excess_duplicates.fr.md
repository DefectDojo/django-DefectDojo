---
title: Éviter les doublons excessifs
description: ''
weight: 4
aliases:
- /fr/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport
---

L'un des atouts de DefectDojo est que son modèle de données peut s'adapter à de nombreux cas d'usage et applications différents. Vous serez probablement amené à modifier votre approche à mesure que vous maîtriserez le logiciel et découvrirez des moyens d'optimiser votre flux de travail.

Par défaut, DefectDojo ne supprime aucune Constatation en double créée. Chaque Constatation est considérée comme une instance distincte d'une vulnérabilité. Dans ce cas, les **Constatations en double** peuvent donc indiquer qu'un changement de processus est nécessaire dans votre flux de travail.

## Quand les Constatations en double sont-elles acceptables ?

Les Constatations en double ne sont pas toujours révélatrices d'un problème. Il existe de nombreux cas où conserver les doublons est l'approche à privilégier. Par exemple :

* Si votre équipe utilise et produit des rapports sur des Engagements interactifs. Si vous souhaitez créer un rapport distinct portant spécifiquement sur un seul Test, vous voudrez savoir s'il existe une occurrence d'une Constatation déjà découverte auparavant.
* Si vous avez des Engagements séparés par contexte (par exemple, parce qu'ils couvrent des dépôts différents), vous voudrez pouvoir signaler les Constatations qui apparaissent aux deux endroits.

## Vérifier les imports redondants

## Étape 1 : nettoyez vos doublons excédentaires

Heureusement, les paramètres de Déduplication de DefectDojo vous permettent de supprimer les doublons en masse une fois qu'un certain seuil a été dépassé. Cette fonctionnalité facilite le processus de nettoyage. Pour en savoir plus sur ce processus, consultez notre article sur la **Déduplication des constatations** \<\-lien à venir ici.

### Étape 2 : évaluez vos Engagements à la recherche de redondances

Une fois que vous avez nettoyé vos Constatations en double, il est recommandé d'examiner le Produit qui les contenait pour voir s'il y a un coupable évident. Vous pourriez constater que certains Engagements qu'il contient ont un contexte redondant.

#### Engagements en double ou réutilisés

Les Engagements stockent un ou plusieurs Tests pour un contexte de test particulier. C'est finalement à vous de définir ce contexte, mais si vous constatez que plusieurs Engagements au sein de votre Produit devraient partager le même contexte, envisagez de les combiner en un seul engagement.
​
### Questions à se poser pour définir le contexte d'un Engagement :

* Si je voulais produire un rapport sur ce travail, l'Engagement contiendrait-il toutes les informations pertinentes dont j'ai besoin ?
* Créons-nous les Engagements de manière proactive à l'avance, ou sont-ils créés « ad\-hoc » par mon processus d'import ?
* Utilisons-nous le bon type d'Engagement \- **Interactif** ou **CI/CD** ?
* Quelle section de la base de code est concernée par les tests : chaque dépôt est-il un contexte distinct, ou plusieurs dépôts pourraient-ils constituer un contexte de test partagé ?
* Qui sont les parties prenantes impliquées dans le Produit, et comment vais-je partager les résultats avec elles ?

### Étape 3 : recherchez les Tests redondants

Si vous découvrez que des Tests distincts ont été créés pour capturer le même contexte de test, cela peut indiquer que ces tests peuvent être consolidés en un seul Réimport.

DefectDojo propose deux méthodes pour importer des données de test afin de créer des Constatations : **Import** et **Reimport**. Ces deux méthodes sont très similaires, mais la différence clé entre les deux est que l'**Import** crée toujours un nouveau Test, tandis que le **Reimport** peut ajouter de nouvelles données à un Test existant. Il convient également de noter que le **Reimport** ne crée pas de Constatations en double au sein de ce Test.

Chaque fois que vous importez de nouveaux rapports de vulnérabilités dans DefectDojo, ces rapports sont stockés dans un objet Test. Un objet Test peut être créé à l'avance par un utilisateur pour accueillir un futur **Import**. Si un utilisateur souhaite importer des données sans spécifier de Test de destination, un nouveau Test sera créé pour stocker le rapport entrant.

Les Tests sont des objets flexibles et, bien qu'ils ne puissent contenir qu'un seul *type* de rapport, ils peuvent gérer plusieurs instances de ce même rapport grâce à la méthode **Reimport**. Pour en savoir plus sur le Reimport, consultez notre **[article](/import_data/import_intro/reimport/)** sur le sujet.


## Utiliser le Reimport pour des Tests continus

Si vous avez un pipeline CI/CD, un processus de scan quotidien ou tout autre type de rapport entrant répété, la mise en place à l'avance d'un processus de Reimport est essentielle pour éviter les doublons excessifs. Le Reimport regroupe le contexte et les Constatations associés à un test récurrent sur une seule page de Test, où vous pouvez consulter l'historique des imports et suivre l'évolution des vulnérabilités d'un scan à l'autre.

1. Créez un Engagement pour stocker les résultats CI/CD de l'objet sur lequel vous exécutez votre CI/CD. Il peut s'agir d'un dépôt de code sur lequel des actions CI/CD sont configurées. En général, vous voudrez un Engagement distinct pour chaque pipeline, afin de pouvoir rapidement comprendre d'où proviennent les résultats de Constatation.
​
2. Chaque action CI/CD importera des données dans DefectDojo à une étape distincte, chacune d'elles doit donc être associée à un Test distinct. Par exemple, si chaque exécution du pipeline lance un audit NPM\-audit ainsi qu'un scan de dépendances, chaque résultat de scan devra alimenter un Test (imbriqué sous l'Engagement).
​
3. Vous n'avez pas besoin de créer un nouveau Test à chaque exécution de l'action CI/CD. Vous pouvez à la place **Reimport** les données au même emplacement de test.

### Le Reimport en action

DefectDojo comparera les données de scan entrantes avec les données de scan existantes, puis appliquera des changements aux Constatations contenues dans votre Test comme suit :
​
#### Création de Constatations

Toute vulnérabilité qui n'était pas présente dans l'import précédent sera ajoutée automatiquement au Test en tant que nouvelle Constatation.
​
#### Ignorer les Constatations existantes

Si des Constatations entrantes correspondent à des Constatations déjà existantes, les Constatations entrantes seront écartées plutôt qu'enregistrées comme doublons. Ces Constatations ont déjà été enregistrées \- inutile d'ajouter un nouvel objet Constatation. La page du Test affichera ces Constatations comme **Left Untouched**.
​
#### Clôture des Constatations

S'il existe des Constatations déjà présentes dans le Test mais absentes du rapport entrant, vous pouvez choisir de les définir automatiquement comme Inactives et Atténuées (en supposant que ces vulnérabilités ont été résolues depuis l'import précédent). La page du Test affichera ces Constatations comme **Closed**.

Si vous ne souhaitez qu'aucune Constatation ne soit clôturée, vous pouvez désactiver ce comportement lors du Reimport :

* Décochez la case **Close Old Findings** si vous utilisez l'interface
* Définissez **close\_old\_findings** sur **False** si vous utilisez l'API  ​

#### Réouverture des Constatations

* Si des Constatations Closed réapparaissent lors d'un Reimport, elles seront automatiquement Reopened. On suppose alors que ces vulnérabilités se sont reproduites malgré une atténuation antérieure. La page du Test suivra ces Constatations comme **Reactivated**.

Si vous utilisez un scanner sans triage, ou si vous ne souhaitez pas que les Constatations Closed soient réactivées, vous pouvez désactiver ce comportement lors du Reimport :

* Définissez **do\_not\_reactivate** sur **True** si vous utilisez l'API
* Cochez la case **Do Not Reactivate** si vous utilisez l'interface

### Utiliser l'historique des imports

L'historique des imports d'un test donné est répertorié sous l'en-tête **Test Overview** sur la page **Test**.

Ce tableau affiche chaque Import ou Reimport sur une seule ligne avec un **Timestamp**, ainsi que des colonnes **Branch Tag, Build ID, Commit Hash** et **Version** si celles-ci ont été spécifiées.

![image](images/Avoiding_Duplicates_Reimport_Recurring_Tests.png)

### Actions

Cet en-tête indique les actions effectuées par un Import/Reimport.

* **\# created indique le nombre de nouvelles Constatations créées au moment de l'Import/Reimport**
* **\# closed indique le nombre de Constatations qui ont été closes par un Reimport (car absentes du rapport entrant).**
* **\# left untouched indique le nombre de Constatations Open qui n'ont pas été modifiées par un Reimport (car elles existaient également dans le rapport entrant).**
* **\#** **reactivated** indique toute Constatation Closed qui a été rouverte par un Reimport entrant.

### Pourquoi ne pas simplement utiliser l'Import ?

Bien que les deux méthodes soient possibles, l'Import doit être réservé aux **nouvelles occurrences** de Constatations et de données, tandis que le Reimport doit être appliqué pour les **itérations ultérieures** des mêmes données.

Si votre pipeline CI/CD exécute un Import et crée un nouvel objet Test à chaque fois, chaque Import vous donnera une collection de Constatations distinctes que vous devrez ensuite gérer comme des objets séparés. Utiliser le Reimport atténue ce problème et élimine la quantité de « nettoyage » que vous devrez faire lorsqu'une vulnérabilité est résolue.

Utiliser le Reimport vous permet de stocker chaque rapport récurrent sur la même page, et maintient une continuité à chaque fois que de nouvelles données ont été ajoutées au Test.

Cependant, si vous utilisez le même outil de scan dans plusieurs emplacements ou contextes, il peut être plus approprié de créer un Test distinct pour chaque emplacement ou contexte. Cela dépend de votre méthode d'organisation préférée.
