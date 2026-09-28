---
title: Définitions des statuts de constatation
description: 'Une référence rapide sur les statuts de constatation : Ouvert, Vérifié,
  Accepté..'
weight: 2
aliases:
- /fr/en/working_with_findings/findings_workflows/finding_status_definitions
---

Chaque constatation créée dans DefectDojo possède un statut qui communique des informations pertinentes. Les statuts aident votre équipe à suivre sa progression dans la résolution des problèmes.

Chaque statut de constatation a une signification propre au contexte, qui devra être définie par votre équipe. Voici nos suggestions, mais l’usage de votre équipe peut varier.

Veuillez noter qu’Ouvert/Fermé ne sont pas des types de statut **explicites** pour les constatations.  Certains éléments de l’interface Classic UI (le tableau « All Open Findings », par exemple) peuvent faire référence à des constatations ouvertes ou fermées : il s’agit d’une catégorie générique regroupant

* Les constatations Actif et/ou Vérifié, dans le cas des « constatations ouvertes »
* Les constatations Inactif et/ou Risque accepté, En cours de révision, Hors périmètre, Faux positif, dans le cas des « constatations fermées »

## **Statuts de constatation ouverte**

Une fois qu’une constatation est **Actif**, elle est étiquetée comme constatation **Ouverte**, qu’elle ait été **Vérifié** ou non.

Les constatations ouvertes sont visibles depuis la vue **Findings \> Open Findings** de DefectDojo.

### **Constatations actives**

« Cette constatation a été découverte par un outil d’analyse. »

Par défaut, toute nouvelle constatation créée dans DefectDojo est étiquetée comme **Actif**. Dans ce cas, Actif signifie « il s’agit d’une nouvelle constatation que DefectDojo n’a pas enregistrée lors d’un import précédent ». Si une constatation a été Atténué par le passé, mais réapparaît dans une analyse ultérieure, le statut de cette constatation sera rouvert pour refléter le retour de la vulnérabilité.

### **Constatations vérifiées**

« Notre équipe a confirmé l’existence de cette constatation. »

Le simple fait qu’un outil enregistre un problème ne signifie pas nécessairement que la constatation nécessite l’attention des ingénieurs. C’est pourquoi les nouvelles constatations sont également étiquetées comme **Unverified** par défaut.

Si vous êtes en mesure de confirmer que la constatation existe bel et bien, vous pouvez la marquer comme **Vérifié**.

Certaines fonctions de DefectDojo exigent que les constatations soient Actif et Vérifié. Si vous n’avez pas besoin de vérifier manuellement chaque constatation, vous pouvez désactiver l’exigence de vérification pour tout ou partie de ces fonctions depuis la page **System Settings** (**Classic UI: Configuration > System Settings**, **Pro UI: Settings > System > System Settings**).

![image](images/verified_status_toggle.png)

Ces statuts Vérifié sont requis pour

* Pousser des tickets Jira
* Appliquer une notation aux produits
* Calculer les métriques

## **Statuts de constatation fermée**

« La vulnérabilité enregistrée ici n’est plus active. »

Une fois le travail sur une constatation terminé, vous pouvez la fermer manuellement via l’option Close Findings. Autrement, si une analyse est réimportée dans DefectDojo sans contenir une constatation précédemment enregistrée, cette dernière se fermera automatiquement.

## **Inactif**

« Cette constatation a été découverte précédemment, mais elle a soit été atténuée, soit ne nécessite pas d’attention immédiate. »

Si une constatation est marquée comme Inactif, cela signifie que le problème n’a actuellement aucun impact sur l’environnement logiciel et ne nécessite pas d’être traité. Ce statut ne signifie pas nécessairement que le problème a été résolu, car les acceptations du risque actives étiquettent également les constatations comme Inactif.

### **En cours de révision**

« J’ai envoyé cette constatation à un ou plusieurs membres de l’équipe pour examen. »

Lorsqu’une constatation est En cours de révision, elle doit être examinée par un membre de l’équipe. Vous pouvez mettre une constatation en révision en sélectionnant **Request Peer Review** dans le menu déroulant de la constatation.

![image](images/Finding_Status_Definitions.png)

### **Risque accepté**

« Notre équipe a évalué le risque associé à cette constatation, et nous avons convenu que nous pouvions retarder sa correction en toute sécurité. »

Les constatations ne peuvent pas toujours être corrigées ou traitées, pour diverses raisons. Vous pouvez ajouter une acceptation du risque à une constatation via l’option Add Risk Acceptance. Les acceptations du risque vous permettent de téléverser des fichiers et de saisir des notes pour étayer une décision d’acceptation du risque.

Les acceptations du risque ont des dates d’expiration, à l’échéance desquelles vous pouvez réévaluer l’impact de la constatation et décider de la suite à donner.

Pour plus d’informations sur les acceptations du risque, consultez notre [Guide](/triage_findings/findings_workflows/os__risk_acceptance/).

### **Hors périmètre**

« Cette constatation a été découverte par notre outil d’analyse, mais la détection de ce type de vulnérabilité n’était pas l’objectif direct de notre test. »

Lorsque vous marquez une constatation comme Hors périmètre, vous indiquez qu’elle n’est pas directement pertinente pour l’engagement ou le test dans lequel elle se trouve.

Si vous menez un effort de test et de correction portant sur un aspect spécifique de votre logiciel, vous pouvez utiliser ce statut pour indiquer que cette constatation n’en fait pas partie.

### **Faux positif**

« Cette constatation a été découverte par notre outil d’analyse, mais après examen, nous avons découvert que la vulnérabilité signalée n’existe pas. »

Après avoir examiné une constatation, vous pourriez découvrir que la vulnérabilité signalée n’existe pas réellement. Le statut Faux positif est conservé lors des réimports et empêche l’ouverture ou la fermeture des constatations correspondantes, ce qui contribue à réduire le bruit.

Si un autre outil d’analyse détecte une constatation similaire, elle ne sera pas enregistrée comme Faux positif. DefectDojo ne peut comparer les constatations qu’au sein d’un même outil pour déterminer si une constatation a déjà été enregistrée.

## Sévérité et risque
La sévérité reflète l’impact technique d’un problème s’il est exploité. Le risque reflète l’urgence pour l’entreprise et la réponse requise, en tenant compte du contexte tel que l’exposition, l’exploitabilité, les contrôles compensatoires et l’impact opérationnel.


## Définitions des niveaux de risque
### Urgent
Une constatation qui représente un risque commercial immédiat et inacceptable.

Forte probabilité d’exploitation ou exploitation active observée
Exposition directe de systèmes critiques, de données sensibles ou d’environnements clients
Contrôles compensatoires limités ou inexistants
L’absence d’action pourrait entraîner une perturbation commerciale sévère, un impact réglementaire ou une atteinte à la réputation

Action attendue : réponse immédiate Délai SLA typique : correction d’urgence


### Action requise
Une constatation qui présente un risque clair et actionnable nécessitant une correction ou une atténuation rapide.

Un chemin d’attaque réaliste existe
L’actif concerné est exposé, critique pour l’entreprise ou orienté client
Les contrôles compensatoires sont faibles, absents ou non vérifiés
L’exploitation entraînerait un impact commercial, sécuritaire ou de conformité mesurable

Action attendue : correction ou atténuation active requise Délai SLA typique : fenêtre de correction à court terme


### Risque moyen
Une constatation qui présente un niveau modéré de risque commercial et qui devrait être corrigée dans un délai planifié.

Un impact significatif pourrait survenir en cas d’exploitation
Une certaine exposition existe, mais l’exploitation nécessite des conditions ou des privilèges spécifiques
Peut affecter indirectement les systèmes de production ou les données clients
Correspond souvent à des problèmes de sévérité moyenne ou élevée sans exploitabilité immédiate

Action attendue : correction priorisée Délai SLA typique : fenêtre de correction planifiée


### Risque faible
Une constatation qui présente un impact commercial minimal et ne nécessite pas d’action immédiate.

Aucune exploitation connue en conditions réelles
Exposition limitée ou inexistante (par exemple, systèmes internes, hors production, contrôles compensatoires solides)
La correction peut être traitée dans le cadre des cycles normaux de développement ou de maintenance
Il s’agit souvent de constatations informatives ou de faible sévérité, mais qui peuvent inclure des problèmes de sévérité plus élevée bien atténués

Action attendue : suivi et traitement opportuniste Délai SLA typique : au mieux / backlog
