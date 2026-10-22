---
title: Joindre des fichiers
description: Téléversez des captures d'écran, des rapports ou d'autres fichiers justificatifs
  vers une Constatation, un Engagement ou un Test dans DefectDojo OS
audience: opensource
weight: 3
aliases:
- /fr/triage_findings/findings_workflows/add_files/
---

Vous pouvez joindre des fichiers à une **Constatation**, un **Engagement**, ou un **Test** pour fournir
un contexte supplémentaire — par exemple une capture d'écran de preuve de concept, un rapport brut de scanner, un
schéma réseau, ou une feuille de calcul étayant un résultat.

Chaque objet conserve son propre ensemble de fichiers, et vous pouvez joindre **jusqu'à 10 fichiers** à un même
objet.

## Types de fichiers pris en charge

Par défaut, les extensions suivantes sont acceptées :

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Les administrateurs peuvent modifier cette liste via la variable d'environnement `DD_FILE_UPLOAD_TYPES`.
Le téléversement d'un fichier dont l'extension ne figure pas dans la liste est rejeté par le formulaire.

Les fichiers image (comme `.png` et `.jpeg`) sont affichés sous forme de miniature, tandis que les autres
types de fichiers sont représentés par une icône générique. Dans les deux cas, cliquer sur le fichier le
télécharge.

## Comment joindre un fichier à une Constatation

1. Ouvrez la Constatation à laquelle vous souhaitez joindre un fichier.
2. Ouvrez le menu d'actions (le bouton **☰** en haut à droite de la Constatation) et cliquez sur
   **Gérer les fichiers**.

   ![Gérer les fichiers dans le menu d'actions de la Constatation](images/OS_manage_files_menu.png)

3. Sur la page **Ajouter des fichiers**, saisissez un **Titre** pour le fichier et choisissez le fichier
   depuis votre ordinateur. Vous pouvez ajouter jusqu'à trois fichiers à la fois ; enregistrez puis revenez
   pour en ajouter d'autres si nécessaire.

   ![Le formulaire de téléversement Gérer les fichiers](images/OS_manage_files_form.png)

4. Cliquez sur **Enregistrer**.

Le fichier est ensuite listé dans le panneau **Fichiers** de la Constatation. Les fichiers image apparaissent
comme une miniature :

![Panneau Fichiers d'une Constatation affichant une capture d'écran jointe](images/OS_finding_files_panel.png)

## Joindre des fichiers aux Engagements et aux Tests

Les Engagements et les Tests utilisent le même processus **Gérer les fichiers** :

- Sur la page de détail d'un **Engagement** ou d'un **Test**, ouvrez le panneau **Fichiers** et cliquez sur
  son bouton de modification (crayon), puis ajoutez des fichiers exactement comme pour une Constatation.

Comme pour les Constatations, les pièces jointes image s'affichent sous forme de miniature et les autres
types de fichiers sont représentés par une icône générique.

## Afficher et télécharger les fichiers

Les fichiers joints apparaissent dans le panneau **Fichiers** de la page de détail de l'objet. Cliquez sur un
fichier pour le télécharger. L'accès est soumis à un contrôle de permission : un utilisateur doit disposer de
la permission **view** sur la Constatation, l'Engagement ou le Test parent pour télécharger ses fichiers.

## Supprimer des fichiers

Pour supprimer un fichier, ouvrez **Gérer les fichiers** pour l'objet concerné, cochez la case **Supprimer**
sous le fichier à retirer, puis cliquez sur **Enregistrer**.
