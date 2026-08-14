---
title: Joindre des fichiers
description: Téléversez des captures d'écran, des rapports ou d'autres fichiers justificatifs
  sur une Constatation, un Engagement ou un Test dans DefectDojo Pro
audience: pro
weight: 3
---

Vous pouvez joindre des fichiers à une **Constatation**, un **Engagement** ou un **Test** afin de fournir un
contexte complémentaire — par exemple une capture d'écran de preuve de concept, un rapport brut de scanner, un
schéma réseau ou une feuille de calcul appuyant un résultat.

Chaque objet conserve son propre jeu de fichiers, et vous pouvez joindre **jusqu'à 10 fichiers** à un même
objet.

## Types de fichiers pris en charge

Par défaut, les extensions suivantes sont acceptées :

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Les administrateurs peuvent modifier cette liste à l'aide de la variable d'environnement `DD_FILE_UPLOAD_TYPES`.
Le téléversement d'un fichier dont l'extension ne figure pas dans la liste est rejeté.

## Comment joindre un fichier à une Constatation

1. Ouvrez la Constatation à laquelle vous souhaitez joindre un fichier.
2. Cliquez sur le **menu en forme d'engrenage (⚙)** en haut à droite de la Constatation, puis choisissez **Add File**.
3. Saisissez un **Title** pour le fichier, sélectionnez le fichier sur votre ordinateur, puis enregistrez.

   ![L'action Add File dans le menu en forme d'engrenage de la Constatation, avec l'onglet Files en dessous](images/PRO_attach_files_menu.png)

Le même menu en forme d'engrenage est disponible sur les pages **Engagement** et **Test**, ce qui permet de
joindre des fichiers à ces objets de la même manière.

## Consulter et télécharger les fichiers

Les fichiers joints sont répertoriés dans l'onglet **Files** de la **Finding Overview** (ainsi que dans la
section équivalente sur les Engagements et les Tests). Cliquez sur le titre d'un fichier pour le télécharger.

![L'onglet Files d'une Constatation répertoriant un fichier joint](images/PRO_finding_files_tab.png)

L'accès fait l'objet d'un contrôle des permissions : un utilisateur doit disposer de la permission **view** sur
la Constatation, l'Engagement ou le Test parent pour pouvoir télécharger ses fichiers.

## Supprimer des fichiers

Pour supprimer un fichier, ouvrez le menu de sa ligne (l'icône **⋮**) dans l'onglet **Files** et choisissez
**Delete File**. Ce même menu propose également **Edit File Name** pour renommer une pièce jointe.
