---
title: Sondages
description: Comprendre les sondages dans DefectDojo Pro
audience: pro
weight: 2
---

Dans DefectDojo, un modèle de sondage est un ensemble réutilisable de questions qui sert à recueillir des informations auprès des développeurs, des équipes et des parties prenantes internes comme externes. Ils peuvent être utilisés pour recueillir des avis avant le début des travaux, garantir l'alignement entre les individus et les équipes à mesure que le travail progresse, et permettre une analyse rétrospective une fois le travail terminé.

Dans DefectDojo, un système de sondage se compose de trois éléments :
- les **modèles de sondage**, qui regroupent et ordonnent les questions.
- les **déploiements de sondage**, qui sont des instances actives collectant des réponses.
- les **réponses**, qui sont les réponses soumises par les utilisateurs.

Créer un modèle de sondage ne le rend pas automatiquement disponible pour recevoir des réponses. Pour collecter des réponses, un modèle de sondage doit être déployé.

## Autorisations

La section Sondages dans la barre latérale n'est visible que pour les utilisateurs ayant le statut de Superutilisateur, et seuls les Superutilisateurs peuvent créer des modèles de sondage, créer des questions et déployer des sondages.

Les utilisateurs sans statut de Superutilisateur peuvent tout de même répondre aux sondages qui sont partagés avec eux, mais ils ne peuvent ni les créer ni les gérer, ni gérer leurs questions associées.

## Accéder aux sondages et aux questions

Les utilisateurs ayant le statut de Superutilisateur peuvent accéder aux sondages et aux questions depuis la barre latérale en cliquant sur l'option **Surveys**. Le sous-menu donne accès à **All Surveys** et **All Questions**, ainsi qu'à l'option permettant de créer de nouveaux sondages et de nouvelles questions.

![image](images/pq_ss1.png)

### Accéder aux sondages

La vue All Surveys comprend un tableau contenant tous les modèles de sondage, avec leur ID, leur nom, leur description et leur statut actif. Le tableau peut être filtré à l'aide de mots-clés, et il peut être réorganisé en cliquant sur l'en-tête de chaque colonne.

### Accéder aux questions

La vue All Questions comprend un tableau des questions pouvant être ajoutées à un sondage. Le tableau peut être filtré à l'aide de mots-clés, et il peut être réorganisé en cliquant sur l'en-tête de chaque colonne.

## Gérer les modèles de sondage

### Créer des modèles de sondage

Les modèles de sondage peuvent être créés soit en cliquant sur **New Survey** dans la barre latérale, soit en cliquant sur le bouton **New Survey** en haut de la vue All Surveys.

![image](images/pq_ss2.png)

Le modèle de sondage doit se voir attribuer un nom et une description, et comporter au moins une question choisie dans le menu déroulant, avant de pouvoir être créé.

#### Ajouter des questions à un modèle de sondage existant

Pour ajouter des questions à un modèle de sondage existant, cliquez sur l'icône kebab ⋮ à gauche du sondage souhaité, cliquez sur **Edit Survey**, sélectionnez les nouvelles questions à ajouter au sondage dans le menu déroulant, puis cliquez sur **Submit**.

En bonne pratique, il est fortement recommandé d'éviter de modifier ou d'ajouter des questions à un modèle de sondage pendant qu'il a des déploiements actifs. L'ajout de nouvelles questions n'affectera pas les réponses existantes, mais ces réponses auront été soumises sans répondre aux questions nouvellement ajoutées, ce qui peut entraîner des données incomplètes.

### Créer des questions

Comme pour les modèles de sondage, les questions peuvent être créées soit en cliquant sur **New Question** dans la barre latérale, soit en cliquant sur le bouton **New Question** en haut de la vue All Questions.

#### Types de questions

Lors de la création d'une nouvelle question, elle peut être formatée soit comme une question textuelle, soit comme une question à choix multiples, en sélectionnant **Text Question** ou **Choice Question** en haut de la vue New Question.

![image](images/pq_ss3.png)

#### Ordre des questions

Déterminez l'ordre d'une question en lui attribuant un numéro d'ordre. Par exemple, si une question a la valeur 1 dans le champ Order, cette question apparaîtra au-dessus d'une question ayant la valeur 2 dans le champ Order.

#### Réponses optionnelles

Les questions textuelles comme les questions à choix multiples peuvent être marquées comme **Optional** en cochant la case correspondante.

#### Autoriser plusieurs réponses

Un nombre illimité de réponses potentielles peut être ajouté à une question à choix multiples. Cocher la case **Allow Multiple Selections** permet de sélectionner plusieurs réponses (disponible uniquement pour les questions à choix multiples).

### Modifier des questions

Pour modifier une question, accédez à la vue All Questions, cliquez sur l'icône kebab ⋮ à gauche de la question à modifier, cliquez sur Edit Question, effectuez la modification souhaitée, puis validez-la en cliquant sur Submit. Les questions ne peuvent pas être supprimées.

![image](images/pq_ss4.png)

Il est important d'éviter de modifier des questions faisant partie de sondages actifs, ou d'ajouter des questions à des sondages actifs. Cela n'affectera pas les réponses déjà collectées, mais peut entraîner des données incomplètes ou peu fiables.

## Déployer des sondages

Une fois qu'un modèle de sondage a été créé avec succès, le déploiement d'un sondage crée une instance active qui accepte les réponses.

Pour déployer un sondage, accédez à la vue All Surveys, cliquez sur l'icône kebab ⋮ à gauche du sondage à déployer, cliquez sur **Open Survey**, définissez la date d'expiration, puis cliquez sur Submit.

Si vous souhaitez déployer à nouveau le même sondage, suivez la même procédure. Tous les déploiements apparaîtront dans le tableau Open Survey Instances, dans la vue du sondage, et peuvent être distingués par leur ID, leur heure de création et leur date d'expiration.

![image](images/pq_ss10.png)

Un sondage se clôturera à la date choisie, à la même heure que celle de son déploiement. Par exemple, si vous déployez un sondage à 8h00 le 1er février 2026, et programmez sa clôture au 1er mars 2026, le sondage se clôturera à 8h00 le matin du 1er mars 2026.

Une fois qu'un sondage a été ouvert, sa date et son heure d'expiration ne peuvent plus être modifiées. Si un délai différent est nécessaire, un nouveau déploiement doit être créé.

Une fois qu'une date d'expiration est passée, il ne sera plus possible de soumettre des réponses à ce déploiement du sondage, mais le déploiement continuera d'apparaître dans le tableau Open Survey Instances de la vue de ce sondage.

#### Partager un sondage

Une fois qu'un sondage a été déployé, il peut être partagé avec d'autres utilisateurs en cliquant sur l'icône ↗ à gauche du sondage dans le tableau Open Survey Instances, dans la vue du modèle de sondage. Cela révèle un lien propre à ce déploiement, qui peut être copié et partagé avec les destinataires visés.

![image](images/pq_ss5.png)

![image](images/pq_ss9.png)

#### Clôturer un sondage

Pour clôturer un sondage, cliquez sur le **X** rouge à gauche du sondage dans le tableau Open Survey Instances, dans la vue du modèle de sondage.

![image](images/pq_ss13.png)

Comme indiqué dans la section Responses plus bas, cela empêchera uniquement la soumission de nouvelles réponses. Les réponses soumises précédemment resteront visibles dans le tableau des réponses en bas de la vue du modèle de sondage.

## Répondre aux sondages

Pour répondre à un sondage, les utilisateurs non-Superutilisateurs doivent avoir reçu le lien directement, en suivant les instructions de la section [Sharing a Survey](#sharing-a-survey) ci-dessus. Les Superutilisateurs peuvent également répondre en utilisant le même lien.

#### Activer les réponses anonymes

Par défaut, les sondages ne sont accessibles qu'aux utilisateurs DefectDojo. Pour permettre à des parties externes de répondre aux sondages DefectDojo, assurez-vous que l'option **Enable Anonymous Survey Responses** a été activée dans les **System Settings**, accessibles via **Settings > System** dans la barre latérale (dans le sous-menu **Pro Settings** sur les instances utilisant encore l'ancienne disposition de menu).

![image](images/pq_ss6.png)

Les réponses externes apparaîtront comme anonymes, car aucun ID d'utilisateur DefectDojo n'est associé à la réponse.

Si le périmètre d'un sondage inclut à la fois des utilisateurs internes et externes, indiquez le nom de l'Engagement dans la description lors de la création, ce qui permettra de filtrer les résultats.

![image](images/pq_ss7.png)

![image](images/pq_ss8.png)

## Gérer les réponses

Un même modèle de sondage peut être déployé plusieurs fois simultanément. Toutes les réponses aux multiples déploiements d'un même modèle de sondage seront affichées ensemble dans le tableau des réponses en bas de la vue de ce sondage.

![image](images/pq_ss11.png)

Même après l'expiration ou la clôture d'un déploiement de sondage, ses réponses restent visibles dans le tableau des réponses en bas de la vue du sondage, à condition que le modèle de sondage lui-même n'ait pas été supprimé. Ces réponses sont permanentes et ne peuvent pas être supprimées.

Comme le montre l'image ci-dessous, aucun déploiement de sondage n'est actuellement ouvert, mais les réponses des déploiements précédents sont toujours présentes dans le tableau des réponses.

![image](images/pq_ss12.png)

### Supprimer des modèles de sondage

Pour supprimer un modèle de sondage, accédez à la vue All Surveys, cliquez sur l'icône kebab ⋮ à gauche du sondage choisi, puis cliquez sur **Delete Survey**. Cela supprime définitivement le modèle de sondage ainsi que tous les déploiements et réponses associés. Cette action est irréversible.
