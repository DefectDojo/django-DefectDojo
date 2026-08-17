---
title: Questionnaires
description: Comprendre les Questionnaires dans OS DefectDojo
audience: opensource
weight: 2
---

Dans DefectDojo, un Questionnaire est un ensemble réutilisable de questions qui permet de recueillir des informations auprès des développeurs, des équipes et des parties prenantes internes et externes. Il peut être utilisé pour recueillir des retours avant le début des travaux, assurer l'alignement entre les personnes et les équipes au fur et à mesure de l'avancement, et permettre une analyse rétrospective une fois le travail terminé.

## Modèles de Questionnaire

Un modèle de Questionnaire définit la structure et le contenu du Questionnaire, notamment son nom, sa description et les Questions associées. La création d'un modèle de Questionnaire ne le rend pas automatiquement disponible pour recueillir des réponses. Pour recueillir des réponses, un modèle de Questionnaire doit être déployé soit comme **Questionnaire général**, soit comme **Questionnaire lié**.

### Questionnaires généraux et liés

Les Questionnaires généraux et les Questionnaires liés diffèrent à plusieurs égards, notamment leur mode de diffusion, les personnes pouvant y répondre et l'emplacement de stockage des réponses.

| Questionnaires généraux | Questionnaires liés |
|---|---|
| Nécessitent une publication | Ne nécessitent pas de publication |
| Nécessitent une date d'expiration | Restent actifs tant que l'Engagement est actif |
| Autorisent les réponses anonymes | N'autorisent pas les réponses anonymes |
| Peuvent être partagés en interne et en externe | Ne peuvent être partagés qu'en interne |
| Ne permettent pas de modifier les réponses | Permettent de modifier les réponses |
| Les réponses ne sont visibles qu'à l'expiration | Les réponses sont visibles immédiatement |
| Les réponses sont visibles dans « Tous les Questionnaires » | Les réponses sont visibles au sein de l'Engagement |
| Peuvent être convertis en Engagement | Sont déjà liés à un Engagement |

#### Cycle de vie du déploiement des Questionnaires

Les modèles de Questionnaire suivent des cycles de vie différents selon le type de déploiement :

**Questionnaires généraux**
Modèle → Publié → Réception des réponses → Expiration → Conversion facultative en Engagement

**Questionnaires liés**
Modèle → Lié à un Engagement → Réception des réponses → Reste actif tant que l'Engagement est actif

#### Séparation des réponses

Un même modèle de Questionnaire peut être déployé plusieurs fois simultanément, à la fois comme Questionnaire général et comme Questionnaire lié. Chaque déploiement crée son propre ensemble de réponses, indépendant des autres.

Si le même modèle de Questionnaire est déployé comme Questionnaire général et également lié à un Engagement, les réponses soumises via chaque déploiement sont stockées indépendamment et ne sont pas combinées. Cela permet de réutiliser le même modèle de Questionnaire dans différents contextes tout en séparant les ensembles de réponses.

## Accéder aux Questionnaires et aux Questions

Les Questionnaires et les Questions sont accessibles depuis la barre latérale en cliquant sur l'option **Questionnaires**. Le sous-menu donne accès à **All Questionnaires** et **All Questions**.

![image](images/q_ss1.png)

À noter que l'accès aux vues All Questionnaires et All Questions est réservé aux Utilisateurs ayant le statut de Superutilisateur. Seuls les Superutilisateurs peuvent créer des modèles de Questionnaire, créer des Questions et déployer des Questionnaires. Les Utilisateurs sans statut de Superutilisateur peuvent néanmoins répondre aux Questionnaires généraux qui leur sont partagés, ainsi qu'aux Questionnaires liés des Engagements auxquels ils ont accès, mais ils ne peuvent ni les créer ni les gérer.

### Questionnaires

La vue All Questionnaires comprend deux tableaux :
- **Questionnaires**
    - Cette section regroupe tous les modèles de Questionnaire existants.
- **General Questionnaires**
    - Cette section regroupe tous les Questionnaires généraux actuellement ouverts aux réponses.

Les deux sections peuvent être filtrées par nom, description ou statut actif.

### Questions

La vue All Questions comprend un tableau des Questions pouvant actuellement être ajoutées à un Questionnaire. Elle peut également être filtrée par le statut facultatif de chaque Question, son contenu ou son type (par exemple, question texte ou question à choix multiples).

## Gestion des modèles de Questionnaire

### Créer des Questionnaires

De nouveaux Questionnaires peuvent être créés à l'aide du bouton Create Questionnaire dans la vue All Questionnaires.

![image](images/q_ss2.png)

Après avoir renseigné un nom et une description, le Questionnaire peut être créé sans Questions (qui pourront être ajoutées ultérieurement) ou avec des Questions ajoutées immédiatement.

#### Ajouter immédiatement des Questions à un nouveau Questionnaire

Si des Questions sont ajoutées immédiatement, sélectionnez toutes les Questions concernées dans le menu déroulant qui apparaît. Vous pouvez également créer une nouvelle Question à ajouter au Questionnaire en cliquant sur le signe + à droite du menu déroulant.

![image](images/q_ss12.png)

Une fois toutes les Questions concernées sélectionnées, cliquez sur **Update Questionnaire Questions** pour les ajouter au Questionnaire.

#### Ajouter des Questions à un Questionnaire existant

Pour ajouter des Questions à un Questionnaire existant, cliquez sur le nom du Questionnaire dans le tableau Questionnaires, cliquez sur **Edit Questions**, sélectionnez les nouvelles Questions à ajouter au Questionnaire dans le menu déroulant, puis cliquez sur **Update Questionnaire Questions**.

### Créer des Questions

De nouvelles Questions peuvent être créées à l'aide du bouton **Create Question** dans la vue All Questions.

![image](images/q_ss3.png)

Il est également possible de créer des Questions au moment de choisir celles à ajouter à un Questionnaire, en cliquant sur le signe + à droite du menu déroulant.

#### Types de Question

Lors de la création d'une nouvelle Question, elle peut être formatée soit comme une question de type texte, soit comme une question à choix multiples, en sélectionnant **Text** ou **Choice** dans le menu déroulant.

#### Autoriser les réponses multiples et les réponses facultatives

Le nombre maximal de réponses autorisées dans une question à choix multiples est de six. Cocher la case **Multichoice** permet de sélectionner plusieurs réponses (disponible uniquement pour les questions à choix multiples). Les Questions peuvent également être marquées comme **Optional** en cochant la case correspondante.

Consultez la section [Modification des Questions](#editing-questions) pour savoir comment ajouter des réponses supplémentaires à une question à choix multiples.

#### Ordre des Questions

Déterminez l'ordre d'une Question en lui attribuant un numéro d'ordre. Par exemple, si une Question a la valeur 1 dans le champ Order, elle apparaîtra au-dessus d'une Question ayant la valeur 2 dans ce même champ.

![image](images/q_ss13.png)

### Modification des Questions

Une fois qu'une Question a été créée, elle peut être modifiée en accédant au sous-menu All Questions et en cliquant sur la Question à modifier. Les Questions ne peuvent pas être supprimées.

Il est important d'éviter de modifier des Questions faisant partie de Questionnaires actifs. Si un élément d'une Question est modifié (par exemple, l'ordre, le statut facultatif, la correction d'une faute de frappe, l'ajout d'une réponse possible, etc.) et que cette Question faisait partie d'un Questionnaire actif ayant déjà reçu des réponses, toutes les réponses précédemment soumises seront invalidées et devront être soumises à nouveau.

#### Modifier les Questions de type texte

Une fois créées, les seules modifications possibles pour les Questions de type texte concernent l'ordre, le statut facultatif et le libellé de la question.

#### Modifier les Questions à choix multiples

Bien que le nombre par défaut de réponses possibles pour une question à choix multiples soit de six, il peut être augmenté après la création du Questionnaire. Pour cela, cliquez sur la Question dans la vue All Questions, cliquez sur le signe **+** à droite du menu déroulant Choices, ajoutez la nouvelle réponse, puis cliquez sur **Submit**.

![image](images/q_ss16.png)

![image](images/q_ss17.png)

La nouvelle option créée ne sera pas automatiquement ajoutée au Questionnaire. Pour l'ajouter, cliquez sur le menu déroulant **Choices** et sélectionnez l'option nouvellement créée. Une coche apparaîtra à côté d'elle, indiquant qu'elle est désormais incluse comme réponse possible dans le Questionnaire.

![image](images/q_ss18.png)

## Déployer des Questionnaires

Une fois qu'un modèle de Questionnaire a été créé avec succès, il peut être déployé pour recevoir des réponses. Le processus de déploiement varie légèrement selon le type de Questionnaire.

### Déploiement d'un Questionnaire général

Pour déployer un Questionnaire général :
1. Accédez à la vue All Questionnaires.
2. Cliquez sur **+** à droite du tableau General Questionnaires.
3. Sélectionnez le Questionnaire à déployer.
4. Définissez la date d'expiration.
5. Cliquez sur **Add Questionnaire**.

#### Partager un Questionnaire général

Une fois déployé, un Questionnaire général peut être partagé en cliquant sur **Share Questionnaire** dans la colonne Actions du tableau General Questionnaires. Cela génère un lien que vous pouvez partager avec les destinataires prévus, tout en vous permettant de vérifier au préalable que le Questionnaire est formaté comme prévu.

![image](images/q_ss14.png)

Remarques :
- Les réponses à un Questionnaire général ne sont pas visibles tant que le Questionnaire n'a pas expiré.
- Il n'est pas possible de modifier la date d'expiration une fois le Questionnaire publié.
- L'heure par défaut à laquelle un Questionnaire expire est minuit (par exemple, un Questionnaire dont l'expiration est fixée au 31 décembre 2026 ne sera visible que jusqu'à 23h59:59 ce jour-là).
- Il n'est pas possible de définir une heure d'expiration personnalisée.

Consultez la section [Activer les réponses anonymes](#enabling-anonymous-responses) ci-dessous pour savoir comment autoriser les réponses d'Utilisateurs externes.

### Déploiement d'un Questionnaire lié

Pour déployer un Questionnaire lié :
1. Accédez à l'Engagement auquel le Questionnaire doit être lié.
2. Cliquez sur la flèche vers le bas du tableau **Additional Features**.
3. Cliquez sur **+** à droite du sous-tableau Questionnaires.
4. Sélectionnez le Questionnaire à lier dans le menu déroulant.
5. Cliquez sur **Add Questionnaire** ou **Add Questionnaire and Respond**.

Le Questionnaire lié sera alors actif pour tous les Utilisateurs ayant accès à l'Engagement.

#### Partager un Questionnaire lié

Pour partager directement le Questionnaire lié avec des Utilisateurs internes de DefectDojo, cliquez sur le menu kebab ⋮ et sélectionnez **Share Questionnaire** dans le menu déroulant. Un lien apparaît, qui peut être copié et transmis au destinataire prévu.

![image](images/q_ss10.png)

Comme indiqué précédemment, les Questionnaires liés ne peuvent être partagés qu'avec des Utilisateurs de DefectDojo.

## Répondre aux Questionnaires

Le processus de réponse varie légèrement selon que le Questionnaire est un Questionnaire général ou un Questionnaire lié.

### Répondre à un Questionnaire général

Pour répondre à un Questionnaire général, les Utilisateurs qui ne sont pas Superutilisateurs doivent recevoir le lien directement d'un Superutilisateur, comme décrit [ici](#sharing-a-general-questionnaire).

#### Activer les réponses anonymes

Par défaut, les Questionnaires généraux ne sont accessibles qu'aux Utilisateurs de DefectDojo. Pour permettre à des tiers externes de répondre aux Questionnaires DefectDojo, assurez-vous que l'option **Allow Anonymous Survey Responses** est activée dans les System Settings, accessibles dans la section **Configurations** de la barre latérale.

![image](images/q_ss4.png)

![image](images/q_ss5.png)

Les réponses externes apparaissent comme anonymes, car aucun identifiant d'utilisateur DefectDojo n'est associé à la réponse.

Si le périmètre d'un Questionnaire inclut à la fois des Utilisateurs internes et externes, créez un Questionnaire général et indiquez le nom de l'Engagement dans la description lors de la création, ce qui permettra de filtrer les résultats.

![image](images/q_ss8.png)

![image](images/q_ss9.png)

### Répondre aux Questionnaires liés

Pour répondre à un Questionnaire lié :
1. Accédez à la vue Engagement.
2. Développez le tableau Additional Features.
3. Développez le sous-tableau Questionnaires.
4. Cliquez sur le menu kebab ⋮ du Questionnaire lié.
5. Cliquez sur **Answer Questionnaire**.

![image](images/q_ss15.png)

Les Questionnaires liés n'autorisent pas les réponses externes/anonymes, car l'accès à DefectDojo est requis pour accéder à l'Engagement.

## Réponses

Comme indiqué précédemment, chaque déploiement d'un modèle de Questionnaire crée son propre conteneur de réponses. Lier le même modèle de Questionnaire à plusieurs Engagements produit des ensembles de réponses distincts, et la publication d'un Questionnaire général n'affecte pas les ensembles de réponses des Questionnaires liés.

### Réponses aux Questionnaires généraux

Une fois la date d'expiration d'un Questionnaire général dépassée :
- Il ne sera plus possible de soumettre de nouvelles réponses.
- Toutes les réponses précédentes seront enregistrées et deviendront consultables.
- Le Questionnaire apparaîtra comme un Unassigned Answered Engagement Questionnaire sur le tableau de bord DefectDojo.

Trois actions sont possibles une fois la fenêtre de réponse d'un Questionnaire fermée : **View Responses**, **Create Engagement** et **Assign User**.

#### Consulter les réponses au Questionnaire

Sélectionner **View Responses** affiche toutes les réponses du Questionnaire.

#### Créer un Engagement à partir d'un Questionnaire

Après expiration, un Questionnaire général peut être associé à un Actif via un Engagement en sélectionnant l'action **Create Engagement**. Sélectionnez un Actif dans le menu déroulant qui apparaît, puis cliquez sur **Create Engagement**. Un nouvel Engagement peut alors être créé et renseigné avec des détails spécifiques, comme pour tout autre Engagement dans DefectDojo, tels que Description, Version, Status, Tags, etc.

![image](images/q_ss6.png)

![image](images/q_ss7.png)

#### Assign User

L'action Assign User invite à sélectionner un Utilisateur dans le menu déroulant des Utilisateurs disponibles. Sélectionnez un Utilisateur dans le menu déroulant et cliquez sur **Assign Questionnaire**, ce qui en fera le propriétaire de ce Questionnaire.

### Réponses aux Questionnaires liés

Les Questionnaires liés restent disponibles tant que l'Engagement associé est actif. Les réponses sont donc consultables à tout moment.

Le menu kebab ⋮ d'un Questionnaire lié propose plusieurs fonctions pour gérer le Questionnaire et ses réponses :
- **Answer Questionnaire** : cette option apparaît si un Utilisateur n'a pas encore répondu au Questionnaire lié. Une fois la réponse soumise, View Responses et Edit Responses apparaissent.
- **View responses** : permet aux Utilisateurs de consulter toutes les réponses reçues à ce jour pour le Questionnaire.
- **Edit Responses** : permet à chaque Utilisateur de modifier ses réponses précédentes.
- **Assign User** : attribue le questionnaire à un Utilisateur.
- **Link to a Different Engagement** : ouvre un menu déroulant listant d'autres Engagements auxquels associer le Questionnaire.
- **Share Questionnaire** : génère un lien pour partager le Questionnaire avec des Utilisateurs internes.
- **Delete Questionnaire** : dissocie le Questionnaire de l'Engagement et supprime toutes les réponses précédemment recueillies.

## Supprimer des Questionnaires

La suppression des Questionnaires généraux et liés a des effets différents en aval, selon le résultat visé par la suppression.

### Supprimer des Questionnaires généraux

Supprimer un Questionnaire général depuis le tableau General Questionnaires dans la section All Questionnaires supprime toutes les réponses collectées lors de ce déploiement avant la suppression. Les Questionnaires liés utilisant le même modèle de Questionnaire ne seront pas supprimés.

### Supprimer des Questionnaires liés

Supprimer un Questionnaire lié dissocie le Questionnaire de l'Engagement. Toutes les réponses collectées au sein de l'Engagement avant la suppression seront perdues. Les Questionnaires généraux déployés précédemment à partir du même modèle de Questionnaire ne seront pas affectés.

### Supprimer des modèles de Questionnaire

Pour supprimer complètement un modèle de Questionnaire, sélectionnez-le dans le tableau Questionnaires de la vue All Questionnaires, puis cliquez sur **Delete Questionnaire**. Cette action supprime définitivement le modèle de Questionnaire ainsi que toutes les réponses associées à tous ses déploiements. Cette action est irréversible.
