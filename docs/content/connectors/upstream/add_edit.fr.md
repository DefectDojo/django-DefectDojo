---
title: Ajouter ou modifier un Connecteur en amont
description: Se connecter à un outil de sécurité pris en charge
aliases:
- /fr/import_data/pro/connectors/add_edit_connectors/
- /fr/en/connecting_your_tools/connectors/add_edit_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les Connecteurs en amont sont une fonctionnalité réservée à DefectDojo Pro.</span>

Le processus d'ajout et de configuration d'un Connecteur en amont est similaire, quel que soit l'outil que vous essayez de connecter. Cependant, certains outils peuvent nécessiter la création de clés API ou des étapes supplémentaires.

Avant de commencer ce processus, nous vous recommandons de consulter notre [Référence spécifique à chaque outil](../../toolreference/upstream/) pour trouver les ressources API de l'outil que vous essayez de connecter.

1. Si ce n'est pas déjà fait, commencez par **passer à la Pro UI** dans DefectDojo.
2. Dans le menu de gauche, ouvrez le groupe **Connecteurs** imbriqué sous l'en-tête **Import**, puis cliquez sur **Connecteurs en amont**.
​
![image](images/add_edit_connectors.png)

3. Choisissez un nouveau connecteur à ajouter à DefectDojo dans **Connecteurs disponibles**, puis cliquez sur le bouton **Add Configuration** de la tuile de l'outil. Vous pouvez utiliser la zone **Search Connectors** pour filtrer chaque section par nom d'outil, ou le bascule **All / Asset / Finding** dans l'en-tête de la page pour filtrer par type de connecteur.  
​  
Vous pouvez également modifier un connecteur existant sous l'en-tête **Connecteurs configurés**. Cliquez sur **Manage Configuration \> Edit Configuration** pour le connecteur configuré que vous souhaitez modifier.  
​
![image](images/add_edit_connectors_2.png)

4. Vous aurez besoin d'une **Location URL** accessible pour l'outil, ainsi que d'une clé API **Secret**. L'emplacement de la clé API dépendra de l'outil que vous essayez de configurer.  Consultez notre [Référence spécifique à chaque outil](../../toolreference/upstream/) pour plus de détails.  
​

5. Définissez un **Label** pour cette connexion afin de pouvoir l'identifier facilement dans DefectDojo.  
​

6. Planifiez la découverte et la synchronisation automatiques du connecteur à l'aide des plannings **Discovery Configuration** et **Synchronization Configuration**. Ceux-ci peuvent être modifiés ultérieurement.  
​

7. Choisissez si vous souhaitez **Enable Auto\-Mapping**. Activer Auto\-Mapping créera un nouveau Produit dans DefectDojo pour stocker les données de ce connecteur. Auto\-Mapping peut être activé ou désactivé à tout moment.  
​

8. Cliquez sur **Submit.**

![image](images/add_edit_connectors_3.png)

## Prochaines étapes

* Maintenant que vous avez ajouté un connecteur, vous pouvez vérifier que tout est correctement configuré en exécutant une opération [Discover](../manage_operations/#discover-operations).
