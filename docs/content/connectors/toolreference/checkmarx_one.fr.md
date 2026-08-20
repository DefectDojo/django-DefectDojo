---
title: "Checkmarx ONE"
description: "Comment configurer le Connecteur Upstream Checkmarx ONE pour DefectDojo"
weight: 33
audience: pro
---
Le connecteur Checkmarx ONE de DefectDojo appelle l'API Checkmarx pour récupérer les données.

#### **Mappages du Connecteur**

1. Saisissez votre **Tenant Name** dans le champ **Checkmarx Tenant**. Ce nom doit être visible sur la page de connexion de Checkmarx ONE, dans le coin supérieur droit :  
" Tenant : \<**votre nom de tenant**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Saisissez une clé API valide. Vous devrez peut-être en générer une nouvelle : consultez la [documentation de l'API Checkmarx](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) pour plus de détails.
3. Saisissez l'emplacement de votre tenant dans le champ **Location**. Cette URL est formatée comme suit :  
​`https://<your-region>.ast.checkmarx.net/` . Votre région se trouve au début de votre URL Checkmarx lorsque vous utilisez l'application Checkmarx. **<https://ast.checkmarx.net>** est le serveur US principal (qui n'a pas de préfixe de région).

#### **Gestion des branches**

Par défaut, chaque synchronisation importe les constatations du **seul scan terminé le plus récent d'un projet, quelle que soit la branche**. Si votre CI analyse de nombreuses branches, la branche qui a été analysée en dernier « remporte » cette synchronisation : les constatations qui n'existent que sur d'autres branches ne sont pas importées, et la réconciliation de fermeture des anciennes constatations lors de la synchronisation peut faire osciller des constatations entre ouvert et fermé à mesure que différentes branches deviennent tour à tour le scan le plus récent.

Deux champs facultatifs contrôlent ce comportement :

- **Branch** : épingle chaque projet à un nom de branche unique — seuls les scans de cette branche sont importés. Il s'agit d'une valeur globale unique pour l'ensemble du connecteur, ce qui convient aux parcs où chaque projet utilise la même branche pérenne (par ex. `main`).
    - Un **caractère générique `*`** est pris en charge. Une valeur Branch contenant `*` sélectionne *toutes* les branches correspondantes plutôt qu'une seule — par exemple `release/*` importe chaque branche de release, et `*` correspond à toutes les branches. Combiné avec **Track Scanned Branches**, c'est le moyen de suivre une famille de branches sans toutes les suivre.
    - Si un caractère générique ne correspond à **aucune** branche dans la fenêtre de scan, cette synchronisation est **ignorée** plutôt que traitée comme « la branche n'a aucune constatation » — ainsi, un motif qui ne correspond temporairement à rien ne peut pas fermer toutes les constatations de l'actif.
- **Track Scanned Branches** : lorsque cette option est activée, chaque synchronisation recherche toutes les branches ayant un scan terminé dans l'historique récent des scans du projet et importe **le dernier scan terminé de chaque branche**, avec une réimportation par branche. Les constatations de chaque branche vivent dans leur propre engagement sur l'actif mappé, nommé « \<engagement par défaut\> \- \<branche\> », si bien que la fermeture des constatations obsolètes est limitée à chaque branche : un correctif fusionné sur une branche ne peut jamais fermer les constatations d'une autre branche. La branche principale du projet (telle que rapportée par Checkmarx) est importée en premier, de sorte que les réapparitions d'une même constatation sur d'autres branches se dédupliquent par rapport à l'originale de la branche principale.

Remarques sur **Track Scanned Branches** :

- **Vérifiez quel comportement par défaut s'applique à vous.** Le suivi des branches est **activé par défaut pour les nouvelles installations**. Les installations antérieures à ce changement conservent leur comportement précédent ; l'option reste donc désactivée pour elles tant que quelqu'un ne l'active pas.
- Lorsque les deux champs sont renseignés, seule la **Branch** épinglée est suivie — y compris lorsque cette valeur Branch est un motif générique, auquel cas toutes les branches correspondant au motif sont suivies.
- Une branche qui cesse d'être analysée (fusionnée ou supprimée) cesse de recevoir des mises à jour : son engagement reste visible avec ses dernières constatations connues, que vous pouvez examiner et fermer en masse.
- Désactiver l'option ultérieurement est sans risque : les engagements par branche cessent simplement de recevoir des imports, et l'engagement par défaut reprend lors de la prochaine synchronisation.
- Les Connecteurs réconcilient l'état selon le calendrier de synchronisation. Le suivi des branches rend chaque synchronisation complète à travers les branches ; il ne rend pas les données en temps réel entre deux synchronisations.
