---
title: Importer depuis l'API
description: ''
aliases:
- /fr/en/connecting_your_tools/import_scan_files/api_pipeline_modelling
---

L'API de DefectDojo permet de mettre en place des solutions de pipeline robustes, qui ingèrent automatiquement de nouveaux scans dans votre instance. Ce type d'automatisation peut prendre plusieurs formes :

* Un import quotidien qui scanne votre environnement chaque jour, puis importe les résultats du scan dans DefectDojo (similaire à notre fonctionnalité **Connectors**)
* Un pipeline CI/CD qui scanne le nouveau code au fur et à mesure de son déploiement, et importe les résultats dans DefectDojo en tant qu'action déclenchée

Ces pipelines peuvent être créés en appelant directement le point de terminaison **/reimport** de notre API avec un fichier de scan joint, d'une manière qui ressemble beaucoup à notre **formulaire d'importation de scan**. 

## L'API de DefectDojo

L'API de DefectDojo est documentée directement dans l'application à l'aide du framework OpenAPI. Vous pouvez accéder à cette documentation depuis le Menu utilisateur, dans le coin supérieur droit, sous **« API v2 OpenAPI3 »**.

\- Cette documentation permet de tester des appels API avec différents paramètres, en utilisant le jeton API de votre propre utilisateur.

Si vous avez besoin d'accéder à un jeton API pour un script ou une autre intégration, vous trouverez cette information sous l'option **API v2 Token** du même menu.

![image](images/api_pipeline_modelling.png)

### Considérations générales sur l'API

* Bien que notre documentation OpenAPI détaille les paramètres utilisables avec chaque point de terminaison, elle suppose que le lecteur maîtrise déjà bien les concepts clés de DefectDojo (hiérarchie de produits, Constatations, déduplication, etc.).
* Les utilisateurs qui souhaitent une intégration d'import fonctionnelle mais qui connaissent moins bien DefectDojo dans son ensemble devraient envisager notre **Universal Importer**.
* L'API de DefectDojo peut parfois créer des objets de données non désirés, en particulier si l'option « Auto-Create Context » est utilisée sur le point de terminaison **/import** ou **/reimport**.
* Heureusement, il est très difficile de supprimer accidentellement des données via l'API. La plupart des objets ne peuvent être supprimés qu'au moyen d'un appel **DELETE** dédié au point de terminaison concerné.

### Remarques spécifiques sur les points de terminaison /import et /reimport

Le point de terminaison **/reimport** peut être utilisé aussi bien pour un import initial que pour un « Reimport » qui étend un Test avec des Constatations supplémentaires. Vous n'avez pas besoin de créer d'abord un Test avec **/import** avant de pouvoir utiliser le point de terminaison **/reimport**. Tant que l'option « Auto Create Context » est activée, le point de terminaison /reimport peut créer un nouveau Test, Engagement, Produit ou Type de produit. Dans presque tous les cas, vous pouvez utiliser exclusivement le point de terminaison **/reimport** pour ajouter des données via l'API.

Cependant, le point de terminaison **/import** peut être utilisé à la place pour un pipeline où vous souhaitez toujours stocker chaque résultat de scan dans un objet Test distinct, plutôt que d'utiliser **/reimport** pour gérer le différentiel au sein d'un seul objet Test. Les deux options sont acceptables, et le point de terminaison à choisir dépend de votre structure de reporting, ou du besoin d'inspecter une exécution isolée d'un pipeline.

### Utilisation du champ Date de fin de scan (API : `scan_date`)

DefectDojo prend en charge une multitude de rapports de scanners, mais ces rapports ne contiennent pas tous l'information la plus importante pour un utilisateur. Le champ `scan_date` est une fonctionnalité intelligente et flexible qui permet aux utilisateurs de définir la date de fin d'un rapport de scan donné, et de la propager à toutes les constatations importées.

Ce champ n'est **pas** obligatoire, mais sa valeur par défaut est la date d'importation (au moment où la requête est traitée et qu'une réponse de succès est renvoyée).

Voici les cas d'usage possibles pour ce champ, et les résultats appliqués au Test :

1. Si le rapport **ne définit pas** la date, et que `scan_date` **n'est pas** défini à l'importation
    - La date de la Constatation sera la valeur par défaut de `scan_date`
2. Si le rapport **définit** la date, et que `scan_date` **n'est pas** défini à l'importation
    - La date de la Constatation sera celle définie par le rapport
3. Si le rapport **ne définit pas** la date, et que `scan_date` **est défini** à l'importation
    - La date de la Constatation sera celle définie par l'utilisateur pour `scan_date`
4. Si le rapport **définit** la date, et que `scan_date` **est défini** à l'importation
    - La date de la Constatation sera celle définie par l'utilisateur pour `scan_date`
