---
title: "Wiz"
description: "Comment configurer le Connecteur Upstream Wiz pour DefectDojo"
weight: 142
audience: pro
---
Le connecteur Wiz importe les **issues et les constatations de vulnérabilités**. DefectDojo crée un Record pour chaque **Wiz Project**, ainsi qu'un Record au niveau du tenant nommé d'après le tenant lui-même, par exemple **Wiz Tenant abc12**, qui couvre l'ensemble du tenant Wiz.

**Vous n'avez pas besoin de Wiz Projects pour utiliser ce connecteur.** Si votre tenant n'a aucun Project, mappez le Record ce Record de tenant et DefectDojo importe toutes les issues et constatations de vulnérabilités que votre compte de service peut voir. Ce Record récupère aussi les constatations sur des ressources qu'aucun Project ne couvre. Mappez-le donc en plus de vos Records de Project si vos Projects ne couvrent pas tout. Si vous mappez à la fois un Record de Project et le Record ce Record de tenant, les constatations de ce Project sont importées dans deux Assets. Ne le faites que si vous souhaitez les deux vues.

L'utilisation du connecteur Wiz nécessite la création d'un compte de service : consultez la [documentation Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) pour plus d'informations.  Vous aurez besoin d'un compte Wiz pour accéder à la documentation.

Le compte de service doit répondre à toutes les exigences suivantes. Un compte de service qui n'en respecte pas une peut tout de même s'authentifier avec succès mais n'importera rien :

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: au minimum `read:projects`, `read:issues`, et `read:vulnerabilities`. `read:projects` reste nécessaire même sur un tenant sans Project, car Discover demande toujours la liste des Projects à Wiz.
* **Project visibility**: le compte de service doit être limité à chaque Wiz Project que vous souhaitez importer (ou à tous les Projects). Un compte qui peut lire les issues mais n'a de visibilité sur aucun Project ne découvre aucun Record de Project, et seul le Record ce Record de tenant reste disponible.

#### **Mappages du connecteur**

1. Saisissez votre Wiz Client ID dans le champ Client ID.
2. Saisissez le Wiz Client Secret dans le champ Secret.
