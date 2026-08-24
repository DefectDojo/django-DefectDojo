---
title: "Wiz"
description: "Comment configurer le Connecteur Upstream Wiz pour DefectDojo"
weight: 142
audience: pro
---
L'utilisation du connecteur Wiz nécessite la création d'un compte de service : consultez la [documentation Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) pour plus d'informations.  Vous aurez besoin d'un compte Wiz pour accéder à la documentation.

Le compte de service doit répondre à toutes les exigences suivantes. Un compte de service qui n'en respecte pas une peut tout de même s'authentifier avec succès mais n'importera rien :

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: au minimum `read:projects`, `read:issues`, et `read:vulnerabilities`.
* **Project visibility**: le compte de service doit être limité à chaque Wiz Project que vous souhaitez importer (ou à tous les Projects). Le connecteur découvre d'abord vos Wiz Projects, puis récupère les constatations de chaque Project — un compte qui peut lire les issues mais n'a de visibilité sur aucun Project ne découvre aucun Project, il n'y a donc rien à importer et aucune erreur n'est signalée par l'un ou l'autre des systèmes.

#### **Mappages du connecteur**

1. Saisissez votre Wiz Client ID dans le champ Client ID.
2. Saisissez le Wiz Client Secret dans le champ Secret.
