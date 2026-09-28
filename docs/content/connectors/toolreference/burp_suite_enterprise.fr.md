---
title: "BurpSuite"
description: "Comment configurer le Connecteur Upstream BurpSuite pour DefectDojo"
weight: 30
audience: pro
---
Le connecteur Burp de DefectDojo appelle l'API GraphQL de Burp pour récupérer les données. 

#### Prérequis

Avant de pouvoir configurer ce connecteur, vous aurez besoin d'une clé API provenant d'un Burp Service Account. Les comptes utilisateur Burp n'ont pas de clé API par défaut ; vous devrez donc peut-être créer un nouvel utilisateur spécifiquement à cette fin. 

Consultez la [documentation Burp](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) pour un guide sur la configuration d'un utilisateur Service Account avec une clé API.

#### Mappages du Connecteur

1. Saisissez l'URL racine de Burp dans le champ **Location** : il s'agit de l'URL à laquelle vous accédez à l'outil Burp.
2. Saisissez une clé API valide dans le champ Secret. Il s'agit de la clé API associée à votre compte Burp Service.

Consultez la [documentation officielle de Burp](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) pour plus d'informations sur l'API Burp.
