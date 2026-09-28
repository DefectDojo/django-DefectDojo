---
title: "BurpSuite"
description: "Cómo configurar el Conector Upstream de BurpSuite para DefectDojo"
weight: 30
audience: pro
---
El conector de Burp de DefectDojo llama a la GraphQL API de Burp para obtener datos. 

#### Prerrequisitos

Antes de configurar este conector, necesitará una clave de API de una Burp Service Account. Las cuentas de usuario de Burp no tienen claves de API de forma predeterminada, por lo que quizás deba crear un nuevo usuario específicamente para este fin. 

Consulte la [documentación de Burp](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) para obtener una guía sobre cómo configurar un usuario Service Account con una clave de API.

#### Asignaciones del conector

1. Ingrese la URL raíz de Burp en el campo **Location**: esta es la URL donde accede a la herramienta Burp.
2. Ingrese una API Key válida en el campo Secret. Esta es la clave de API asociada con su cuenta de Burp Service.

Consulte la [documentación oficial de Burp](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) para obtener más información sobre la API de Burp.
