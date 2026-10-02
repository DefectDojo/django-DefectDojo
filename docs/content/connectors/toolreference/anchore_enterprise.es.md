---
title: "Anchore"
description: "Cómo configurar el Conector Upstream de Anchore para DefectDojo"
weight: 16
audience: pro
---
El conector de Anchore usa el token de API de un usuario para extraer datos de Anchore Enterprise.  Los Productos se asignarán y descubrirán en función de las "Applications", que se componen de varias Images en Anchore - consulte la [documentación de Anchore Enterprise](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) para obtener más información.

#### Asignaciones del conector

1. La URL de Anchore en el campo **Location**: esta es la URL donde accede a Anchore.
2. Ingrese una API Key válida en el campo Secret. Esta es la clave de API asociada con su cuenta de servicio de Burp.

Consulte la [documentación oficial de Anchore](https://docs.anchore.com/current/docs/) para obtener más información sobre cómo crear un token para Anchore.
