---
title: "IriusRisk"
description: "Cómo configurar el Conector Upstream de IriusRisk para DefectDojo"
weight: 80
audience: pro
---
El conector IriusRisk usa un token de API para importar datos de modelado de amenazas desde su instancia de IriusRisk.

#### Requisitos previos

Necesitará un token de API de su cuenta de IriusRisk. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que se distinga claramente la actividad automatizada de las acciones manuales del equipo.

Para generar un token de API en IriusRisk:

1. Inicie sesión en su instancia de IriusRisk.
2. Vaya a su **User Profile** en el menú superior derecho.
3. Seleccione **API Token** y genere un nuevo token.

Consulte la [documentación de la API de IriusRisk](https://support.iriusrisk.com/hc/en-us/categories/360001148511) para obtener más información.

#### Asignaciones del conector

1. Introduzca la URL de su instancia de IriusRisk en el campo **Location URL**. Para instancias alojadas en la nube, suele ser `https://{your-subdomain}.iriusrisk.com`. Para instalaciones locales, use la URL base de su instancia.
2. Introduzca su **API Token** en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.
