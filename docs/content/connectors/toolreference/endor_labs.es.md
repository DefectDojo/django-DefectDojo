---
title: "Endor Labs"
description: "Cómo configurar el Conector Upstream de Endor Labs para DefectDojo"
weight: 54
audience: pro
---
El conector de Endor Labs utiliza la API REST de Endor Labs para sincronizar un **namespace** completo de Endor Labs. DefectDojo detecta cada **proyecto** de Endor como un Registro e importa los hallazgos de ese proyecto, trasladando el veredicto de **accesibilidad** de Endor para que pueda priorizar las vulnerabilidades cuyo código afectado sea realmente accesible.

#### Requisitos previos

Necesitará una **API key** de Endor Labs (un identificador de clave más su secret) y el **namespace** que desea sincronizar. Cree la clave en la plataforma de Endor Labs en **Settings \> Access \> API Keys**; la clave necesita acceso de lectura a los proyectos y hallazgos de ese namespace.

El conector se autentica intercambiando la API key y el secret por un bearer token de corta duración; el secret se utiliza únicamente para ese intercambio y nunca se almacena en texto plano.

#### Asignaciones del conector

1. Introduzca `https://api.endorlabs.com` en el campo **Location**. Si su tenant está alojado en una región distinta, utilice en su lugar la URL base de la API de esa región.
2. Introduzca el **Namespace** de Endor Labs que desea sincronizar (por ejemplo `your-org` o `your-org.team`).
3. Introduzca el identificador de **API Key**.
4. Introduzca el **API Secret** asociado a la clave.
5. De forma opcional, defina **Traverse Child Namespaces** en `true` para importar también los hallazgos de los namespaces hijos del namespace configurado.
6. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importan.

DefectDojo crea un Registro para cada proyecto de Endor Labs del namespace e importa sus hallazgos, asignando los niveles de severidad de Endor a las severidades de DefectDojo, los identificadores CVE/GHSA y la puntuación CVSS de cada vulnerabilidad, y las etiquetas de accesibilidad de Endor. El veredicto de accesibilidad (por ejemplo, *Reachable — vulnerable function is called* o *Unreachable*) se muestra como el Impact del hallazgo y como una etiqueta.

Para obtener más información, consulte la **[documentación de la API REST de Endor Labs](https://docs.endorlabs.com/rest-api/)**.
