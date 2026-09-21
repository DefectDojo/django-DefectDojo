---
title: "Black Duck"
description: "Cómo configurar el Conector Upstream de Black Duck para DefectDojo"
weight: 26
audience: pro
---
El conector de Black Duck importa hallazgos de **análisis de composición de software (SCA)** desde una instancia de Black Duck Hub (Synopsys / Black Duck). DefectDojo descubre todos los proyectos de la instancia y crea un Registro para cada **proyecto**; los hallazgos de un proyecto provienen de los componentes de la BOM vulnerables de su versión seleccionada.

#### Prerrequisitos

Un **token de API** de Black Duck para un usuario que pueda ver los proyectos que desea importar. En Black Duck, abra el menú de usuario \> **My Access Tokens** \> **Create New Token**, otórguele (como mínimo) acceso de lectura y copie el token cuando se muestre — solo se exhibe una vez. El conector intercambia este token por un bearer de corta duración en cada sincronización; nunca se almacena en texto claro más allá del campo secreto del conector.

#### Asignaciones del conector

1. Ingrese la URL de su hub de Black Duck en el campo **Location** — por ejemplo `https://your-company.app.blackduck.com`.
2. Ingrese el token de API en el campo **Secret**.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

Cada proyecto de Black Duck se convierte en un Registro. Por defecto el conector importa la versión **released** del proyecto (recurriendo a su primera versión si no existe); cada componente de la BOM vulnerable de esa versión se convierte en un hallazgo, titulado `{vulnerability} in {component}:{version}`.

Este conector es distinto de los parsers de Black Duck basados en archivos — sus hallazgos usan el tipo de análisis dedicado **Black Duck - Connectors Import**.
