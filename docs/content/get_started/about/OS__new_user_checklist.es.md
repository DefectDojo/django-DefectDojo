---
title: ☑️ Lista de verificación para nuevos usuarios
description: Primeros pasos con DefectDojo
draft: 'false'
weight: 3
audience: opensource
---

Aquí tiene una referencia rápida que puede usar para garantizar una implementación exitosa, desde un lienzo en blanco hasta una aplicación totalmente funcional.  Este artículo asume que tiene **DefectDojo Community Edition** instalado y en funcionamiento en su entorno.

La esencia de DefectDojo es importar datos de seguridad, organizarlos y presentarlos a las personas que necesitan conocerlos.  Estas son algunas formas de lograrlo en DefectDojo Open-Source:

### DefectDojo Open-Source

1. Los usuarios de Open-Source pueden empezar creando su primer [Product Type and Product](/asset_modelling/os_hierarchy/product_hierarchy/).  Una vez creados, pueden [importar un archivo](/import_data/import_scan_files/os__import_scan_ui/) a uno de esos Productos mediante la interfaz de usuario.

2. Ahora que tiene datos en DefectDojo, considere ampliar su estructura de Productos con la [Product Hierarchy Overview](/asset_modelling/os_hierarchy/product_hierarchy/). La Product Hierarchy crea un inventario funcional de sus aplicaciones, lo que le ayuda a dividir sus datos en categorías lógicas. Estas categorías pueden usarse para aplicar reglas de control de acceso, o para segmentar sus informes al equipo correcto.

3. Use el [Report Builder](/metrics_reports/reports/using-the-report-builder/#opening-the-report-builder) para resumir los datos que ha importado. Los informes pueden usarse para compartir rápidamente los Hallazgos con las partes interesadas, como los propietarios de productos.

Esta es la esencia de DefectDojo - importar datos de seguridad, organizarlos y presentarlos a las personas que necesitan conocerlos.

Todas estas funciones se pueden automatizar, y dado que DefectDojo puede gestionar más de 500 herramientas (en el momento de escribir esto) debería estar listo para crear un inventario de seguridad funcional de toda la producción de su organización.

### Open-Source Features
- ¿Su organización usa Jira? Aprenda a usar nuestra [integración con Jira](/connectors/os_jira/os__jira_guide/) para crear tickets de Jira a partir de los datos que ingiere.
- ¿Espera compartir DefectDojo con muchos usuarios de su organización? Consulte nuestras guías de [gestión de usuarios](/admin/user_management/about_perms_and_roles/) y configure el control de acceso basado en roles (RBAC).
- ¿Listo para adentrarse en la automatización? Aprenda a usar la [API de DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/) para importar automáticamente nuevos datos, y crear una canalización de CI/CD robusta.
