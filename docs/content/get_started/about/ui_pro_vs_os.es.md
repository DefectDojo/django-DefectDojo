---
title: 🎨 Cambios en la UI Pro
description: Cómo trabajar con las distintas interfaces de usuario en DefectDojo
draft: 'false'
weight: 5
audience: pro
aliases:
- /es/en/about_defectdojo/ui_pro_vs_os
---

A fines de 2023, DefectDojo, Inc. lanzó una nueva UI para DefectDojo Pro, que ahora es la UI predeterminada de esta edición.

La UI Pro aporta las siguientes mejoras a DefectDojo:

- Diseño moderno y elegante utilizando Vue.js.
- Entrega de datos y tiempos de carga optimizados, especialmente para grandes volúmenes de datos.
- Acceso a nuevas funciones Pro, incluidas las vistas de [Conectores Upstream](/connectors/upstream/about/), [Universal Importer](/import_data/pro/specialized_import/external_tools/), y [Métricas Pro](/metrics_reports/pro_metrics/pro__overview/).
- Flujos de trabajo de UI mejorados: mejor filtrado, paneles y navegación.

## Cambiar a la UI Pro

Para acceder a la UI Pro, abra el menú de Opciones de usuario en la esquina superior derecha.  También puede volver a la UI Clásica desde el mismo menú.

![image](images/beta-classic-uis.png)

## Cambios de navegación

![image](images/pro_ui_overview.png)

1. La **barra lateral** se ha reorganizado en cuatro categorías principales: Paneles, Importar, Gestionar y Configuración.

2. La página de inicio, las [capacidades nativas de conexión a la API impulsadas por IA](/metrics_reports/ai/mcp_server_pro/), las Métricas Pro y la vista de Calendario son accesibles desde Paneles.

4. Los métodos de importación se encuentran en la sección Importar: configure [Conectores](/connectors/about/) para extraer hallazgos de sus escáneres (Upstream) o enviarlos a sistemas de seguimiento de incidencias (Downstream), use el formulario [Agregar hallazgos](/import_data/import_scan_files/pro__import_scan_ui/) para añadir Hallazgos, use [Smart Upload](/import_data/pro/specialized_import/smart_upload/) para gestionar herramientas de escaneo de infraestructura, o utilice nuestras herramientas externas—[Universal Importer y DefectDojo CLI](/import_data/pro/specialized_import/external_tools/)—para agilizar los procesos de importación y reimportación de Hallazgos y objetos asociados.

5. La sección **Gestionar** le permite ver los distintos objetos de la [Jerarquía de producto](/asset_modelling/os_hierarchy/product_hierarchy/), con vistas para Tipos de producto, Productos, Compromisos, Tests, Hallazgos, Aceptación de riesgo, Endpoints y Componentes.  También hay secciones adicionales para generar informes (Report Builder), usar encuestas (Surveys), así como un [Motor de reglas](/automation/rules_engine/about/).

5. La sección **Configuración** le permite configurar su instancia de DefectDojo, incluyendo su Licencia, la Configuración en la nube, los Usuarios, la Configuración de funciones y los ajustes empresariales de nivel administrativo. (Las integraciones se trasladaron a **Importar > Conectores > Conectores Downstream**.)

6. La sección **Configuración** contiene las páginas administrativas, agrupadas como Sistema, Usuarios y permisos, Flujo de trabajo de Hallazgos, Configuración, Notificaciones, Operaciones y Licencia y soporte, con una página de **Toda la configuración** que lista y permite buscar en todas ellas. Consulte [El menú de configuración](/navigation/pro__settings_menu/).

7. La UI Pro también cuenta con un **nuevo formato de tabla**, utilizado en la [Jerarquía de producto](/asset_modelling/os_hierarchy/product_hierarchy/) para facilitar la navegación.  Se puede hacer clic en cada columna para aplicar un filtro correspondiente, y las columnas se pueden reordenar para presentar los datos como usted prefiera.

8. La tabla también cuenta con un menú de **"Alternar columnas"** que permite añadir o quitar columnas de la tabla.

## Filtrar la tabla

En esta captura de pantalla estamos filtrando todos los Hallazgos que pertenecen a "Sam's Awesome Product." Una vez que se hace clic en Apply, el contenido de esta lista de Hallazgos se actualizará para reflejar el filtro elegido.

![image](images/pro_ui_sams_filter.png)

## Nuevos paneles

Se incluyen nuevas visualizaciones de Métricas en la UI Pro. Todos estos informes se pueden filtrar y exportar como PDF para compartirlos con una audiencia más amplia.

![image](images/program_insights.png)

- El panel de **Executive Insights** muestra el estado actual de sus Productos y Tipos de producto.
- **Priority Insights** muestra los hallazgos más críticos, con la opción de filtrar por diferentes períodos, Tipos de producto, Productos y Etiquetas.
- El panel de **Program Insights** muestra la eficacia de su equipo de seguridad y el ahorro de costos asociado a separar los duplicados y falsos positivos de los Hallazgos procesables.
- **Remediation Insights** muestra la eficacia de su equipo en la remediación de Hallazgos.
- **Tool Insights** muestra la eficacia de su conjunto de herramientas (y de los pipelines de Conectores Upstream) en la detección y el informe de vulnerabilidades.
