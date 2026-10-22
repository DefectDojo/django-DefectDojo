---
title: Jerarquía de activos
description: 'DefectDojo Pro: renovación de la jerarquía de productos'
audience: pro
weight: 1
aliases:
- /es/en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
- /es/asset_modelling/pro_hierarchy/assets_organizations
---

DefectDojo Pro está ampliando las clases de objetos Producto/Tipo de producto para ofrecer mayor flexibilidad en el modelo de datos.

## Enabling the Hierarchy Feature

Las dos partes siguientes son independientes y se controlan mediante mecanismos distintos.

### Asset Hierarchy

**Jerarquía de activos** habilita relaciones padre/hijo entre Activos. La jerarquía se visualiza y se administra desde la pestaña **Producto** en la navegación.

Jerarquía de activos está disponible de forma general y activada en todas las instancias, tanto Cloud como On-Premise. No hay nada que habilitar, y ya no aparece en la página de Feature Flags.

### Label Changes (optional)

**Cambios de etiquetas** renombra "Product Type" a "Organization" y "Product" a "Asset" en toda la interfaz. Este es un paso independiente de la habilitación de la jerarquía y se puede realizar al mismo tiempo o más adelante.

Los cambios de etiquetas están activados de forma predeterminada a partir de la versión 3.0. Hay dos controles que abarcan partes distintas de la aplicación:

* **Interfaz Pro** (la interfaz predeterminada): un superusuario activa "Organization / Asset Relabeling" en **Settings > Feature Flags**, tanto en instancias Cloud como On-Premise. Las nuevas etiquetas aparecen en la siguiente carga de página. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).
* **Páginas de la interfaz clásica e informes generados**: sus etiquetas y URLs provienen del ajuste de despliegue `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`, que se lee cuando DefectDojo se inicia. En instalaciones on-premise, configúrelo y reinicie DefectDojo. En [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), envíe un correo a [support@defectdojo.com](mailto:support@defectdojo.com) con la URL de su instancia.

Ambos están activados de forma predeterminada, y el valor de Feature Flags se inicializó a partir del ajuste de despliegue, por lo que ambos coinciden a menos que cambie uno de ellos. Manténgalos sincronizados si usa tanto la interfaz clásica como la interfaz Pro.

Tenga en cuenta que los cambios de etiquetas son solo cosméticos: los endpoints de la API y los nombres de los campos permanecen sin cambios, por lo que la automatización existente seguirá funcionando.

## Significant Changes

* **Los Tipos de producto** se han renombrado a "Organizations", y los **Productos** se han renombrado a "Assets". A partir de la versión 3.0, este cambio de nombre está activado de forma predeterminada. Consulte [Cambios de etiquetas](#label-changes-optional) para conocer los controles que lo desactivan.
* Los **Activos** ahora pueden tener relaciones padre/hijo entre sí para subcategorizar aún más los componentes organizacionales.

### Organizations

Al igual que con los Tipos de producto, las **Organizaciones** deben entenderse como una categoría de nivel superior. Puede usarlas para separar las aplicaciones de software principales de su empresa, sus departamentos o sus funciones de negocio.

Por ejemplo, podría crear una Organización para varias agrupaciones de repositorios: "Core Application", "Infrastructure", "DevOps", "Analytics" o "SDK" podrían contener cada una múltiples repositorios de código.

Tenga en cuenta que, a efectos de generación de informes, es más fácil combinar varias Organizaciones en un solo documento que subdividir una única Organización en documentos separados. Por lo tanto, recomendamos configurar las Organizaciones con el nivel de granularidad que tenga sentido para los informes de su equipo. Por ejemplo, no es necesario representar una gran división de negocio como una Organización si principalmente va a generar informes sobre departamentos individuales dentro de esa división.

### Assets

Los Activos están pensados para representar subdivisiones de sus Organizaciones. Sin embargo, a diferencia de los Productos, los Activos pueden anidarse y tener relaciones padre-hijo entre sí.

## Asset Nesting Examples

### Asset-Level Branch Representation

Las ramas de desarrollo y de funcionalidades se pueden representar de varias maneras; Compromisos o Tests separados son formas ya existentes de representar la diferencia entre sus ramas de Producción, Desarrollo y otras ramas de funcionalidades.

También puede representarlas usando Activos anidados. Considere el siguiente árbol de Activos:

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

En este entorno, cada rama (`prod`, `dev`, `feature a`, `feature b`) podría tener sus propios Compromisos y Tests aislados de los demás Activos, de modo que no se deduplican entre sí. Esta configuración también puede facilitar la navegación, ya que los nombres de los Activos pueden corresponder directamente a la ruta en Git.

### Mono-Repo: Separate Components

Si usa un único repositorio para todo su código, pero tiene distintos equipos que contribuyen a directorios dentro de ese repositorio, puede configurar el anidamiento de Activos para representar esa estructura.

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

En este diagrama, cada elemento bajo "Core Application" podría registrarse como un Activo separado, con criticidad de negocio propia (ver: [Priority & Risk](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines)), RBAC y sus correspondientes Compromisos y Tests. Podría seguir realizando pruebas y almacenando resultados en el Activo superior (por ejemplo, `webapp-backend`), pero también podría ejecutar pruebas aisladas en un Activo hijo concreto (por ejemplo, `database`).

### Pen Tests: Isolated RBAC

Si desea almacenar los resultados de pruebas de penetración dentro de un único activo, pero no quiere que los testers puedan ver los datos del activo, podría crear activos hijos para que cada grupo de pruebas suba sus resultados.

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

Es fundamental señalar que dar a un usuario acceso RBAC a un único Activo hijo (por ejemplo, `Pen Test Group A`) no le permite ver ningún Hallazgo de otros Activos hijos (por ejemplo, `Pen Test Group B`), ni tampoco le permite ver Hallazgos en el Activo superior (`webapp-frontend`).

El Activo superior podría contener Compromisos que representen resultados de CI/CD, pruebas internas, datos históricos u otros datos de Hallazgos que no desee que terceros puedan descubrir. Crear un Activo hijo para resultados de Test específicos permite que su equipo interno informe sobre esos resultados en combinación con el estado del Activo superior.

## Visualizing Assets - Hierarchy

Puede visualizar la estructura de los Activos en DefectDojo y cambiar las relaciones usando la opción Jerarquía de activos en el menú.

![image](images/asset_hierarchy.png)

Al abrir Jerarquía de activos se mostrará una tabla con todos sus Activos, que se puede filtrar. Seleccionar uno o más Activos de esta tabla generará un diagrama de jerarquía.

![image](images/asset_hierarchy_diagram.png)

### Diagram navigation

Los iconos de la parte superior izquierda del diagrama de jerarquía le permiten acercar y alejar el zoom. Hacer clic y arrastrar en este diagrama le permite desplazarse por él.

Cada Activo se representa como un único nodo en este diagrama, que se puede mover para fines de visualización.

Los Activos se conectan entre sí mediante rutas etiquetadas, que representan el tipo de relación que tiene cada nodo con los demás. Actualmente, `parent` es la única etiqueta admitida.

### Exploring Asset nodes

Se puede interactuar con cada nodo de Activo haciendo clic en los botones azules. Estos botones solo aparecen cuando se selecciona un nodo de Activo (haciendo clic en el nodo).

![image](images/asset_hierarchy_node.png)

* 👁️ (icono de ojo) lo llevará directamente a la Vista de activo correspondiente (anteriormente conocida como Vista de producto).
* ✏️ (icono de lápiz) abrirá una ventana modal con el formulario Editar activo (anteriormente conocido como formulario Editar producto)
* ➕ (icono de más) le permitirá agregar un nuevo Activo hijo a este Activo. El Activo no necesita estar actualmente visible en el diagrama, pero debe formar parte de la misma Organización.
* ✥ (icono de cuatro flechas) le permite cambiar el Activo superior del Activo seleccionado actualmente.
* 🗑️ (icono de papelera) le permite eliminar la relación de un Activo con su superior. Este icono solo aparece si un Activo ya tiene un Activo superior.

Si su diagrama muestra un Activo con Activos superiores no seleccionados, puede hacer clic en el botón Load More para completar el diagrama con el Activo superior (así como con los hijos de ese Activo superior).

![image](images/assets_loadmore.png)

## Notes

* Tenga en cuenta que los ámbitos de deduplicación no han cambiado; los Activos solo deduplican Hallazgos dentro de sí mismos y no consideran los Hallazgos de otros Activos, independientemente de las relaciones padre/hijo.
* Los ámbitos de RBAC no han cambiado dentro de este sistema; cada Activo sigue considerándose un objeto individual a efectos de asignación de permisos. No se ha creado ninguna nueva herencia de RBAC.
  * Dar a un usuario acceso a toda una Organización seguirá dándole acceso a todos los Activos contenidos en esa Organización (como ocurría con los Tipos de producto).
  * Dar a un usuario acceso a un único Activo no le da acceso a ningún Activo superior o hijo relacionado, ni acceso a la Organización.
* No hay límite en la cantidad de relaciones padre/hijo que se pueden crear. En teoría, podría representar toda la estructura de directorios de un repositorio con Activos separados si así lo deseara.
* No se permiten relaciones cíclicas: los Activos superiores no pueden ser hijos de sus propios Activos hijos.
