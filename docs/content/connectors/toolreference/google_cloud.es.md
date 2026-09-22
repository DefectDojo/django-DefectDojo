---
title: "Google Cloud"
description: "Cómo configurar el Conector Upstream de Google Cloud para DefectDojo"
weight: 67
audience: pro
---
El conector de Google Cloud es un **Asset Connector**: lee la jerarquía de recursos de su Google Cloud y crea un Activo de DefectDojo para cada **proyecto**, agrupados en Organizaciones según la carpeta en la que se encuentra el proyecto. Cada carpeta también se convierte en un Activo, de modo que su organización, sus carpetas y sus proyectos aparecen en DefectDojo como el mismo árbol que ve en la consola de Cloud. No se importa ningún hallazgo.

**Tenga en cuenta:** este conector importa únicamente el **inventario** de sus proyectos. Para importar los hallazgos de Security Command Center, utilice el conector independiente [Google Cloud Security Command Center](/connectors/toolreference/google_cloud_scc/). Ambos son independientes y están diseñados para ejecutarse juntos: un proyecto que crea este conector es el mismo Activo sobre el que aterrizan los hallazgos de SCC, por lo que ejecutar ambos no duplica nada.

#### Requisitos previos

El conector se autentica con una **cuenta de servicio** de Google y solo lee metadatos de la jerarquía: nombres, ids, estado del ciclo de vida y etiquetas de carpetas y proyectos. No lee el contenido de los recursos ni hallazgos.

1. En Google Cloud, cree una cuenta de servicio; se recomienda una dedicada para DefectDojo.
2. Otórguele el rol **Browser** (`roles/browser`) en la organización o carpeta que desea importar. Los dos permisos que realmente necesita son `resourcemanager.folders.list` y `resourcemanager.projects.list`, por lo que un rol personalizado que los incluya también funciona.
3. Otorgue el rol en la parte **superior** del alcance que configure. El conector recorre todo el subárbol, y una carpeta que no pueda leer hace que la sincronización falle en lugar de importar silenciosamente un inventario parcial.
4. Cree una **clave JSON** para la cuenta de servicio y descárguela.
5. Habilite la **Cloud Resource Manager API** (`cloudresourcemanager.googleapis.com`) en el proyecto propietario de la cuenta de servicio.

#### Asignaciones del conector

1. Deje el campo **Location** con el valor predeterminado `https://cloudresourcemanager.googleapis.com`, salvo que utilice un endpoint no estándar.
2. En el campo **Parent Resource**, introduzca la raíz de la jerarquía que desea importar: `organizations/{id}` o `folders/{id}`. Un solo proyecto no es una jerarquía, por lo que `projects/{id}` no se acepta aquí — use el conector Google Cloud SCC para un alcance de un solo proyecto.
3. Pegue el contenido completo del archivo de **clave JSON** de la cuenta de servicio en el campo **Service Account Key**.

Cada carpeta y cada proyecto `ACTIVE` bajo el elemento padre se convierte en un Record. El Record de cada proyecto se nombra según su **ID de proyecto**, y su Organización en DefectDojo es la carpeta en la que se encuentra (o su organización de Google Cloud, si el proyecto se encuentra directamente debajo de ella).

Un proyecto que elimina en Google Cloud pasa al estado `DELETE_REQUESTED` y deja de importarse, por lo que su Record asignado se marca como `MISSING` en la siguiente sincronización en lugar de eliminarse: DefectDojo nunca elimina un Activo de forma silenciosa. Lo mismo ocurre con una carpeta que elimina.

#### Uso conjunto con el conector de Google Cloud SCC

Ambos conectores identifican un proyecto de la misma manera, y ambos nombran su Activo según el ID del proyecto. Por eso, si ejecuta primero este conector, los hallazgos de SCC aterrizan en los Activos que creó; si SCC se ejecutó primero, este conector adopta esos Activos y añade la jerarquía de carpetas a su alrededor. No necesita mapear nada dos veces.
