---
title: "Backstage"
description: "Cómo configurar el Conector Upstream de Backstage para DefectDojo"
weight: 22
audience: pro
---
El conector de Backstage es un **conector de activos**: en lugar de importar Hallazgos, extrae su Software Catalog de [Backstage](https://backstage.io) hacia DefectDojo y mantiene sincronizada su jerarquía de Productos y la propiedad de los equipos con ella. Está diseñado para organizaciones que mantienen su inventario de servicios y su estructura organizativa en Backstage y desean que DefectDojo refleje esa estructura en lugar de mantenerla manualmente.

#### Qué se asigna

| Backstage | DefectDojo |
|---|---|
| **System** | Tipo de producto (los Components sin System se agrupan bajo un Tipo de producto configurable "Backstage / Uncategorized") |
| **Component** | Producto — con el nombre tomado de la entidad `title` (o de `name` si no existe), junto con la descripción del catálogo |
| **Owning Group** (relación `ownedBy`) | Un Grupo de DefectDojo vinculado al Producto (rol predeterminado: Maintainer, configurable) |
| **Owner email** (correo del perfil del Group, o correo del propietario User) | Un miembro del Producto, cuando ya existe un usuario de DefectDojo con ese correo (nunca se crean usuarios) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Etiquetas de Producto con el prefijo `backstage:` |
| `metadata.annotations` | Se almacena en el Registro (con límite); ciertas anotaciones seleccionadas pueden promoverse a atributos de primera clase o a etiquetas mediante **Annotation Mappings** |

Los Registros se identifican mediante el `metadata.uid` asignado por el servidor de la entidad, por lo que los cambios de nombre en Backstage actualizan el Producto asignado **en el mismo lugar** en la siguiente sincronización — sin duplicados. El nombre del Producto siempre sigue al catálogo: para cambiar el nombre de un Producto gestionado por este conector, cambie el nombre del Component en Backstage (un cambio de nombre realizado del lado de DefectDojo, o un nombre personalizado asignado durante la asignación manual, se concilia con el nombre del catálogo en la siguiente sincronización a menos que colisione con otro Producto). Los cambios de propiedad mueven la asignación de grupo del Producto. Los Components que desaparecen del catálogo (o que están marcados con la anotación `backstage.io/orphan`) se marcan como **MISSING** — DefectDojo nunca elimina un Producto por sí mismo. La jerarquía de Domain y Group (equipos superiores) se registra únicamente como etiquetas/metadatos; no crea niveles de jerarquía adicionales.

#### Prerrequisitos

El conector se autentica con un **token de acceso externo estático** frente al backend de Backstage. En la configuración de su aplicación Backstage, defina un token y (recomendado) restríjalo al plugin de catálogo:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Genere un token aleatorio robusto (por ejemplo `openssl rand -hex 32`) y guárdelo en el entorno de su implementación de Backstage. Consulte la [documentación de autenticación servicio a servicio de Backstage](https://backstage.io/docs/auth/service-to-service-auth) para obtener más detalles.

#### Asignaciones del conector

1. Ingrese la **URL raíz del backend de Backstage** en el campo **Location**: por ejemplo `https://backstage.example.com` (el conector añade `/api/catalog`). Debe ser la URL del **backend**, no la de la interfaz web frontend.
2. Ingrese el token de acceso externo estático en el campo **Secret**.

Campos opcionales (déjelos en blanco para usar los valores predeterminados):

* **Namespaces** — namespaces del catálogo a importar, separados por comas; en blanco se importan todos los namespaces.
* **Component Types** — valores de `spec.type` separados por comas (p. ej. `service,website`); en blanco se importan todos los tipos.
* **Page Size** — tamaño de página para las consultas al catálogo (1\-500, valor predeterminado 250).
* **TLS Verification** — establézcalo en `false` solo si Backstage sirve un certificado que DefectDojo no puede verificar (CA interna); no se recomienda.
* **Uncategorized Product Type** — el Tipo de producto usado para los Components sin System (valor predeterminado `Backstage / Uncategorized`).
* **Owner Group Role** — el rol otorgado al equipo propietario en los Productos asignados (valor predeterminado `Maintainer`).
* **Annotation Mappings** — un objeto JSON que asigna claves de anotación a nombres de atributos del Registro, o a `"tag"` para importar una anotación como etiqueta de Producto, p. ej. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Con **Auto\-Map** habilitado, un único Discover \+ Sync genera toda la estructura de Tipo de producto / Producto / propiedad sin pasos manuales. Con Auto\-Map deshabilitado, los Components descubiertos aparecen como Registros a la espera de su decisión de asignación.

#### Limitaciones (v1)

* La **pertenencia a Group de Backstage no se sincroniza**: el conector crea/vincula el equipo propietario como un Grupo de DefectDojo, pero completar los usuarios de ese grupo queda a cargo de su proveedor de identidad o de los administradores.
* Solo los Components se convierten en Productos; las APIs, Resources y Domains no se importan como activos (los domains aparecen como etiquetas).
* Las etiquetas y anotaciones se normalizan y se limitan para ajustarse a los límites de campo de DefectDojo (los valores demasiado grandes se truncan).

**Una nota sobre la dirección inversa:** mostrar los hallazgos y las calificaciones de DefectDojo *dentro* de Backstage (en las páginas de entidad) es una extensión natural que se implementaría como un plugin de frontend de Backstage que consume la REST API de DefectDojo — queda deliberadamente fuera del alcance de este conector, que solo extrae datos del catálogo hacia DefectDojo.
