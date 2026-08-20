---
title: "Coverity"
description: "Cómo configurar el Conector Upstream de Coverity para DefectDojo"
weight: 40
audience: pro
---
El conector de Coverity importa hallazgos desde un servidor **Coverity Connect**. DefectDojo crea un Registro para cada **proyecto** de Coverity.

#### Asignaciones del conector

1. Introduzca la URL de su servidor Coverity Connect en el campo **Location**.
2. Introduzca el **username** de Coverity Connect en el campo **Username**.
3. Introduzca la contraseña o la clave de autenticación del usuario en el campo **Secret**.
4. De forma opcional, defina un **View Name** para seleccionar qué vista de incidencias guardada lee el conector. Déjelo en blanco para usar la opción predeterminada, **Outstanding Issues**.
5. De forma opcional, defina **Import All Issue Kinds** en `true` para ampliar la importación más allá del filtro predeterminado de incidencias de Security y Quality (`RESOURCE_LEAK`).
