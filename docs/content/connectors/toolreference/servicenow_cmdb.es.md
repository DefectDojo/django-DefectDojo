---
title: "ServiceNow CMDB"
description: "Cómo configurar el Conector Upstream de ServiceNow CMDB para DefectDojo"
weight: 121
audience: pro
---
El conector de ServiceNow CMDB es un **conector de activos (Asset Connector)**: en lugar de importar hallazgos, lee Configuration Items (CI) de su ServiceNow Configuration Management Database y crea un Asset de DefectDojo para cada CI, agrupados en Organizations según su clase de CI. No se importa ningún hallazgo.

#### Requisitos previos

Necesitará una instancia de ServiceNow y una cuenta que pueda leer las tablas de CMDB a través de la ServiceNow Table API. Recomendamos una cuenta de servicio dedicada y de solo lectura para DefectDojo. La cuenta necesita acceso de lectura a las tablas `cmdb_ci` que desea importar.

#### Asignaciones del conector

1. Ingrese la URL de su instancia de ServiceNow en el campo **Location**: `https://{your-instance}.service-now.com`.
2. Seleccione o cree una **Tool Configuration** de ServiceNow que contenga las credenciales de la instancia (el nombre de usuario y la contraseña de ServiceNow).

Cada Configuration Item se convierte en un Record con el nombre del CI, agrupado por su **clase de CI** (por ejemplo, aplicación, servidor o servicio de negocio). Discovery y Sync concilian la lista de CI: los CI nuevos aparecen como Records `NEW`, y un CI eliminado del CMDB se marca como `MISSING` en el siguiente Sync para que su equipo pueda triarlo. DefectDojo nunca elimina un Producto de forma silenciosa.
