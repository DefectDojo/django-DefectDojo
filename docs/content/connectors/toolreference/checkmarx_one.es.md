---
title: "Checkmarx ONE"
description: "Cómo configurar el Conector Upstream de Checkmarx ONE para DefectDojo"
weight: 33
audience: pro
---
El conector de Checkmarx ONE de DefectDojo llama a la API de Checkmarx para obtener datos.

#### **Asignaciones del conector**

1. Ingrese su **Tenant Name** en el campo **Checkmarx Tenant**. Este nombre debería ser visible en la página de inicio de sesión de Checkmarx ONE, en la esquina superior derecha:   
" Tenant: \<**su nombre de tenant**\> "  
​
![imagen](images/connectors_tool_reference_2.png)

2. Ingrese una clave de API válida. Es posible que deba generar una nueva: consulte la [documentación de la API de Checkmarx](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) para obtener más detalles.
3. Ingrese la ubicación de su tenant en el campo **Location**. Esta URL tiene el siguiente formato:  
​`https://<your-region>.ast.checkmarx.net/` . Su Región se encuentra al comienzo de la URL de Checkmarx cuando usa la aplicación Checkmarx. **<https://ast.checkmarx.net>** es el servidor principal de EE. UU. (que no tiene prefijo de región).

#### **Manejo de branches**

Por defecto, cada sincronización importa los hallazgos del **único scan completado más reciente de un proyecto, sin importar el branch**. Si su CI escanea muchos branches, el branch que resulte haber escaneado en último lugar "gana" esa sincronización: los hallazgos que solo existen en otros branches no se importan, y la conciliación de cierre de antiguos de la sincronización puede hacer que los hallazgos se abran y cierren alternadamente a medida que distintos branches se turnan como el scan más reciente.

Dos campos opcionales controlan este comportamiento:

- **Branch**: fija cada proyecto a un único nombre de branch — solo se importan los scans de ese branch. Es un valor global único para todo el conector, por lo que se adapta a flotas donde cada proyecto usa el mismo branch de larga duración (p. ej. `main`).
    - Se admite un **comodín `*`**. Un valor de Branch que contenga `*` selecciona *todos* los branches coincidentes en lugar de uno solo — por ejemplo `release/*` importa cada branch de release, y `*` coincide con todos los branches. Combinado con **Track Scanned Branches**, esta es la forma de rastrear una familia de branches sin rastrearlos todos.
    - Si un comodín no coincide con **ningún** branch dentro de la ventana de escaneo, esa sincronización se **omite** en lugar de tratarse como "el branch no tiene hallazgos" — de este modo, un patrón que temporalmente no coincide con nada no puede cerrar todos los hallazgos del activo.
- **Track Scanned Branches**: cuando está habilitado, cada sincronización encuentra todos los branches con un scan completado en el historial reciente de scans del proyecto e importa **el scan completado más reciente de cada branch**, con una reimportación por branch. Los hallazgos de cada branch residen en su propio Compromiso en el activo asignado, llamado "\<Compromiso predeterminado\> \- \<branch\>", por lo que el cierre de hallazgos obsoletos está delimitado por branch: una corrección fusionada en un branch nunca puede cerrar los hallazgos de otro branch. El branch principal del proyecto (según lo informado por Checkmarx) se importa primero, de modo que las reapariciones del mismo hallazgo en otros branches se deduplican contra el original del branch principal.

Notas sobre **Track Scanned Branches**:

- **Verifique qué valor predeterminado se aplica en su caso.** El seguimiento de branches está **habilitado por defecto para las instalaciones nuevas**. Las instalaciones anteriores al cambio conservan su comportamiento previo, por lo que la opción permanece deshabilitada para ellas hasta que alguien la active.
- Cuando ambos campos están configurados, solo se rastrea el **Branch** fijado — incluso cuando ese valor de Branch es un patrón comodín, en cuyo caso se rastrea cada branch que coincida con el patrón.
- Un branch que deja de escanearse (fusionado o eliminado) deja de recibir actualizaciones: su Compromiso permanece visible con sus últimos hallazgos conocidos, que puede revisar y cerrar en bloque.
- Deshabilitar la opción más adelante es seguro: los Compromisos por branch simplemente dejan de recibir importaciones y el Compromiso predeterminado se reanuda en la siguiente sincronización.
- Los Conectores concilian el estado según el programa de sincronización. El seguimiento de branches hace que cada sincronización sea completa entre branches; no hace que los datos sean en tiempo real entre sincronizaciones.
