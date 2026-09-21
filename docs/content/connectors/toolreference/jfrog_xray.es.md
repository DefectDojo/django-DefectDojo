---
title: "JFrog Xray"
description: "Cómo configurar el Conector Upstream de JFrog Xray para DefectDojo"
weight: 81
audience: pro
---
El conector JFrog Xray usa la API REST de JFrog Xray para obtener datos de vulnerabilidades de sus repositorios de Artifactory. DefectDojo detectará todos los repositorios de su instancia de JFrog y generará informes de vulnerabilidades mediante Xray, importando hallazgos de forma programada.

#### Requisitos previos

Necesitará un token de API con acceso tanto a la API de Artifactory como a la de Xray. Recomendamos crear una cuenta de servicio dedicada para DefectDojo. La cuenta requiere:

* Acceso de lectura a los repositorios de Artifactory
* Permiso para generar y ver informes de vulnerabilidades de Xray (permiso `Apply on Watches` en Xray, o equivalente)

#### Asignaciones del conector

1. Introduzca la URL base de su instancia de JFrog en el campo **Location**. Debe ser la URL raíz de su instancia de JFrog, por ejemplo `https://your-instance.jfrog.io`. No incluya una ruta final — DefectDojo construirá automáticamente las rutas de API correspondientes.
2. Introduzca un **Reference Token** válido en el campo **Secret**. Los tokens se pueden generar en **User Management > Access Tokens** en la interfaz de JFrog Platform.
Deberá generar un **Reference Token** y usar ese valor.

Ámbitos de token necesarios para JFrog Xray:

- **All Services**, ya que DefectDojo necesita acceso tanto a los servicios de XRay como de Artifactory
- **Manage Reports + Manage Resources** como mínimo.

De forma predeterminada, DefectDojo asigna cada **repositorio** de Artifactory como un Registro independiente. Cada Sincronización genera un informe de vulnerabilidades completo por repositorio mediante Xray, de modo que los estados de los hallazgos en DefectDojo siempre reflejan el estado actual del repositorio.

#### Filtro de repositorio (opcional)

De forma predeterminada, el conector detecta **todos** los repositorios de su instancia de JFrog. En instancias con un gran número de repositorios — muchos de los cuales pueden no ser relevantes para la revisión de seguridad —, la detección se puede limitar con el campo opcional **Repository Filter**, en **Import Filters** en el formulario del conector.

El filtro se aplica durante la detección, **antes de realizar cualquier trabajo por repositorio**. Un repositorio fuera del filtro no tiene ningún coste: no se genera ningún informe de Xray para él y, en el modo de artefactos, no se enumera ninguno de sus artefactos de primer nivel. Esto lo convierte en la forma más eficaz de reducir tanto el tiempo de Sincronización como la carga que DefectDojo impone a su instancia de JFrog — más que cualquier ajuste aplicado más adelante en la Sincronización. Se recomienda especialmente junto con **Artifact-Level Records** en instancias grandes.

**Sintaxis:** una lista de claves de repositorio separadas por comas. Cada entrada puede usar comodines `*`:

* Una entrada que contenga `*` se compara como un patrón — `releases-*` coincide con toda clave de repositorio que comience por `releases-`, y `*docker-pr-local*` coincide con cualquier clave que contenga `docker-pr-local`. Un `*` coincide con cualquier secuencia de caracteres, incluido `/`.
* Una entrada sin `*` debe coincidir **exactamente** con una clave de repositorio.
* Un repositorio se detecta si coincide con **cualquier** entrada de la lista. Los espacios alrededor de las comas se ignoran.

```
releases-*, snapshots
```

El ejemplo anterior detecta todos los repositorios cuya clave comience por `releases-`, más el único repositorio llamado exactamente `snapshots`.

Notas:

* El filtro es una **lista de permitidos** (allow-list) — una coincidencia selecciona un repositorio. No existe sintaxis de exclusión o negación, por lo que no se puede expresar directamente "todo excepto X".
* La comparación es **sensible a mayúsculas y minúsculas**, tanto para entradas exactas como para comodines. `*` es el único carácter comodín; `?` y los rangos de caracteres no son compatibles.
* **Déjelo en blanco para detectar todos los repositorios.** Un valor que solo contiene espacios o comas se trata como en blanco.
* Un filtro que no coincide con nada simplemente no detecta nada — no se produce ningún error. Si una Sincronización no encuentra repositorios inesperadamente, revise el log del conector en busca de la entrada `repository filter scoped discovery`, que indica cuántos de los repositorios totales coincidieron.
* El campo se puede modificar después de crear la conexión.

**Cambiar el filtro más adelante:** los repositorios que un filtro recién restringido ya no incluye dejan de detectarse, y sus Registros existentes siguen el ciclo de vida normal de los productos que la herramienta ya no reporta — los Registros **mapeados** se marcan como `MISSING` en la siguiente Sincronización, y los Registros `NEW` sin mapear se eliminan. Los hallazgos ya importados en DefectDojo no se eliminan; el filtro solo rige la detección.

#### Registros a nivel de artefacto

El interruptor **Artifact-Level Records** cambia la detección a un nivel por debajo del repositorio: cada entrada de primer nivel bajo la raíz de un repositorio (para repositorios Docker, cada imagen; para repositorios genéricos, cada archivo o carpeta de nivel superior) se convierte en su propio Registro. Cada Sincronización sigue generando un único informe de Xray por repositorio — DefectDojo atribuye cada vulnerabilidad a los artefactos a los que afecta, de modo que la carga sobre su instancia de JFrog no aumenta.

> **Compruebe en qué modo se encuentra antes de su primera Sincronización.** Artifact-Level Records está **activado de forma predeterminada para las instalaciones nuevas**. Las instalaciones anteriores a esta función conservan su diseño existente a nivel de repositorio, por lo que el interruptor permanece desactivado hasta que alguien lo active. En ambos casos, el interruptor se puede cambiar en cualquier momento — consulte *Cambiar una conexión existente* más abajo.

Con Artifact-Level Records habilitado:

* Los repositorios permanecen como Registros y se convierten en **activos principales**: no contienen hallazgos propios, pero cuando la función Asset Hierarchy está habilitada, DefectDojo relaciona automáticamente cada activo de artefacto con su activo de repositorio mediante una relación `parent`. Los activos se pueden filtrar entonces por elemento principal/secundario, y los hallazgos se propagan hacia arriba en la jerarquía.
* Una vulnerabilidad que afecta a varios artefactos se importa en el activo de cada artefacto afectado, de modo que cada activo muestra el conjunto completo de hallazgos que le afectan.
* Los hallazgos se limitan a la **última build** de cada artefacto, de modo que los hallazgos de un artefacto describen su build actual en lugar de acumular resultados de todas las builds que Xray haya escaneado alguna vez.
* Las relaciones jerárquicas creadas por el conector nunca sobrescriben las relaciones que usted haya creado manualmente. Si un activo ya tiene un elemento principal asignado, el conector lo deja tal cual.
* El token necesita además acceso de lectura a la API de almacenamiento de Artifactory (incluido en los ámbitos anteriores).

**Cambiar una conexión existente a Artifact-Level Records:** el interruptor se puede cambiar en cualquier momento. En la primera Sincronización posterior, aparecen nuevos Registros de artefactos para mapear — habilite **Auto Map** en la conexión al cambiar el interruptor para que los hallazgos se muevan sin interrupción. Los activos a nivel de repositorio dejan de recibir hallazgos y sus hallazgos importados previamente se cierran en su siguiente Sincronización (los mismos hallazgos se vuelven a importar bajo los nuevos activos de artefacto, con un estado nuevo); las notas y el historial de los hallazgos antiguos a nivel de repositorio permanecen en el activo de repositorio. Volver al modo anterior invierte esto: los Registros de repositorio vuelven a recibir hallazgos (los hallazgos previamente cerrados se reabren al volver a coincidir), y los Registros de artefacto se marcan como MISSING — sus activos y hallazgos se conservan pero dejan de actualizarse, por lo que puede archivarlos cuando le convenga.

Consulte la [documentación de la API REST de JFrog Xray](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) para obtener más información.
