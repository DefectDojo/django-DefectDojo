---
title: "Group-IB ASM"
description: "Cómo configurar el Conector Upstream de Group-IB ASM para DefectDojo"
weight: 68
audience: pro
---
El conector Group-IB ASM (Attack Surface Management) usa la API REST de Group-IB ASM para importar a DefectDojo **incidencias** (hallazgos) de superficie de ataque externa. DefectDojo detecta cada **empresa/tenant** de Group-IB como un Registro independiente e importa las incidencias de esa empresa de forma programada e incremental. El activo al que se refiere cada incidencia (un dominio, una IP o una URL) se adjunta al hallazgo resultante como un **Endpoint**.

#### Requisitos previos

Necesitará su inicio de sesión de Group-IB ASM y una clave de API. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada pueda distinguirse de las acciones manuales del equipo.

Para generar una clave de API:

1. Abra Group-IB Attack Surface Management, haga clic en **Help** en la esquina inferior izquierda y seleccione **API**.
2. Haga clic en **Generate API Key** (arriba a la derecha, debajo de su nombre de usuario).
3. Introduzca su contraseña de SSO y haga clic en **Next**, luego haga clic en **Copy token**.
4. Guarde la clave en un gestor de secretos y planifique su rotación periódica.

#### Asignaciones del conector

Group-IB ASM se autentica mediante HTTP Basic Auth, donde el nombre de usuario es su inicio de sesión de ASM y la contraseña es su clave de API. **Se requieren ambos valores**: la clave de API por sí sola no es suficiente.

1. Introduzca `https://asm.group-ib.com` en el campo **Location**. Es el mismo para todos los tenants de Group-IB ASM.
2. Introduzca su inicio de sesión de ASM (normalmente una dirección de correo electrónico) en el campo **Username**.
3. Introduzca su clave de API en el campo **API Key** (Secret).
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importan.

DefectDojo asigna cada **empresa** de Group-IB como un Registro independiente, usando el ID de la empresa como identificador. En la primera Sincronización, DefectDojo recupera el historial reciente de incidencias; las Sincronizaciones posteriores son incrementales y solo obtienen las incidencias modificadas desde la última Sincronización (según la marca de tiempo `lastSeen` más reciente de cada incidencia).

#### Limitar a una sola empresa (opcional)

De forma predeterminada, el conector detecta automáticamente las empresas disponibles para sus credenciales de API (mediante el endpoint `clients` de ASM) y crea un Registro por empresa. Esta es la configuración recomendada y no requiere configuración adicional.

Si el endpoint `clients` no está disponible para su tenant — por ejemplo, cuando está restringido a cuentas de socios/MSP —, el conector puede limitarse a una sola empresa proporcionando su **ID de empresa** como campo específico de la herramienta `company_id` en la configuración del conector. Cuando se establece `company_id`, DefectDojo usa esa empresa directamente en lugar de enumerar las empresas. Déjelo sin establecer para usar la detección automática.

Consulte el manual de la API REST de Group-IB ASM (disponible en el propio producto en **Help → API**) para obtener más información.
