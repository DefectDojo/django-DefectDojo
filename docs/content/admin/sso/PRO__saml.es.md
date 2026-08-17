---
title: Configuración de SAML
description: Configura SAML en DefectDojo Pro
weight: 1
audience: pro
---

DefectDojo Pro admite la autenticación SAML mediante la interfaz de **Enterprise Settings**. DefectDojo de código abierto no incluye SSO — consulte [Usuarios autorizados](/admin/user_management/os__authorized_users/) para conocer el control de acceso en código abierto.

## URL de ACS (Assertion Consumer Service)

Su proveedor de identidad necesita saber a dónde enviar (POST) la respuesta SAML después de que un usuario se autentica. La URL de ACS de DefectDojo es:

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

Algunas cosas que debe saber sobre este endpoint:

- **El endpoint solo acepta solicitudes `POST`.** Abrir la URL de ACS directamente en un navegador emite un GET y devolverá un **HTTP 405 Method Not Allowed**. Este es el comportamiento esperado — no significa que SAML esté roto o mal configurado. El endpoint está diseñado para ser invocado por su IdP como parte del flujo de redirección SAML, no por un navegador que escribe la URL.
- **La URL de ACS está disponible en su instancia de DefectDojo Cloud en todo momento** — no necesita habilitar SAML en DefectDojo antes de configurarlo en su IdP. Puede configurar el lado del IdP y el lado de DefectDojo en cualquier orden.

## Configuración inicial

1. Abra **Enterprise Settings > SAML Settings**.

   ![image](images/sso_betaui_1.png)

2. Establezca un **Entity ID** — una etiqueta o URL que su proveedor de identidad SAML usa para identificar a DefectDojo. Este campo es obligatorio.

3. Opcionalmente, establezca **Login Button Text** — el texto que se muestra en el botón en el que los usuarios hacen clic para iniciar el inicio de sesión SAML.

4. Opcionalmente, establezca una **Logout URL** para redirigir a los usuarios después de que cierren sesión en DefectDojo.

5. Elija un **Name ID Format**:
   - **Persistent** — los usuarios se identifican de forma consistente mediante SAML entre sesiones.
   - **Transient** — los usuarios reciben un ID SAML diferente en cada inicio de sesión.
   - **Entity** — todos los usuarios comparten un único NameID de SAML.
   - **Encrypted** — el NameID de cada usuario está cifrado.

6. **Required Attributes** — especifique los atributos que DefectDojo requiere de la respuesta SAML.

7. **Attribute Mapping** — asigne los atributos que envía su IdP a los campos de usuario de DefectDojo que deben completar. Cada fila empareja un **SAML Attribute** con un **DefectDojo Field**; use **Add Attribute Mapping** para agregar más filas y el icono de papelera para eliminar una.

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** es texto libre y debe coincidir con el nombre de atributo que realmente emite su IdP. Algunos IdP (por ejemplo, Entra ID / Azure AD) envían URI de notificación completamente calificados, como `http://schemas.microsoft.com/identity/claims/emailaddress`, en lugar de nombres descriptivos. Si no está seguro de qué envía su IdP, habilite **Enable SAML Debugging** (consulte [Solución de problemas](#troubleshooting)) e inspeccione la aserción en los registros.
   - **DefectDojo Field** se elige de una lista: **Username**, **First Name**, **Last Name** y **Email**.
   - Como mínimo, asigne el atributo que corresponde a **Username**. DefectDojo busca a los usuarios por nombre de usuario al hacer coincidir los inicios de sesión SAML con las cuentas existentes.
   - Se recomienda encarecidamente asignar un atributo a **Email**: DefectDojo usa la dirección de correo electrónico para las notificaciones y para hacer coincidir un inicio de sesión entrante con una cuenta existente por correo electrónico.
   - El mismo atributo puede alimentar más de un campo; por ejemplo, una notificación de correo electrónico usada tanto para **Email** como para **Username**. Lo contrario no está permitido: cada campo de DefectDojo solo puede asignarse desde un atributo.
   - Una fila con solo una mitad completada se rechaza al guardar, y la celda correspondiente se resalta. Las filas que agrega pero nunca completa se descartan en lugar de tratarse como errores.

8. **Remote SAML Metadata** — la URL donde está alojado el metadato de su proveedor de identidad SAML.

9. Marque **Enable SAML** en la parte inferior del formulario para activar el inicio de sesión SAML. Aparecerá un botón **Login With SAML** en la página de inicio de sesión de DefectDojo.

   ![image](images/sso_saml_login.png).

## Opciones adicionales

* **Create Unknown User** — crea automáticamente un nuevo usuario de DefectDojo si no se encuentra en la respuesta SAML.
* **Allow Unknown Attributes** — permite el inicio de sesión de usuarios que tienen atributos no listados en Attribute Mapping.
* **Sign Assertions/Responses** — requiere que todas las respuestas SAML entrantes estén firmadas.
* **Sign Logout Requests** — firma todas las solicitudes de cierre de sesión enviadas por DefectDojo.
* **Force Authentication** — requiere que los usuarios se autentiquen con el proveedor de identidad en cada inicio de sesión, independientemente de las sesiones existentes.
* **Enable SAML Debugging** — registra información detallada de SAML para solución de problemas. Consulte [Solución de problemas → Salida de depuración de SAML](#saml-debugging-output) para saber dónde aparece la salida del registro.

## Asignación de grupos SAML

DefectDojo puede usar la aserción SAML para asignar usuarios automáticamente a [Grupos de usuarios](../../user_management/create_user_group/). Los grupos en DefectDojo asignan permisos a todos sus miembros, por lo que la asignación de grupos le permite gestionar permisos de forma masiva. Esta es la única forma de establecer permisos mediante SAML.

**La asignación de grupos es opcional.** Aunque los campos **Group Name Attribute** y **Group Limiter Regex Expression** aparecen con un asterisco de campo obligatorio (`*`) en la interfaz, el formulario SAML se enviará sin ellos, y el inicio de sesión SAML funcionará sin la asignación de grupos. No necesita crear previamente grupos o roles en su IdP (por ejemplo, roles de aplicación de Azure AD) antes de habilitar SAML — solo necesita configurar estos campos cuando realmente desee que DefectDojo lea la membresía de grupo desde la aserción. Si no configura la asignación de grupos, los nuevos usuarios SSO creados no tendrán permisos por defecto; consulte [Acceso predeterminado para usuarios aprovisionados por SSO](#default-access-for-sso-provisioned-users) más abajo.

El campo **Group Name Attribute** especifica qué atributo en la aserción SAML contiene las membresías de grupo del usuario. Cuando un usuario inicia sesión, DefectDojo lee este atributo y asigna al usuario a los grupos coincidentes. Para limitar qué grupos de la aserción se consideran, use el campo **Group Limiter Regex Expression** — esta es una expresión regular aplicada a los nombres de grupo de la aserción, usada para filtrar sobre cuáles debe actuar DefectDojo.

El valor debe coincidir exactamente con el nombre de atributo que emite su proveedor de identidad en la aserción, incluido cualquier prefijo de espacio de nombres. Un nombre corto y descriptivo como `groups` solo funcionará si su IdP está configurado para emitir ese nombre de atributo literal — muchos IdP usan en su lugar un URI de notificación completamente calificado.

### Atributo de nombre de grupo por proveedor de identidad

| Identity Provider | Default attribute name to use |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups` (el nombre de atributo que configuró en el Group Attribute Statement de la aplicación SAML) |
| **Keycloak** | `groups` (o lo que haya establecido como "SAML Attribute Name" en el mapper Group List) |
| **PingFederate / genérico** | El valor que haya configurado en el lado del IdP — verifique la aserción de su IdP antes de asumir `groups` |

Si la asignación de grupos parece no hacer nada — los usuarios inician sesión correctamente pero no se crean ni asignan grupos — consulte [Solución de problemas → La asignación de grupos SAML no hace nada](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned) más abajo.

Si no existe ningún grupo con un nombre coincidente, DefectDojo creará uno automáticamente y asignará a sus miembros el rol **Reader**. Tenga en cuenta que este rol Reader rige el acceso del miembro *al grupo en sí* — no otorga ningún acceso a los Productos, Tipos de producto u otros activos organizativos subyacentes. Esos permisos se configuran por separado, y un grupo recién creado automáticamente todavía no tiene ninguno de ellos hasta que un Superusuario le asigna un rol sobre los Productos o Tipos de producto relevantes.

Para activar la asignación de grupos, marque la casilla **Enable Group Mapping** en la parte inferior del formulario.

## Acceso predeterminado para usuarios aprovisionados por SSO

Cuando se crea un nuevo usuario mediante SAML (o cualquier proveedor de autenticación social) y no se lo agrega a ningún grupo mediante la asignación de grupos SAML, llegará a una instancia de DefectDojo **sin permisos**. Al iniciar sesión verá cero Tipos de producto, cero Productos y cero Compromisos — el panel aparecerá vacío.

Para dar a cada nuevo usuario SSO aprovisionado una base razonable, configure un **Default group** + **Default group role** en la página de Configuración del sistema:

1. Abra **⚙️ Configuration → System Settings** (solo Superusuario).
2. Establezca **Default group** en el [Grupo de usuarios](../../user_management/create_user_group/) al que deben unirse los usuarios recién creados.
3. Establezca **Default group role** en el rol que deben tener en ese grupo (por ejemplo, **Reader**).
4. Opcionalmente, establezca **Default group email pattern** en una expresión regular (por ejemplo, `.*@yourcompany\.com$`) para que el grupo predeterminado solo se aplique a los usuarios cuyo correo electrónico coincida.
5. Guarde.

Tanto **Default group** como **Default group role** deben estar establecidos — si alguno está vacío, el grupo predeterminado no se aplica.

Esta configuración se aplica a **todos los usuarios recién creados**, incluidos los creados mediante SAML, OAuth y otros proveedores de autenticación social, porque se ejecuta en la señal de creación de usuario de Django en lugar de dentro de un backend de autenticación específico.

> **Los usuarios existentes no se ven afectados.** El grupo predeterminado solo se aplica cuando se crea un usuario por primera vez. Los usuarios existentes de DefectDojo conservarán sus membresías de grupo actuales incluso si cambia esta configuración más tarde.

## Diferencias entre Cloud y On-Premise

DefectDojo Cloud no tiene el mismo nivel de personalización de SAML que DefectDojo On-Prem. Las únicas variables que se pueden establecer son a través de la interfaz. Estas son algunas de las diferencias clave:

| Capability | Cloud | On-Premise |
|---|---|---|
| **Coincidencia de nombre de usuario** | Solo NameID | Solo NameID (la variable de entorno `SAML_USE_NAME_ID_AS_USERNAME` se aplica solo a Código abierto, no a Pro) |
| **Cifrado de aserciones SAML** | No compatible actualmente | No compatible actualmente |
| **Registros de inicio de sesión SAML** | No disponible en la interfaz. Contacte a Soporte para solicitar los registros. | Disponible mediante los registros del contenedor de la aplicación (`docker logs dojo`) |
| **Método de configuración** | Solo interfaz de Enterprise Settings | Interfaz de Enterprise Settings, Django Admin o Django Shell |
| **Variables de entorno** | Los clientes no pueden establecerlas directamente. Contacte a Soporte para cambios. | Se pueden establecer mediante `dojo-compose-cli environment add` |

Si necesita hacer coincidir usuarios en un atributo distinto de NameID (como `uid` o `email`), configure su proveedor de identidad para enviar el valor deseado como NameID en lugar de ajustar la configuración de DefectDojo.

## Solución de problemas

### Salida de depuración de SAML

Cuando **Enable SAML Debugging** (en [Opciones adicionales](#additional-options)) está marcado, DefectDojo escribe información detallada del procesamiento SAML — incluidos los atributos sin procesar recibidos del IdP — en los registros de la aplicación al nivel `DEBUG` bajo el logger `saml2`.

| Where you're running | Where to read the debug output |
|---|---|
| **DefectDojo Cloud** | El registro de depuración SAML no está expuesto en la interfaz. Contacte a DefectDojo Support para solicitar los registros de una ventana de tiempo específica. |
| **On-Premise (contenedor único)** | `docker logs dojo` (o su agregación de registros de Helm/K8s) |
| **On-Premise (Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi` (o el agregador de registros de su clúster) |

Desactive esta opción después de terminar de solucionar problemas — los registros de depuración de SAML son extensos y pueden contener valores de atributos sensibles de su IdP.

### Los usuarios reciben un error de "User not found" o "Permission denied" después de iniciar sesión correctamente en el IdP

Si la aserción SAML se analiza correctamente (sin errores de XML o de firma) pero DefectDojo rechaza el inicio de sesión, la causa más común es una **discrepancia de nombre de usuario** entre el IdP y DefectDojo.

DefectDojo busca al usuario **por nombre de usuario** al hacer coincidir un inicio de sesión SAML con una cuenta existente. Si el valor que su IdP envía como atributo `username` no coincide con el nombre de usuario de un usuario existente de DefectDojo, la búsqueda falla — aunque el resto de la aserción sea válida.

Hay dos soluciones; elija la que mejor se adapte a su entorno:

- **Elimine `username` de Attribute Mapping** y deje que DefectDojo recurra a usar el `NameID` de SAML como nombre de usuario. Esto es apropiado si los nombres de usuario de DefectDojo ya coinciden con el formato de NameID que emite su IdP.
- **Alinee los nombres de usuario.** Asegúrese de que los nombres de usuario en DefectDojo sean exactamente lo que su IdP envía en la notificación `username`. Para la mayoría de las organizaciones, la convención más sencilla es hacer que los nombres de usuario de DefectDojo sean iguales a la dirección de correo electrónico del usuario, y que el IdP envíe el correo electrónico como la notificación `username`.

Si no está seguro de qué está enviando realmente el IdP, habilite **Enable SAML Debugging** (arriba) e inspeccione los atributos analizados en los registros.

### La asignación de grupos SAML no hace nada — los usuarios inician sesión pero no se asigna ningún grupo

La causa más común es una discrepancia entre el campo **Group Name Attribute** y el nombre de atributo que su IdP realmente está enviando. Consulte la tabla [Atributo de nombre de grupo por proveedor de identidad](#group-name-attribute-by-identity-provider) más arriba, y habilite **Enable SAML Debugging** para ver los atributos sin procesar que devuelve el IdP.
