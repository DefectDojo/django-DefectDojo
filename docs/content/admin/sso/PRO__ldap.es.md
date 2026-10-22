---
title: LDAP Authentication
description: Configure la autenticación LDAP en DefectDojo Pro
weight: 20
audience: pro
aliases:
- /es/en/open_source/ldap-authentication
---

DefectDojo Pro admite la autenticación LDAP desde la interfaz de **Enterprise Settings** — no se necesitan imágenes de Docker personalizadas ni archivos de configuración.

A diferencia de los demás proveedores de esta página, LDAP no es un flujo basado en redirección. Los usuarios inician sesión con el formulario estándar de nombre de usuario y contraseña de DefectDojo, y sus credenciales se verifican contra su directorio. No hay ningún botón de inicio de sesión adicional.

## Configuración

Abra **Enterprise Settings > LDAP Settings**.

![imagen](images/sso_ldap_settings.png)

1. **Server URI** — el directorio al que conectarse, por ejemplo `ldaps://ldap.example.com:636`.
   Prefiera `ldaps://`. Si debe usar `ldap://` sin cifrar, habilite **Use StartTLS** más abajo para que la conexión se actualice a un canal cifrado antes de enviar las credenciales.
2. **Bind DN** — el nombre distintivo de la cuenta de servicio usada para buscar usuarios.
   Déjelo en blanco para un bind anónimo.
3. **Bind Password** — la contraseña de esa cuenta de servicio. El valor almacenado nunca se devuelve al navegador; deje el campo en blanco para conservar la contraseña que ya guardó.
4. **User Search Base** — el DN bajo el cual buscar las entradas de usuario, por ejemplo
   `ou=people,dc=example,dc=com`.
5. **User Search Filter** — el filtro usado para localizar al usuario. **Debe** contener el marcador de posición literal `%(user)s`, que se sustituye por el nombre de usuario introducido. Los valores habituales son `(uid=%(user)s)` para OpenLDAP y `(sAMAccountName=%(user)s)` para Active Directory.
6. **User Attribute Mapping** — vea más abajo.
7. Marque **Enable LDAP** para activarlo.

Use **Validate Config** para comprobar la configuración sin guardarla. Informa sobre si la configuración está completa, si el servidor es accesible, si el bind se realiza correctamente, si las bases de búsqueda se resuelven, y si la asignación de atributos parece utilizable.

## User Attribute Mapping

Cada fila asigna un **LDAP Attribute** al **DefectDojo Field** que debe rellenar. Use **Add Attribute Mapping** para añadir más filas y el icono de papelera para eliminar una.

![imagen](images/sso_ldap_attribute_mapping.png)

- **LDAP Attribute** es texto libre y debe coincidir con el atributo que realmente devuelve su directorio — por ejemplo `uid`, `givenName`, `sn`, `mail` en OpenLDAP, o `sAMAccountName`, `givenName`, `sn`, `mail` en Active Directory.
- **DefectDojo Field** se elige de una lista: **Username**, **First Name**, **Last Name** y **Email**.
- Se recomienda encarecidamente asignar un atributo a **Email**: DefectDojo usa la dirección de correo para las notificaciones.
- El mismo atributo puede alimentar más de un campo. Cada campo de DefectDojo solo puede asignarse desde un único atributo.
- Sin ninguna asignación, las cuentas se crean sin nombre ni dirección de correo.

**Always Update User** controla cuándo se aplica la asignación. Cuando está habilitado (el valor predeterminado), los atributos asignados se actualizan desde el directorio en cada inicio de sesión, de modo que un cambio de nombre o correo en LDAP llega a DefectDojo. Cuando está deshabilitado, solo se aplican cuando se crea la cuenta por primera vez.

## Group Mapping

DefectDojo puede reflejar los grupos LDAP de un usuario en grupos de DefectDojo al iniciar sesión. Marque **Enable Group Mapping** para mostrar la configuración.

![imagen](images/sso_ldap_group_mapping.png)

- **Group Search Base** — el DN bajo el cual buscar las entradas de grupo, por ejemplo `ou=groups,dc=example,dc=com`. Obligatorio cuando la asignación de grupos está habilitada.
- **Group Type** — cómo modela la pertenencia su directorio. Elija **groupOfNames** para OpenLDAP y Active Directory, **groupOfUniqueNames**, o **posixGroup**.
- **Group Limiter Regex Expression** — solo se reflejan los grupos cuyo nombre coincide con esta expresión. Use `.*` para permitir todos, o un prefijo como `^dd-` para reflejar solo los grupos que DefectDojo debe gestionar.

Los grupos se crean en el primer uso si aún no existen. Un grupo recién creado no tiene permisos hasta que un Superuser los configura — consulte [User Groups](../../user_management/create_user_group/).

## Additional Options

* **Use StartTLS** — actualiza una conexión `ldap://` sin cifrar a TLS antes de realizar el bind. No es necesario cuando el URI ya es `ldaps://`.
* **Always Update User** — actualiza los atributos asignados desde el directorio en cada inicio de sesión.

## Solución de problemas

Ejecute primero **Validate Config** — normalmente indicará el problema directamente. Más allá de eso:

**Todos los inicios de sesión fallan, pero el directorio es accesible.** Compruebe que el **User Search Filter** contiene `%(user)s` y que el atributo que contiene coincide con lo que los usuarios realmente escriben. Un filtro `(uid=%(user)s)` nunca coincidirá si sus usuarios inician sesión con un `sAMAccountName` de Active Directory.

**Los inicios de sesión funcionan pero las cuentas no tienen nombre ni correo.** El **User Attribute Mapping** está vacío, o los nombres de atributo LDAP de la izquierda no coinciden con lo que devuelve su directorio.

**Un nombre cambió en LDAP pero no en DefectDojo.** **Always Update User** está deshabilitado, por lo que la asignación solo se aplicó cuando se creó la cuenta.

**Los intentos de inicio de sesión se quedan colgados o son lentos.** Las conexiones y búsquedas están limitadas por un tiempo de espera, de modo que un directorio inaccesible falla en lugar de bloquearse indefinidamente. Compruebe **Server Reachability** en **Validate Config** y confirme que el puerto está abierto desde el host de DefectDojo.
