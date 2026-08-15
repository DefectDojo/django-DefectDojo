---
title: Aprovisionamiento SCIM
description: Aprovisiona y desaprovisiona usuarios de DefectDojo Pro desde su proveedor
  de identidad
weight: 19
audience: pro
---

DefectDojo Pro admite SCIM 2.0, lo que permite que su proveedor de identidad cree, actualice y desactive usuarios de DefectDojo directamente. Sin esto, DefectDojo solo se entera de un usuario cuando ese usuario inicia sesión, por lo que eliminar a alguien de su proveedor de identidad detiene los inicios de sesión futuros pero deja su cuenta de DefectDojo activa.

SCIM es independiente del inicio de sesión único y lo complementa. El SSO decide quién puede iniciar sesión; SCIM mantiene la lista de cuentas en sí sincronizada con su directorio. La mayoría de los clientes configuran ambos: SAML u OIDC para la autenticación, SCIM para el aprovisionamiento.

La configuración de SCIM solo puede realizarla un **Superusuario**.

## Qué hace SCIM en DefectDojo

Cuando conecta un proveedor de identidad mediante SCIM, este puede:

* crear usuarios de DefectDojo cuando se asigna la aplicación a alguien
* actualizar nombres y direcciones de correo electrónico cuando cambian en el directorio
* desactivar usuarios cuando se les retira la asignación o dejan la organización
* crear grupos, y agregar y eliminar sus miembros

Desactivar un usuario mediante SCIM hace dos cosas a la vez. La cuenta se marca como inactiva, por lo que el usuario ya no puede iniciar sesión, y se eliminan los tokens de API de DefectDojo del usuario. Por lo tanto, la baja cierra ambas puertas en un solo paso, que es la razón principal para usar SCIM en lugar de depender únicamente de su proveedor de identidad.

Se conserva el registro del usuario en sí. Los hallazgos, las notas y el historial hacen referencia a las personas que los crearon, por lo que DefectDojo desactiva la cuenta en lugar de eliminarla. Si la misma persona regresa, reactivarla mediante su proveedor de identidad restaura el acceso sin alterar ese historial.

## Configuración

1. Abra **Connect > Authorization** y seleccione **SCIM Provisioning**. SCIM aparece junto a sus proveedores de inicio de sesión porque se conecta al mismo proveedor de identidad, y está etiquetado como **Provisioning** para distinguirlo de los proveedores que colocan un botón en la página de inicio de sesión.

2. Marque **Enable SCIM Provisioning** y envíe. Mientras esto esté desactivado, los endpoints de SCIM se comportan como si no existieran, por lo que una prueba de conexión desde su proveedor de identidad reporta la dirección como no encontrada.

3. Copie la **Tenant URL** que se muestra en la página. Se ve así:

   ```
   https://<your-instance>.cloud.defectdojo.com/scim/v2
   ```

4. En el panel **SCIM Tokens**, asigne al token un nombre que indique dónde se usará, por ejemplo "Okta production", y luego seleccione **Generate Token**.

5. Copie el token del cuadro de diálogo y péguelo en su proveedor de identidad. DefectDojo solo almacena un hash del token, por lo que no se puede volver a mostrar. Si lo pierde, genere otro y revoque el anterior.

Puede mantener más de un token activo a la vez. Para rotarlos, genere un token nuevo, actualice su proveedor de identidad y luego revoque el anterior. No hay ninguna ventana en la que el aprovisionamiento deje de funcionar.

El panel de tokens registra cuándo se usó cada token por última vez, lo cual es una forma rápida de confirmar que su proveedor de identidad realmente está llegando a DefectDojo.

## Okta

1. En Okta Admin Console, vaya a **Applications > Browse App Catalog** y agregue **SCIM 2.0 Test App (Header Auth)**. Si ya tiene una aplicación SAML para DefectDojo, puede habilitar el aprovisionamiento en esa aplicación en su lugar.

2. Abra la pestaña **Provisioning** y seleccione **Configure API Integration**.

3. Establezca **SCIM 2.0 Base Url** en la Tenant URL que copió anteriormente.

4. Establezca **API Token** en `Bearer <your token>`, incluida la palabra `Bearer` y un único espacio. Este tipo de aplicación envía el valor literalmente como encabezado de Authorization.

5. Seleccione **Test API Credentials** y luego guarde.

6. En **Provisioning > To App**, habilite **Create Users**, **Update User Attributes** y **Deactivate Users**.

7. Asigne personas o grupos a la aplicación. Okta busca primero a cada persona en DefectDojo por nombre de usuario y solo crea una cuenta cuando no encuentra ninguna, por lo que cualquiera que ya tenga una cuenta de DefectDojo se vincula en lugar de duplicarse.

Para enviar también grupos, abra la pestaña **Push Groups** y agregue los grupos que desea que DefectDojo refleje. Consulte [Grupos](#groups) más abajo para saber qué hace DefectDojo con ellos.

## Microsoft Entra ID

1. En el centro de administración de Entra, vaya a **Enterprise applications > New application > Create your own application**, y elija la opción "non-gallery". Si ya tiene una aplicación para DefectDojo, use esa.

2. Abra **Provisioning** y establezca **Provisioning Mode** en **Automatic**.

3. Establezca **Tenant URL** en la Tenant URL que copió anteriormente.

4. Establezca **Secret Token** en su token de SCIM. Entra lo envía como token bearer, por lo que no agregue aquí la palabra `Bearer`.

5. Seleccione **Test Connection** y luego guarde.

6. Asigne usuarios y grupos en **Users and groups**, e inicie el aprovisionamiento.

Entra aprovisiona en un ciclo de aproximadamente 40 minutos. Mientras configura todo, **Provision on demand** aplica un solo usuario o grupo de inmediato, lo que hace mucho más rápido confirmar que la configuración funciona.

## Qué almacena DefectDojo

DefectDojo asigna un pequeño conjunto de atributos SCIM e ignora el resto.

| SCIM attribute | DefectDojo field |
|---|---|
| `userName` | Nombre de usuario |
| `name.givenName` | Nombre |
| `name.familyName` | Apellido |
| `emails` | Dirección de correo electrónico |
| `active` | Si la cuenta está habilitada |
| `externalId` | Se conserva para que su proveedor de identidad pueda hacer coincidir el registro más adelante |

Los atributos que DefectDojo no modela, incluidos los números de teléfono, los cargos y la extensión empresarial de SCIM, se aceptan y se ignoran en lugar de rechazarse. Asignar atributos adicionales en su proveedor de identidad es inofensivo.

Dos atributos merecen especial atención:

**Nombre de usuario.** DefectDojo permite letras, dígitos y los caracteres `@ . + - _` en un nombre de usuario. Si su proveedor de identidad envía un nombre de usuario que contiene cualquier otra cosa, DefectDojo rechaza a ese usuario con un error que indica el problema, en lugar de almacenar silenciosamente un nombre de usuario diferente. Almacenar un nombre de usuario alterado impediría que su proveedor pudiera encontrar la cuenta más adelante.

**Dirección de correo electrónico.** SCIM no requiere una, y DefectDojo creará el usuario sin ella. Tenga en cuenta que las notificaciones de DefectDojo, incluidos los informes programados y las alertas, no tienen adónde ir para un usuario sin dirección de correo electrónico. Asigne el atributo `emails` a menos que tenga una razón para no hacerlo.

SCIM nunca establece contraseñas, ni otorga nunca el estado de superusuario o de staff. Si su proveedor de identidad está configurado para enviar contraseñas, DefectDojo las ignora. Los usuarios aprovisionados de esta manera inician sesión mediante SSO.

## Grupos

SCIM gestiona solo los grupos que creó. Los grupos que usted creó en la interfaz de DefectDojo, o que llegaron mediante la asignación de grupos de SAML o Azure AD, son invisibles para SCIM y su proveedor de identidad no puede renombrarlos, vaciarlos ni eliminarlos.

Esto importa porque el envío de grupos es, por naturaleza, un reemplazo completo. Si un proveedor de identidad pudiera adoptar un grupo existente, su próxima sincronización reemplazaría la membresía cuidadosamente elegida de ese grupo por lo que contenga el directorio. Por lo tanto, enviar un grupo cuyo nombre ya está en uso falla con un mensaje que explica el conflicto. Para entregar un grupo existente a su proveedor de identidad, renombre uno de los dos, o elimine el grupo de DefectDojo y deje que el proveedor lo vuelva a crear.

Dentro de un grupo gestionado por SCIM, la membresía pertenece a su proveedor de identidad y los roles pertenecen a DefectDojo:

* A un miembro recién agregado se le asigna el rol **Reader**.
* Si asciende a alguien a un rol superior en DefectDojo, las sincronizaciones posteriores dejan ese rol sin cambios.
* Cualquier persona agregada manualmente a un grupo gestionado por SCIM se elimina en la siguiente sincronización, porque el proveedor de identidad es la fuente de verdad sobre quién pertenece.

Eliminar un grupo mediante SCIM elimina el grupo y sus membresías. Nunca elimina a las personas que estaban en él.

## Protección del acceso de administrador

Por defecto, SCIM no desactivará una cuenta de superusuario. El fallo común en cualquier configuración de aprovisionamiento es un proveedor de identidad con un alcance más amplio del previsto, y los superusuarios son la forma de volver a entrar en DefectDojo cuando algo sale mal.

Si desea que su proveedor de identidad también gestione superusuarios, habilite **Allow SCIM to deactivate superusers** en la página de configuración de SCIM. Aun así, DefectDojo se niega a desactivar el último superusuario activo restante, por lo que el aprovisionamiento no puede dejar la instancia sin un administrador.

## Limitaciones

* Un proveedor de identidad por instancia de DefectDojo.
* El filtrado es compatible en `userName`, `displayName`, `externalId` e `id`, usando una única comparación de igualdad. Esto cubre lo que envían Okta y Entra cuando hacen coincidir registros. Los filtros más complejos se rechazan con un error que lo indica.
* Las operaciones masivas, la ordenación y el endpoint `/Me` no están implementados.
* Las membresías de grupo se gestionan mediante el endpoint Groups. Enviar la membresía de grupo en un registro de usuario no tiene efecto, lo cual coincide con el comportamiento de ambos proveedores.

## Solución de problemas

**La prueba de conexión reporta "not found".** SCIM está desactivado, o la instancia no tiene licencia para él. Verifique que **Enable SCIM Provisioning** esté activado y que su suscripción incluya SSO. Toda la dirección de SCIM se comporta como si no existiera hasta que ambas condiciones se cumplan.

**La prueba de conexión reporta un error de autenticación.** El token es incorrecto, o se ha revocado. Genere uno nuevo y actualice su proveedor de identidad. En Okta, verifique que el valor comience con `Bearer ` y un espacio; en Entra, verifique que no sea así.

**Un usuario no logra aprovisionarse con un error sobre el nombre de usuario.** El nombre de usuario contiene caracteres que DefectDojo no permite. Cambie el atributo que su proveedor de identidad asigna a `userName`, normalmente a la dirección de correo electrónico del usuario o al nombre principal de usuario.

**Un grupo no logra enviarse, reportando que ya existe un grupo con ese nombre.** Se creó un grupo de DefectDojo con ese nombre en otro lugar. Consulte [Grupos](#groups) más arriba.

**Un miembro de grupo no logra aprovisionarse.** La persona aún no ha sido aprovisionada en DefectDojo. Asígnela a la aplicación, y la membresía se completará en el siguiente ciclo.

**Comience con Diagnostics.** Las solicitudes SCIM rechazadas se registran en **Connect > Diagnostics**, con el endpoint, el estado y el mensaje que envió DefectDojo. Esto suele ser más rápido que leer el registro de su proveedor de identidad, y es el único lugar que muestra ambos lados del intercambio. El aprovisionamiento exitoso no se registra allí; los cambios en usuarios y grupos aparecen en el historial de auditoría en su lugar.

**Todo reporta éxito, pero nada aparece en DefectDojo.** Verifique que la Tenant URL termine en `/scim/v2` sin barra diagonal final, y que su proveedor de identidad realmente esté llegando a su instancia. La columna **Last Used** en el panel de SCIM Tokens muestra si ha llegado alguna solicitud.

**Usuarios de DefectDojo Pro:** si su instancia restringe el acceso por dirección IP, agregue las direcciones de su proveedor de identidad a la lista blanca del firewall antes de configurar SCIM. Consulte [Reglas de firewall](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings).
