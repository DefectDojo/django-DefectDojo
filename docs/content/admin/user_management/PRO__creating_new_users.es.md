---
title: Creación de un nuevo usuario
description: Cómo incorporar un nuevo usuario a su instancia de DefectDojo
audience: pro
weight: 1
---

Esta página describe el flujo de trabajo de incorporación recomendado para agregar nuevos usuarios a una instancia de DefectDojo.  Los usuarios de DefectDojo se pueden utilizar tanto como cuentas estándar operadas por personas como cuentas de servicio.

El administrador que crea la cuenta es responsable de entregar las credenciales iniciales (nombre de usuario y contraseña) al nuevo usuario.

## Flujo de trabajo recomendado

1. **Cree la cuenta de usuario** en DefectDojo (solo Superuser):
   * Vaya a **👤 Users → ➕ New User**.
   * Ingrese el nombre y la dirección de correo electrónico del nuevo usuario.
   * Establezca una contraseña temporal.
   * Envíe el formulario.

2. **Asigne los permisos** correspondientes: membresía de Producto/Tipo de producto, Permisos de configuración, Rol global o estado de Superuser. Consulte [Establecer los permisos de un Usuario](../set_user_permissions/) para obtener más información. Un nuevo usuario sin asignaciones no podrá ver ningún Producto ni Hallazgo.

3. **Envíe las credenciales al nuevo usuario por un canal externo** (por correo electrónico, la herramienta de chat de su equipo, o la forma en que normalmente comparte información confidencial). Incluya:
   * La URL de la instancia de DefectDojo.
   * El nombre de usuario (normalmente su dirección de correo electrónico).
   * La contraseña temporal que acaba de establecer.
   * Una nota indicando que debe cambiar la contraseña y habilitar la MFA (si su instancia utiliza MFA) en el primer inicio de sesión.

4. **El nuevo usuario inicia sesión y renueva la credencial.** Puede hacerlo de dos maneras:
   * Iniciar sesión con la contraseña temporal y luego cambiarla desde su menú de perfil, o
   * Usar el enlace **I forgot my password** en la página de inicio de sesión para establecer una contraseña directamente, sin usar la temporal. La contraseña temporal sigue siendo necesaria para que exista el registro inicial de la cuenta, pero el usuario no necesita recordarla si utiliza el flujo de restablecimiento de contraseña.

5. **El nuevo usuario configura la MFA** desde su menú de perfil. Recomendamos encarecidamente exigir la MFA a todos los usuarios en las instancias que no están detrás de un SSO.

## Usuarios SSO

Si su instancia está configurada con [SSO](../configure_sso/), el flujo de trabajo es diferente: los usuarios normalmente se crean en el primer inicio de sesión desde el Identity Provider, y usted solo necesita otorgarles membresía de grupo o roles después.

## Recuperación de un token de MFA perdido

Si un usuario pierde el acceso a su dispositivo de MFA, puede iniciar sesión con uno de los códigos de recuperación emitidos al momento de la inscripción. Si esos códigos también se han perdido, un administrador con acceso al servidor puede eliminar la MFA de la cuenta con `python manage.py remove_mfa --username <username>`, tras lo cual el usuario inicia sesión con su contraseña y se inscribe nuevamente; sus permisos e historial se conservan, por lo que no es necesario crear una cuenta de reemplazo.

Consulte [Autenticación multifactor](../pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) para conocer todas las opciones de recuperación, y tenga en cuenta que el acceso al propio **Cloud Manager** es un asunto aparte; consulte la [guía de resolución de problemas de conectividad](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes).
