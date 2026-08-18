---
title: Autenticación multifactor (MFA)
description: Configure la MFA en su propia cuenta, exíjala en toda su instancia, y
  recupere a un usuario que haya perdido su dispositivo
audience: pro
weight: 3
---

La autenticación multifactor añade un segundo paso al inicio de sesión: después de su contraseña, DefectDojo solicita un código de seis dígitos de una aplicación de autenticación. Recomendamos encarecidamente exigirla para todos los usuarios en las instancias que no están detrás de un SSO.

La MFA de DefectDojo Pro utiliza una **aplicación de autenticación TOTP** — Google Authenticator, 1Password, Authy, o cualquier otra aplicación que escanee un código QR estándar. No existe una opción por correo electrónico o SMS.

## Configuración de la MFA en su cuenta

1. Vaya a **Connect \> Authorization \> MFA Settings**.
2. En **Personal Multi-Factor Authentication Settings**, haga clic en **Set Up MFA**.
3. Escanee el código QR con su aplicación de autenticación. Si no puede escanearlo, la pantalla de configuración también muestra la clave como texto, que puede escribir en su aplicación manualmente.
4. Ingrese el código de seis dígitos que muestra su aplicación, y haga clic en **Verify & enable**.
5. DefectDojo muestra sus **códigos de recuperación**. Guárdelos en un lugar seguro antes de continuar — vea más abajo. Haga clic en **Copy codes**, guárdelos, y luego haga clic en **I've saved them. Continue**.

La MFA queda activa a partir de ese momento. La próxima vez que inicie sesión, DefectDojo le pedirá un código después de su contraseña.

### Códigos de recuperación

Se le entregan **diez códigos de recuperación de un solo uso** al habilitar la MFA. Cada uno se puede usar una vez, en lugar de un código de su aplicación de autenticación, y se consume al utilizarlo.

Se muestran **una sola vez**, en la pantalla final de configuración. Después, la página MFA Settings solo muestra cuántos le quedan, no los códigos en sí.

Si pierde sus códigos de recuperación — o desea un nuevo conjunto después de haber usado varios — haga clic en **Regenerate Recovery Codes** en la página MFA Settings. Esto **reemplaza todos sus códigos existentes**: los que haya guardado anteriormente dejan de funcionar de inmediato, así que guarde el nuevo conjunto enseguida.

Los códigos de recuperación son lo que le permite volver a entrar cuando pierde su teléfono, así que guárdelos en un lugar distinto del dispositivo donde ejecuta su aplicación de autenticación.

### Desactivación de la MFA

**Disable MFA** en la página MFA Settings la desactiva para su propia cuenta. Solo necesita haber iniciado sesión — no se le pedirá un código de confirmación.

Si su administrador ha hecho obligatoria la MFA, se le pedirá que la configure de nuevo en su próximo inicio de sesión.

## Inicio de sesión con MFA

Después de ingresar su nombre de usuario y contraseña, DefectDojo le solicita su código de seis dígitos. Si no tiene su aplicación de autenticación, ingrese en su lugar uno de sus **códigos de recuperación** en el mismo campo — ese código quedará entonces consumido.

## Exigir la MFA para todos

Los superusuarios pueden hacer obligatoria la MFA en toda la instancia:

1. Vaya a **Connect \> Authorization \> MFA Settings**.
2. En la tarjeta **MFA Settings** — visible solo para los Superusers — marque **Require Multi-Factor Authentication Globally**.
3. Envíe el formulario.

Esto está **desactivado de forma predeterminada**.

Una vez activado, cualquier usuario que aún no se haya inscrito es enviado a la pantalla de configuración de MFA en su próximo inicio de sesión, y **no puede omitirla**. Completa la inscripción, guarda sus códigos de recuperación, y llega al lugar al que se dirigía originalmente.

### Usuarios SSO

La MFA es aplicada por DefectDojo, no delegada a su proveedor de identidad. Con la MFA global obligatoria, los usuarios que inician sesión mediante SSO también son enviados a configurar la MFA después de que su proveedor los devuelve a DefectDojo, y se les solicita un código en los inicios de sesión posteriores.

No existe una configuración para eximir a los usuarios SSO. Si su proveedor de identidad ya aplica su propia MFA, decida deliberadamente si desea ambas — activar la MFA global implicará dos solicitudes para los usuarios SSO.

## Recuperación de un usuario que ha perdido su dispositivo de MFA

Siga estos pasos en orden:

1. **Use un código de recuperación.** Si el usuario aún conserva sus códigos de recuperación, ingresa uno en lugar del código de la aplicación al iniciar sesión, y luego configura la MFA de nuevo desde cero.
2. **Si todavía tiene una sesión iniciada en algún lugar,** puede ir a **MFA Settings** y hacer clic en **Disable MFA** sin necesitar un código, y luego volver a inscribirse.
3. **Pida a un administrador que elimine su MFA.** Con acceso al servidor, un administrador puede eliminar la MFA de una cuenta:

   ```
   python manage.py remove_mfa --username <username>
   ```

   El comando también acepta `--user-id` o `--email` en lugar de `--username` (se requiere exactamente uno; `--email` no distingue mayúsculas de minúsculas). Solicita confirmación antes de realizar el cambio. El usuario puede entonces iniciar sesión solo con su contraseña e inscribirse de nuevo.

   Este es un comando de shell, por lo que requiere acceso al contenedor o host de DefectDojo. No existe un botón equivalente en la interfaz ni un endpoint en la API. En **DefectDojo Cloud**, comuníquese con [Soporte de DefectDojo](mailto:support@defectdojo.com) para que lo ejecuten.

Crear una cuenta de reemplazo **no** es necesario — eliminar la MFA conserva los permisos, el historial y las asignaciones existentes del usuario.

## MFA y la API

Cuando un usuario tiene la MFA habilitada, las solicitudes a `/api/v2/api-token-auth/` — el endpoint que intercambia un nombre de usuario y contraseña por un token de API — también deben incluir un código de MFA, en un campo `mfa_code` junto con las credenciales. Se acepta tanto un código TOTP vigente como un código de recuperación sin usar; pasar un código de recuperación aquí lo **consume**.

Un código faltante o incorrecto devuelve el mismo error genérico *"Unable to log in with provided credentials"* que una contraseña incorrecta, por lo que, si las solicitudes de token empiezan a fallar después de que un usuario habilita la MFA, esto es lo primero que hay que verificar.

**Los tokens de API existentes siguen funcionando.** Habilitar o deshabilitar la MFA no revoca ni rota los tokens ya emitidos — la verificación de MFA se aplica cuando se emite un token, no en cada solicitud realizada con él. La automatización de larga duración que ya posee un token no se ve afectada porque un usuario se inscriba en la MFA.
