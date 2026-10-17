---
title: Crear un nuevo usuario
description: Cómo incorporar un nuevo usuario a su instancia de DefectDojo
audience: opensource
weight: 1
---

Esta página describe el flujo de trabajo de incorporación recomendado para agregar nuevos usuarios a una instancia de DefectDojo.  Los usuarios de DefectDojo se pueden usar tanto como cuentas estándar operadas por personas como cuentas de servicio.

El administrador que crea la cuenta es responsable de entregar las credenciales iniciales (nombre de usuario y contraseña) al nuevo usuario.

## Flujo de trabajo recomendado

1. **Cree la cuenta de usuario** en DefectDojo (solo superusuario):
   * Vaya a **👤 Usuarios → Usuarios** para abrir la tabla de Todos los usuarios.
   * Haga clic en el icono 🛠️ (llave y destornillador cruzados).
   * Ingrese el nombre y la dirección de correo electrónico del nuevo usuario.
   * Establezca una contraseña temporal.
   * Envíe el formulario.

2. **Otorgue acceso** según corresponda. Agregue al usuario a la lista de Usuarios autorizados de cada Activo u Organización que necesite, o márquelo como staff o superusuario. Consulte [Permisos de código abierto](../os__authorized_users/) para más detalles. Un nuevo usuario sin asignaciones no podrá ver ningún Activo ni Hallazgo.

3. **Envíe las credenciales al nuevo usuario por un canal externo** (por correo electrónico, la herramienta de chat de su equipo, o como normalmente comparta secretos). Incluya:
   * La URL de la instancia de DefectDojo.
   * El nombre de usuario (típicamente su dirección de correo electrónico).
   * La contraseña temporal que acaba de establecer.
   * Una nota indicando que deben cambiar la contraseña en el primer inicio de sesión.

4. **El nuevo usuario inicia sesión y rota la credencial.** Puede hacerlo de dos maneras:
   * Iniciar sesión con la contraseña temporal y luego cambiarla desde su menú de perfil, o
   * Usar el enlace **I forgot my password** en la página de inicio de sesión para establecer una contraseña directamente sin usar la temporal. La contraseña temporal sigue siendo necesaria para que exista el registro inicial de la cuenta, pero el usuario no necesita recordarla si usa el flujo de restablecimiento de contraseña.

## Usuarios que iniciaron sesión con SSO

DefectDojo de código abierto solo admite cuentas locales. SSO (SAML, OIDC, OAuth), LDAP y MFA están disponibles en [DefectDojo Pro](/admin/sso/).

Si actualizó a DefectDojo de código abierto 3.x y los usuarios SSO existentes ya no pueden iniciar sesión, consulte [Restablecer el inicio de sesión para usuarios SSO](../os__sso_user_local_login_fallback/).
