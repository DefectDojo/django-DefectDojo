---
title: Restablecimiento masivo de credenciales de usuario
description: Rote tokens de API y fuerce el restablecimiento de contraseña de muchos
  usuarios a la vez desde la lista de Usuarios
audience: pro
weight: 2
---

La lista de **Usuarios** de DefectDojo Pro le permite rotar tokens de API y forzar el restablecimiento de contraseña de muchos usuarios a la vez, lo que resulta útil para la higiene periódica de credenciales o para responder ante una posible exposición de credenciales.

Estas acciones masivas solo están disponibles para **Superusuarios** y usuarios con el rol de **Global Owner**. Si no cuenta con ninguno de estos, las casillas de selección y los botones de acciones masivas no aparecerán.

## Seleccionar usuarios

En la lista de **Usuarios**, use las casillas de verificación para seleccionar uno o más usuarios. Aparecerá una barra de acciones masivas con los botones de restablecimiento. Cada acción le pedirá confirmación en un cuadro de diálogo antes de ejecutarse.

La acción se aplica a los usuarios que haya marcado explícitamente. **No puede incluir su propia cuenta** en un restablecimiento masivo: si su cuenta está entre las filas seleccionadas, los botones de acciones masivas se deshabilitan y se muestra una advertencia.

## Restablecer tokens de API

**Restablecer tokens de API** rota el token de API de cada usuario seleccionado: DefectDojo elimina el token existente del usuario y emite uno nuevo. **El token actual del usuario deja de funcionar de inmediato**, por lo que cualquier script o integración que use el token anterior debe actualizarse con el nuevo.

* Los nuevos valores de token **no** se muestran al administrador. Cada usuario afectado recibe una notificación de **"API Token Reset"** que le indica que debe obtener su nuevo token desde la interfaz (entregada según la configuración de notificaciones de ese usuario).

## Forzar restablecimiento de contraseña

**Forzar restablecimiento de contraseña** activa el indicador *force-password-reset-on-next-login* en cada usuario seleccionado. La próxima vez que ese usuario realice una solicitud, DefectDojo lo redirigirá a la página **Change Password** y no le permitirá continuar hasta que establezca una nueva contraseña. El indicador se borra automáticamente una vez que lo hace.

Tenga en cuenta lo que esta acción **no** hace:

* **No** establece ni genera aleatoriamente una contraseña temporal, y **no** le devuelve ninguna credencial.
* **No** envía a los usuarios afectados ningún correo electrónico ni notificación. Dado que no hay aviso automático, informe a los usuarios afectados por otro medio de que se les pedirá cambiar su contraseña en el próximo inicio de sesión.

> **Usuarios SSO:** A diferencia del formulario de edición de un solo usuario (que deshabilita el indicador de restablecimiento forzoso para las cuentas autorizadas mediante SSO), la acción masiva aplica el indicador a **todos** los usuarios seleccionados, sin importar cómo se autentiquen. Dado que los usuarios SSO inician sesión a través de su Proveedor de Identidad en lugar de una contraseña de DefectDojo, forzar un restablecimiento de contraseña en ellos generalmente carece de sentido; evite incluir en la selección a usuarios exclusivamente SSO.
