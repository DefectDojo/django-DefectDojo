---
title: Restablecer el inicio de sesión para usuarios SSO (código abierto)
description: Otorgar una contraseña local a los usuarios aprovisionados por SSO tras
  pasar a código abierto, donde SSO es una función exclusiva de Pro
audience: opensource
weight: 2
---

## Cuándo se aplica esto

SSO (SAML, OIDC, OAuth) es una función de [DefectDojo Pro](https://defectdojo.com). Si actualiza a DefectDojo de código abierto 3.x (o de otro modo deja de usar Pro), las opciones de inicio de sesión con SSO se eliminan, y los usuarios que fueron aprovisionados mediante SSO ya no pueden iniciar sesión. Sus cuentas nunca recibieron una contraseña local, y la interfaz y la API no le permitirán establecer una para ellos: DefectDojo los detecta como cuentas SSO y bloquea el cambio.

**No** necesita eliminar y volver a crear estos usuarios (lo cual haría perder su historial, permisos y propiedad de objetos). En su lugar, otorgue a cada cuenta una contraseña local en el backend y fuerce un restablecimiento de contraseña en el siguiente inicio de sesión.

Consulte la [sección de SSO](/admin/sso/) y las [notas de actualización de la 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only) para más contexto sobre por qué SSO es exclusivo de Pro.

## Por qué ocurre

DefectDojo de código abierto autentica únicamente contra la base de datos de usuarios local de Django. Decide si una cuenta es un "usuario SSO" únicamente en función de si la cuenta tiene una contraseña utilizable. Las cuentas aprovisionadas por SSO se crearon con una contraseña *no utilizable*, por lo que:

* el inicio de sesión local falla (no hay contraseña que verificar), y
* el control **Force password reset** de la interfaz y la API está bloqueado, con un mensaje de que el usuario está autorizado mediante SSO.

Establecer una contraseña real resuelve ambas condiciones a la vez: la cuenta puede iniciar sesión localmente, y el indicador de restablecimiento forzado se vuelve configurable.

## La solución alternativa

Ejecute estos pasos desde el shell de Django dentro del contenedor `uwsgi`:

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### Ejemplo para un solo usuario

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

## Qué hace el usuario a continuación

Entregue la contraseña temporal a cada usuario por un canal externo (correo electrónico, el chat de su equipo, o como normalmente comparta secretos). En su próximo inicio de sesión, DefectDojo los redirige a la página **Change Password** y no les permitirá ir a ningún otro lado hasta que establezcan su propia contraseña. El indicador de restablecimiento forzado se borra automáticamente una vez que lo hacen.

Si su instancia tiene habilitado el flujo "I forgot my password" (`DD_FORGOT_PASSWORD`, activado de forma predeterminada) y el correo electrónico configurado, los usuarios pueden en cambio usar el enlace **I forgot my password** en la página de inicio de sesión una vez que su cuenta tenga una contraseña utilizable, y establecer una contraseña sin necesitar la temporal.

## Notas

* **Kubernetes:** en su lugar, ejecute el shell en el pod de Django, por ejemplo `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell` (ajuste los nombres de deployment y contenedor a su versión).
* Elija una contraseña descartable y segura. Con `force_password_reset = True` el usuario no puede conservarla, así que solo necesita durar un inicio de sesión.
* Mantenga al menos una cuenta de administrador local funcional para no quedar nunca bloqueado.
