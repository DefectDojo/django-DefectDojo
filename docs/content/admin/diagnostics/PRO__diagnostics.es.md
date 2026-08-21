---
title: Diagnósticos
description: 'Consulte el registro entre subsistemas de los intentos de integración:
  qué se registra, cómo filtrarlo, cómo se excluyen las credenciales y quién puede
  ver el detalle técnico'
weight: 1
audience: pro
---

Diagnósticos es un único registro de todos los intentos que DefectDojo realiza para comunicarse con algo externo a sí mismo, y de los intentos que otros sistemas realizan para comunicarse con él. Cuando un ticket nunca aparece, un escaneo nunca se importa o un usuario no puede iniciar sesión, esta es la página que indica qué ocurrió, cuándo, en qué configuración y quién lo originó.

Diagnósticos es una función de **DefectDojo Pro**. Se encuentra en **Conectar > Diagnósticos**.

![El registro de Diagnósticos, vista de Errores](images/diagnostics_errors.png)

## Qué se registra

Se escribe una fila por cada intento, proveniente de cada subsistema que se comunica fuera de DefectDojo:

| Origen | Qué genera las filas |
| --- | --- |
| **Conector** | Ejecuciones de descubrimiento y sincronización de conectores ascendentes |
| **Integrador descendente** | Envíos a Jira, GitHub, GitLab, ServiceNow y los demás conectores descendentes |
| **Jira** | La integración heredada de Jira: envíos, comentarios y vistas previas |
| **SSO (OIDC/OAuth2)** | Intentos de inicio de sesión a través de un proveedor OAuth |
| **SAML** | Aserciones SAML, incluidos los fallos de firma y de atributos |
| **LDAP** | Enlaces (binds) y búsquedas LDAP |
| **Importar / Reimportar** | Cargas de escaneos, ya sea por la interfaz, la API o programación |
| **Motor de reglas** | Evaluaciones de reglas y las acciones que intentan |
| **Programación** | Ejecuciones programadas, incluidas las que nunca comenzaron |
| **Sensei** | Escaneos de repositorios y ejecuciones de corrección |
| **Notificación** | Envío de notificaciones salientes |
| **Sistema** | Actividad a nivel de instancia que no pertenece a ningún producto |

Las filas se escriben *junto al* subsistema, nunca en su lugar. Cada adaptador está vinculado al registro de origen y se diseñó deliberadamente para no generar fallos: si al escribir una fila de diagnóstico se produce un error, este se absorbe y la operación original continúa. Por lo tanto, Diagnósticos nunca puede ser la causa de que falle un envío, una importación o un inicio de sesión.

Dado que las filas se indexan según el registro que las generó, volver a guardar un registro de origen actualiza su fila de diagnóstico existente en lugar de agregar un duplicado. Un intento es una fila durante toda su vida, desde `Queued`, pasando por `Running`, hasta su resultado.

### Campos de una fila

| Campo | Significado |
| --- | --- |
| **Cuándo** | Cuándo se registró la fila; **Iniciado**, **Finalizado** y **Duración** describen el intento en sí |
| **Origen** | El subsistema, según la tabla anterior |
| **Proveedor** | La herramienta o proveedor específico dentro de ese origen (`jira`, `github`, `okta`, el nombre de un scanner) |
| **Operación** | Qué se intentó (`push`, `sync`, `login`, `reimport`, `rule_run`) |
| **Estado** | `Queued`, `Running`, `Success`, `Failed`, `Timed out`, `Skipped` o `Dry run` |
| **Severidad** | `Info`, `Warning`, `Error` o `Critical` |
| **Resumen** | Un resultado de una línea, seguro de leer de un vistazo |
| **Activador** | Qué originó el intento: `UI`, `API`, `Scheduled`, `Webhook`, `Automatic`, `Command line` o `System` |
| **Activado por** | El usuario responsable, o `System` para trabajos no supervisados |
| **Activo** | El producto al que pertenece el intento; vacío significa a nivel de instancia |
| **Objeto relacionado** | El hallazgo, compromiso u otro registro con el que se relacionaba el intento |
| **Configuración** | Qué configuración se usó, por su etiqueta |
| **Referencia externa** | El identificador que devolvió el otro sistema, como una clave de incidencia creada |
| **ID de correlación** | Vincula las filas de una misma operación lógica |
| **Detalle notificado** y **Contexto** | El detalle técnico completo (restringido, ver [Quién ve qué](#who-sees-what)) |

## Las cuatro vistas

Las pestañas sobre la tabla son puntos de partida guardados, no filtros que deba reconstruir:

* **Errores**: fallas y tiempos de espera agotados. La primera que conviene abrir.
* **Éxitos**: prueba de que una integración que funciona, efectivamente funciona; útil cuando alguien informa que "nada se está sincronizando".
* **Nunca completados**: intentos que siguen en `Queued` o `Running` mucho después de cuando deberían haber terminado. Son los silenciosos: nada falló, así que nada se informó, pero tampoco llegó nada.
* **Todos los eventos**: todo, sin filtrar.

![Todos los eventos, mostrando cada origen](images/diagnostics_all_events.png)

La vista activa forma parte de la URL de la página, por lo que se puede enlazar y sobrevive a una actualización de la página.

## Acotar la lista

* **Rango de tiempo** — 24 horas, 7 días, 30 días o 90 días, desde los botones del encabezado.
* **Recuentos por origen** — los recuentos con color debajo de las tarjetas de resumen también funcionan como filtros rápidos. Haga clic en uno para mostrar solo ese origen; vuelva a hacer clic (o en **Clear source filter**) para volver atrás. Solo uno, o ninguno, puede estar activo a la vez.
* **Filtros y ordenamiento por columna** — todas las columnas permiten filtrar y ordenar, incluidas Severidad y Origen. Severidad ordena por gravedad (`Critical` → `Info`) en lugar de alfabéticamente, y Origen ordena por la etiqueta que se ve en pantalla y no por el valor almacenado internamente.
* **Búsqueda por palabra clave** — busca en todos los campos de texto a la vez.
* **Preferencias de columnas** — el selector de columnas y sus diseños guardados se comportan igual que en el resto de las listas de Pro.

![Un recuento de origen usado como filtro rápido](images/diagnostics_chip_filter.png)

Haga clic en la lupa al comienzo de una fila para abrir el intento completo:

![Un solo evento, incluido el aviso de redacción](images/diagnostics_detail.png)

## Las credenciales se eliminan antes de escribir la fila

Los errores de integración citan la solicitud que falló, y esas citas contienen secretos: un encabezado `Authorization`, un token en una cadena de consulta, una contraseña dentro de una URL de conexión. Diagnósticos los elimina **al momento de ingresar**, de modo que el valor original nunca llega a la base de datos y ningún cambio de opinión posterior puede exponerlo.

Se depuran dos cosas:

* **Valores bajo claves con forma de credencial** — todo aquello cuya clave parezca un secreto (`password`, `token`, `secret`, `api_key`, `authorization`, `private_key` y similares, con cualquier capitalización o con guiones o espacios). Un pequeño conjunto de claves está exento porque solo importa su *presencia*, nunca su contenido.
* **Valores que parecen credenciales dondequiera que aparezcan** — encabezados de autorización bearer y basic, JWT, credenciales incrustadas en URL (`https://user:pass@host`), prefijos de token de proveedores reconocibles y bloques PEM.

Cada uno se reemplaza con `[redacted]`. El mensaje circundante se conserva, de modo que el error sigue siendo legible:

```text
401 Unauthorized: Authorization: [redacted]
upload rejected: https://svc:[redacted]@sftp.example/out/…
```

Los valores largos se truncan y el contexto muy anidado se aplana, de modo que una carga útil enorme no puede inflar la tabla.

Cuando se elimina algo de una fila, la fila lo indica, en lugar de dejarlo preguntándose si el campo estaba vacío o fue vaciado.

> **La redacción es un esfuerzo razonable por diseño.** El depurador reconoce *formas* de credenciales. Un secreto que parece prosa común, bajo una clave que no se lee como sensible, aún puede quedar registrado. Trate Diagnósticos como un registro operativo, no como un lugar donde se garantiza la ausencia de secretos, y mantenga el detalle técnico restringido a las personas que lo necesitan.

## Quién ve qué

Diagnósticos está organizado por niveles, porque el resumen de una falla es útil para el propietario de un producto, mientras que la solicitud sin procesar detrás de ella no lo es.

| | Superusuario | Todos los demás |
| --- | --- | --- |
| Filas de los productos en los que están autorizados | Sí | Sí |
| Filas a nivel de instancia (sin producto) | Sí | No |
| Resumen, origen, estado, severidad, tiempos, configuración | Sí | Sí |
| **Detalle notificado**, **Contexto**, **IP remota** | Sí | Se oculta, y se etiqueta como oculto |

Un usuario que no es superusuario ve que un detalle existe y está siendo ocultado, en lugar de un campo vacío que parece un dato faltante. Las filas a nivel de instancia — SSO, SAML, LDAP y otra actividad que no pertenece a ningún producto — son exclusivas de superusuarios, ya que no existe una membresía de producto que pudiera otorgar acceso a ellas.

## Cuánto tiempo se conservan los registros

Una tarea programada recorta el registro para que no pueda crecer sin límite:

| Severidad | Se conserva durante |
| --- | --- |
| `Info` | 30 días |
| `Warning`, `Error`, `Critical` | 180 días |

Ambos períodos se pueden configurar con los ajustes `DIAGNOSTIC_EVENT_INFO_RETENTION_DAYS` y `DIAGNOSTIC_EVENT_RETENTION_DAYS`. La eliminación se ejecuta por lotes, de modo que una purga grande no mantiene abierta una transacción larga.

## API

El registro es de solo lectura a través de la API, en `/api/v2/diagnostic_events/`:

| Endpoint | Devuelve |
| --- | --- |
| `GET /api/v2/diagnostic_events/` | La lista, con los filtros descritos a continuación |
| `GET /api/v2/diagnostic_events/{id}/` | Un evento |
| `GET /api/v2/diagnostic_events/summary/` | Los recuentos detrás de las tarjetas del encabezado, incluidos los totales por origen |
| `GET /api/v2/diagnostic_events/choices/` | Los valores válidos para `source`, `status`, `severity` y `trigger` |

Parámetros útiles:

| Parámetro | Efecto |
| --- | --- |
| `source`, `status`, `severity`, `trigger` | Aceptan varios valores separados por comas a la vez |
| `failures_only=true` | Fallas y tiempos de espera agotados |
| `unresolved_only=true` | Intentos que aún están en cola o en ejecución |
| `product_name` | Filtrar por nombre de producto |
| `object_model` | Filtrar por el tipo de registro con el que se relacionaba el intento |
| `o=` | Ordenamiento, con el prefijo `-` para invertir (`o=-created_at`) |

Se aplican las mismas reglas de acceso: un usuario que no es superusuario obtiene filas limitadas a sus productos, con los campos restringidos ocultos.

## Cómo averiguar qué salió mal

* **Un ticket nunca apareció.** Filtre Origen por el integrador (o Jira) y luego lea Estado. `Failed` le da el motivo en Resumen; `Queued` mucho después del hecho significa que el trabajo nunca se ejecutó, lo cual es un problema de worker o de programación, no de credenciales.
* **Un usuario no puede iniciar sesión.** Filtre Origen por SSO, SAML o LDAP, y lea el fallo de su intento — una firma de aserción incorrecta, un bind rechazado, un atributo no coincidente. Estas filas son a nivel de instancia, por lo que son exclusivas de superusuarios.
* **Un escaneo no apareció.** Filtre Origen por Importar / Reimportar. Observe Activador para distinguir una carga programada no supervisada de una manual, y Activado por para saber a quién preguntar.
* **Algo sigue reintentando sin parar.** Ordene por ID de correlación, o filtre por uno, para ver juntos todos los intentos de la misma operación lógica.
* **"Nada funciona."** Abra primero Éxitos para la misma ventana de tiempo. Una lista saludable allí convierte una interrupción vaga en una específica.

## Relacionado

* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — activar y desactivar funciones opcionales de Pro
* [Conectores](/connectors/upstream/about/) — para incorporar hallazgos
* [Integraciones Pro](/connectors/downstream/about/) — para enviar hallazgos
* [Inicio de sesión único](/admin/sso/) — los proveedores de identidad cuyos intentos de inicio de sesión aparecen aquí
