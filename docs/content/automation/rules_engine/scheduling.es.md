---
title: Programación de Reglas
description: Ejecutar automáticamente las reglas de Rules Engine según una programación
  recurrente o única
weight: 2
audience: pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: la programación de Rules Engine es una función exclusiva de DefectDojo Pro.</span>

Las Reglas se pueden programar para ejecutarse automáticamente en lugar de activarse manualmente cada vez.  Una regla programada se ejecutará contra todos los Hallazgos que coincidan con sus condiciones de filtro en el momento configurado.

La programación está desactivada de forma predeterminada y DefectDojo la habilita por instancia, en lugar de hacerlo desde la página de Feature Flags. Contacte con [DefectDojo Support](mailto:support@defectdojo.com) para que se active el **Scheduling Service**; la opción **Schedule Rule** aparece una vez activado. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/) para ver cómo se muestran las funciones que DefectDojo gestiona de forma centralizada.

El usuario que configura la programación debe tener el permiso de configuración **Change Scheduling Service Schedule**.

## Schedule Types

### Single Run

Una programación de Single Run ejecuta la regla una vez en una fecha y hora específicas.  Después de que la ejecución se complete, la programación no se repite.

### Repeated Run

Una programación de Repeated Run permite activar una regla de forma recurrente — por ejemplo, todos los días a las 9:00 AM, o todos los lunes a las 15:00.

**Nota:** las programaciones de Rules Engine están limitadas a marcas de cuarto de hora.  El campo de minutos de una programación cron debe ser uno de: **0, 15, 30 o 45**.  No se permiten otros valores de minutos.

Ejemplos de programaciones válidas:
- Cada hora en punto: `0 * * * *`
- Todos los días a las 9:15 AM: `15 9 * * *`
- Todos los lunes a las 3:00 PM: `0 15 * * 1`
- Cada 15 minutos: `0,15,30,45 * * * *`

## Creating a Schedule for a Rule

1. Vaya a la página **All Rules** desde el menú **Rules Engine** en la barra lateral.
2. Busque la regla que quiere programar y abra su menú de acciones (**⋮**).
3. Haga clic en **Schedule Rule**.  Esta opción solo es visible si el Scheduling Service está habilitado y usted tiene el permiso requerido.
4. En el modal **Schedule Rule**, complete los siguientes campos:

| Field | Description |
|---|---|
| **Name** | Un nombre único para esta programación (obligatorio, máximo 100 caracteres). |
| **Description** | Descripción opcional del propósito de la programación. |
| **Trigger Type** | Elija **Single Run** para una ejecución única, o **Repeated Run** para una programación cron recurrente. |
| **Frequency** | Para Repeated Run: use el generador de cron para seleccionar el período (por hora, diario, semanal, etc.) y los valores específicos de minuto, hora y día. Para Single Run: seleccione una fecha y hora con el selector de fecha. |
| **Enable Schedule** | Active o desactive la programación con este control.  Una programación desactivada no se ejecutará hasta que se vuelva a activar. |

5. Haga clic en **Submit** para guardar la programación.  La regla se ejecutará automáticamente en el próximo horario programado.


## Permissions

El acceso a la programación dentro de Rules Engine requiere permisos de Superusuario o el Permiso de Configuración correspondiente.  Consulte [User Permission Chart](/admin/user_management/user_permission_chart) para más detalles.
