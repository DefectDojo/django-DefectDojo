---
title: El menú de configuración
description: Cómo está organizada la sección Settings de la barra lateral de DefectDojo
  Pro, la página de directorio All Settings, y cómo cambiar entre el diseño actual
  y el anterior
weight: 6
audience: pro
---

La sección Settings de la barra lateral agrupa todas las páginas administrativas de DefectDojo Pro. El diseño que vea depende de cuándo se creó su instancia:

- **Las instalaciones nuevas** se abren con el diseño reorganizado que se describe a continuación.
- **Las instalaciones existentes** mantienen el diseño anterior hasta que un administrador active **Menu 2.0** (consulte [Cambiar de diseño](#switching-layouts)).

De cualquier manera, **cada página de configuración conserva la misma URL**. Los marcadores, enlaces guardados y cualquier elemento de sus propios runbooks siguen funcionando sin importar qué diseño esté activo.

## El diseño reorganizado

Settings se divide en siete grupos, nombrados según lo que se intenta hacer, en lugar de según la parte del sistema involucrada.

| Grupo | Qué contiene |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, E-mail, Feature Flags |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | Las tres páginas de Deduplication, Finding Enrichment, Service Level Agreements, Prioritization Engines, Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status, y — en DefectDojo Cloud — Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

Solo verá las entradas para las que su cuenta tiene permiso de acceso, y un grupo desaparece por completo cuando ninguna de sus páginas está disponible para usted.

Vale la pena conocer dos convenciones:

- **No hay entradas "New" independientes.** Cada página de listado tiene un botón **New** que abre el formulario de creación, por lo que el menú lleva una entrada por catálogo en lugar de dos. Si su cuenta puede crear un registro pero no listarlos, la entrada del menú lo lleva directamente al formulario de creación.
- **Nada se anida más de un nivel por debajo de un grupo.** Llegar a una página es como máximo Settings → grupo → página.

## All Settings

La primera entrada de la sección, **All Settings**, abre un directorio de todas las páginas de configuración a las que su cuenta puede acceder, organizadas en los mismos grupos que el menú y con posibilidad de búsqueda por nombre o por lo que hace la página. Buscar `deduplication` encuentra las tres páginas de deduplicación *y* System Settings, porque System Settings también contiene opciones de deduplicación.

La última categoría, **Elsewhere in the app**, enumera páginas que configuran DefectDojo pero que residen en otras secciones de la barra lateral — los proveedores de autorización, la configuración de Login y MFA, las instancias de Jira, los conectores Upstream y Downstream, y el Universal Parser. Cada mosaico lleva una etiqueta con la sección a la que pertenece.

## Qué cambió de lugar

Si está acostumbrado al diseño anterior:

| Antes | Ahora |
| --- | --- |
| Settings → *(nivel superior)* → Feature Flags | Settings → System → Feature Flags |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → E-mail Settings | Settings → System → E-mail |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(tres páginas)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(catálogos de datos de referencia)* | Settings → Configuration → *(sin cambios)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(páginas de cloud)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

El grupo que llevaba el nombre de su paquete de licencia — **Pro Settings** en una instancia Pro, **Enterprise Settings** en una Enterprise — ya no existe. Sus páginas se distribuyen entre System, Finding Workflow, Notifications y Operations.

## Cambiar de diseño

**Menu 2.0** en la página [Feature Flags](/admin/feature_flags/pro__feature_flags/) controla qué diseño está activo. Activarlo o desactivarlo reorganiza la barra lateral de inmediato; no se necesita reiniciar y ningún otro aspecto de su instancia cambia.

Las instalaciones nuevas comienzan con esta opción activada. Las instalaciones existentes comienzan con ella desactivada, de modo que una actualización nunca reorganiza el menú debajo de un equipo en pleno trabajo — actívela cuando sus administradores estén listos.

Mientras esté desactivada, la página **All Settings** no está disponible y su URL devuelve Not Found.
