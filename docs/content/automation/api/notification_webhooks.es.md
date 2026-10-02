---
title: Webhooks de notificación
description: Envíe notificaciones de webhook HTTP a un servidor externo ante eventos
  de DefectDojo
weight: 8
audience: opensource
aliases:
- /es/en/open_source/notification_webhooks/how_to
---

**Esta es una función experimental de Open Source; su comportamiento puede cambiar en futuras versiones.**

Los webhooks son solicitudes HTTP salientes que se envían desde su instancia de DefectDojo a un servidor definido por el usuario cada vez que ocurren eventos específicos.

## Setup

Los endpoints de webhook los configuran los administradores. Cuando se crea un webhook, DefectDojo envía un evento [`ping`](#ping) para verificar que el endpoint sea accesible y devuelva el código de estado esperado.

## Endpoint State Transitions

DefectDojo supervisa el éxito de la entrega y deshabilitará un endpoint de forma temporal o permanente según las respuestas HTTP o los fallos de red. También es posible la reactivación manual por parte de un administrador.

- **Estados con forma de estadio**: Activo — se pueden enviar webhooks
- **Estados rectangulares**: Inactivo — la entrega de webhooks fallará y no se reintentará
- **Transiciones impulsadas por**: respuestas HTTP del servidor de destino, automatización de celery o acción manual de un administrador

## Request Headers

Cada solicitud de webhook incluye los siguientes encabezados:

```yaml
User-Agent: DefectDojo-<version>
X-DefectDojo-Event: <event_name>
X-DefectDojo-Instance: <base_url_of_dd_instance>
```

## Events

### product_type_added

Se dispara cuando se crea un nuevo Tipo de producto.

**Encabezado:**
```yaml
X-DefectDojo-Event: product_type_added
```

**Cuerpo:**
```json
{
    "description": "",
    "title": "",
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "url_api": "http://localhost:8080/api/v2/product_types/4/",
    "url_ui": "http://localhost:8080/product/type/4",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### product_added

Se dispara cuando se crea un nuevo Producto.

**Encabezado:**
```yaml
X-DefectDojo-Event: product_added
```

**Cuerpo:**
```json
{
    "description": "",
    "title": "",
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "url_api": "http://localhost:8080/api/v2/products/4/",
    "url_ui": "http://localhost:8080/product/4",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### engagement_added

Se dispara cuando se crea un nuevo Compromiso.

**Encabezado:**
```yaml
X-DefectDojo-Event: engagement_added
```

**Cuerpo:**
```json
{
    "description": "",
    "title": "",
    "engagement": {
        "id": 7,
        "name": "notif eng",
        "url_api": "http://localhost:8080/api/v2/engagements/7/",
        "url_ui": "http://localhost:8080/engagement/7"
    },
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "url_api": "http://localhost:8080/api/v2/engagements/7/",
    "url_ui": "http://localhost:8080/engagement/7",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### test_added

Se dispara cuando se crea un nuevo Test.

**Encabezado:**
```yaml
X-DefectDojo-Event: test_added
```

**Cuerpo:**
```json
{
    "description": "",
    "title": "",
    "engagement": {
        "id": 7,
        "name": "notif eng",
        "url_api": "http://localhost:8080/api/v2/engagements/7/",
        "url_ui": "http://localhost:8080/engagement/7"
    },
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "test": {
        "id": 90,
        "title": "notif test",
        "url_api": "http://localhost:8080/api/v2/tests/90/",
        "url_ui": "http://localhost:8080/test/90"
    },
    "url_api": "http://localhost:8080/api/v2/tests/90/",
    "url_ui": "http://localhost:8080/test/90",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### scan_added / scan_added_empty

Se dispara cuando se importa o reimporta un escaneo. `scan_added_empty` se dispara cuando una reimportación no produce cambios (no se crean ni cierran hallazgos).

**Encabezados:**
```yaml
X-DefectDojo-Event: scan_added
```
```yaml
X-DefectDojo-Event: scan_added_empty
```

**Cuerpo:**
```json
{
    "description": "",
    "title": "",
    "engagement": {
        "id": 7,
        "name": "notif eng",
        "url_api": "http://localhost:8080/api/v2/engagements/7/",
        "url_ui": "http://localhost:8080/engagement/7"
    },
    "finding_count": 4,
    "findings": {
        "mitigated": [
            {
                "id": 233,
                "severity": "Medium",
                "title": "Mitigated Finding",
                "url_api": "http://localhost:8080/api/v2/findings/233/",
                "url_ui": "http://localhost:8080/finding/233"
            }
        ],
        "new": [
            {
                "id": 232,
                "severity": "Critical",
                "title": "New Finding",
                "url_api": "http://localhost:8080/api/v2/findings/232/",
                "url_ui": "http://localhost:8080/finding/232"
            }
        ],
        "reactivated": [
            {
                "id": 234,
                "severity": "Low",
                "title": "Reactivated Finding",
                "url_api": "http://localhost:8080/api/v2/findings/234/",
                "url_ui": "http://localhost:8080/finding/234"
            }
        ],
        "untouched": [
            {
                "id": 235,
                "severity": "Info",
                "title": "Untouched Finding",
                "url_api": "http://localhost:8080/api/v2/findings/235/",
                "url_ui": "http://localhost:8080/finding/235"
            }
        ]
    },
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "test": {
        "id": 90,
        "title": "notif test",
        "url_api": "http://localhost:8080/api/v2/tests/90/",
        "url_ui": "http://localhost:8080/test/90"
    },
    "url_api": "http://localhost:8080/api/v2/tests/90/",
    "url_ui": "http://localhost:8080/test/90",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### ping

Se envía durante la configuración del webhook para verificar que el endpoint sea accesible.

**Encabezado:**
```yaml
X-DefectDojo-Event: ping
```

**Cuerpo:**
```json
{
    "description": "Test webhook notification",
    "title": "",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

## Roadmap

Mejoras planificadas conocidas:

- Eventos relacionados con SLA (aún no compatibles)
- Webhooks definidos por el usuario (actualmente solo para administradores)
- Interfaz mejorada con filtrado y paginación para los endpoints de webhook
