---
title: Webhooks de notification
description: Envoyer des notifications webhook HTTP vers un serveur externe lors d'événements
  DefectDojo
weight: 8
audience: opensource
aliases:
- /fr/en/open_source/notification_webhooks/how_to
---

**Il s'agit d'une fonctionnalité Open Source expérimentale — son comportement peut évoluer dans les prochaines versions.**

Les webhooks sont des requêtes HTTP sortantes envoyées depuis votre instance DefectDojo vers un serveur défini par l'utilisateur lorsque certains événements se produisent.

## Setup

Les endpoints de webhook sont configurés par les administrateurs. Lors de la création d'un webhook, DefectDojo envoie un événement [`ping`](#ping) pour vérifier que l'endpoint est accessible et renvoie le code de statut attendu.

## Endpoint State Transitions

DefectDojo surveille le succès des livraisons et désactive temporairement ou définitivement un endpoint en fonction des réponses HTTP ou des échecs réseau. Une réactivation manuelle par un administrateur reste également possible.

- **États en forme de stade** : Active — les webhooks peuvent être envoyés
- **États en forme de rectangle** : Inactive — la livraison du webhook échoue et n'est pas retentée
- **Transitions déclenchées par** : les réponses HTTP du serveur cible, l'automatisation celery, ou une action manuelle de l'administrateur

## Request Headers

Chaque requête webhook inclut les en-têtes suivants :

```yaml
User-Agent: DefectDojo-<version>
X-DefectDojo-Event: <event_name>
X-DefectDojo-Instance: <base_url_of_dd_instance>
```

## Events

### product_type_added

Déclenché lors de la création d'un nouveau Type de produit.

**Header:**
```yaml
X-DefectDojo-Event: product_type_added
```

**Body:**
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

Déclenché lors de la création d'un nouveau Produit.

**Header:**
```yaml
X-DefectDojo-Event: product_added
```

**Body:**
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

Déclenché lors de la création d'un nouvel Engagement.

**Header:**
```yaml
X-DefectDojo-Event: engagement_added
```

**Body:**
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

Déclenché lors de la création d'un nouveau Test.

**Header:**
```yaml
X-DefectDojo-Event: test_added
```

**Body:**
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

Déclenché lorsqu'un scan est importé ou réimporté. `scan_added_empty` se déclenche lorsqu'un réimport n'entraîne aucun changement (aucune constatation créée ou clôturée).

**Headers:**
```yaml
X-DefectDojo-Event: scan_added
```
```yaml
X-DefectDojo-Event: scan_added_empty
```

**Body:**
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

Envoyé lors de la configuration du webhook pour vérifier que l'endpoint est accessible.

**Header:**
```yaml
X-DefectDojo-Event: ping
```

**Body:**
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

Améliorations prévues connues :

- Événements liés aux SLA (non encore pris en charge)
- Webhooks définis par l'utilisateur (actuellement réservés aux administrateurs)
- UI améliorée avec filtrage et pagination pour les endpoints de webhook
