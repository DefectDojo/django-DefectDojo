---
title: Webhooks de notificação
description: Envie notificações de webhook HTTP para um servidor externo em eventos
  do DefectDojo
weight: 8
audience: opensource
aliases:
- /pt-br/en/open_source/notification_webhooks/how_to
---

**Este é um recurso experimental do Open Source — o comportamento pode mudar em versões futuras.**

Webhooks são requisições HTTP de saída enviadas da sua instância do DefectDojo para um servidor definido pelo usuário sempre que ocorrem eventos específicos. 

## Configuração

Os endpoints de webhook são configurados por administradores. Quando um webhook é criado, o DefectDojo envia um evento [`ping`](#ping) para verificar se o endpoint está acessível e retornando o código de status esperado.

## Transições de estado do endpoint

O DefectDojo monitora o sucesso das entregas e desabilitará um endpoint temporária ou permanentemente com base em respostas HTTP ou falhas de rede. A reativação manual por um administrador também é possível.

- **Estados em formato de estádio**: Ativo — webhooks podem ser enviados
- **Estados em formato de retângulo**: Inativo — a entrega do webhook falhará e não será repetida
- **Transições motivadas por**: respostas HTTP do servidor de destino, automação do celery, ou ação manual de um administrador

## Cabeçalhos da requisição

Toda requisição de webhook inclui os seguintes cabeçalhos:

```yaml
User-Agent: DefectDojo-<version>
X-DefectDojo-Event: <event_name>
X-DefectDojo-Instance: <base_url_of_dd_instance>
```

## Eventos

### product_type_added

Disparado quando um novo Tipo de Produto é criado.

**Cabeçalho:**
```yaml
X-DefectDojo-Event: product_type_added
```

**Corpo:**
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

Disparado quando um novo Produto é criado.

**Cabeçalho:**
```yaml
X-DefectDojo-Event: product_added
```

**Corpo:**
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

Disparado quando um novo Engajamento é criado.

**Cabeçalho:**
```yaml
X-DefectDojo-Event: engagement_added
```

**Corpo:**
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

Disparado quando um novo Teste é criado.

**Cabeçalho:**
```yaml
X-DefectDojo-Event: test_added
```

**Corpo:**
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

Disparado quando um scan é importado ou reimportado. `scan_added_empty` é disparado quando uma reimportação não resulta em nenhuma alteração (nenhum achado criado ou fechado).

**Cabeçalhos:**
```yaml
X-DefectDojo-Event: scan_added
```
```yaml
X-DefectDojo-Event: scan_added_empty
```

**Corpo:**
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

Enviado durante a configuração do webhook para verificar se o endpoint está acessível.

**Cabeçalho:**
```yaml
X-DefectDojo-Event: ping
```

**Corpo:**
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

## Roteiro

Melhorias planejadas conhecidas:

- Eventos relacionados a SLA (ainda não suportado)
- Webhooks definidos pelo usuário (atualmente restrito a administradores)
- UI aprimorada com filtragem e paginação para endpoints de webhook
