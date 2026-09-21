---
title: Endpoint Meta Importer
description: Aplique tags e campos personalizados a endpoints em massa via CSV
weight: 4
audience: opensource
---

O **Endpoint Meta Importer** permite aplicar tags e campos personalizados a um grande número de endpoints de uma só vez, usando um arquivo CSV. Isso é particularmente útil para organizações que executam scans intensivos de infraestrutura, onde os endpoints precisam de metadados flexíveis para filtragem, ordenação e geração de relatórios.

## Formato do CSV

O arquivo CSV deve ter uma coluna `hostname` (obrigatória), além de qualquer número de colunas adicionais representando as tags ou campos personalizados que você deseja aplicar. Cada nome de coluna adicional se torna a chave da tag/campo, e o valor da linha se torna o valor da tag/campo.

**Exemplo:**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

Isso aplicaria os seguintes metadados:

| Endpoint | Tags / Campos Personalizados |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## Requisitos

- A coluna `hostname` é **obrigatória**. Ela é usada para encontrar endpoints existentes com um host correspondente, ou para criar novos endpoints caso nenhuma correspondência seja encontrada.
- Todos os outros nomes de coluna são tratados como chaves de tag/campo personalizado.
- Os valores são armazenados no formato `key:value`.

## Usando o Endpoint Meta Importer

O Endpoint Meta Importer está disponível na aba **Endpoints** ao visualizar um Produto. Envie seu arquivo CSV lá para aplicar os metadados aos seus endpoints em massa.
