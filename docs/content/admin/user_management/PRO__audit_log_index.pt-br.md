---
title: Log de Auditoria
description: Toda ação de criação, atualização e exclusão que o DefectDojo registra
  no seu log de auditoria, além do que é capturado e como configurar a retenção.
draft: false
weight: 4
---

O DefectDojo registra uma trilha de auditoria das alterações em seus dados.  Todo objeto rastreado
registra automaticamente eventos de **criação**, **atualização** e **exclusão**, e as tabelas de relacionamento
(muitos-para-muitos) registram eventos de **adição** e **remoção**.

## Como funciona

O rastreamento de auditoria é conduzido por triggers de banco de dados registrados por modelo. Para cada
objeto rastreado, três tipos de evento podem ser disparados:

| Tipo de evento    | Quando é disparado                                                                 | Ação     |
| ------------- | ----------------------------------------------------------------------------- | ---------- |
| `InsertEvent` | Um novo registro é criado                                                        | **Criação** |
| `UpdateEvent` | Um registro é alterado — apenas quando o valor de um campo realmente muda               | **Atualização** |
| `DeleteEvent` | Um registro é excluído                                                            | **Exclusão** |

As tabelas de relacionamento muitos-para-muitos (tags, revisores, faixas de IP do firewall) rastreiam
apenas **adição** (`InsertEvent`) e **remoção** (`DeleteEvent`) — não existe
"atualização" para uma linha de relacionamento.

### O que é capturado em cada evento

- **Quem** — o usuário que executou a ação, obtido do contexto da requisição.
- **Quando** — um timestamp.
- **IP de origem** — o endereço remoto, respeitando as cadeias de proxy `X-Forwarded-For`.
- **Snapshot antes/depois** — os valores completos dos campos do registro.
- **Contexto / rótulo** — agrupa eventos originados da mesma requisição. O rótulo
  `initial_backfill` marca registros históricos importados quando o rastreamento foi
  ativado pela primeira vez.

Eventos produzidos por jobs em segundo plano são reconectados ao contexto da
requisição de origem, de modo que uma ação concluída de forma assíncrona ainda é
atribuída ao usuário que a disparou.

## Core (Open Source) — ações rastreadas

| Objeto                         | Criação | Atualização | Exclusão | Notas                                          |
| ------------------------------ | :----: | :----: | :----: | ---------------------------------------------- |
| Usuário                        |   ✅   |   ✅   |   ✅   | `password` excluído dos snapshots             |
| Tipo de Produto                |   ✅   |   ✅   |   ✅   |                                                |
| Produto                        |   ✅   |   ✅   |   ✅   |                                                |
| Engajamento                    |   ✅   |   ✅   |   ✅   |                                                |
| Teste                          |   ✅   |   ✅   |   ✅   |                                                |
| Achado                         |   ✅   |   ✅   |   ✅   |                                                |
| Grupo de Achados               |   ✅   |   ✅   |   ✅   |                                                |
| Modelo de Achado               |   ✅   |   ✅   |   ✅   |                                                |
| Aceitação de risco             |   ✅   |   ✅   |   ✅   |                                                |
| Endpoint                       |   ✅   |   ✅   |   ✅   |                                                |
| Localização                    |   ✅   |   ✅   |   ✅   |                                                |
| URL                            |   ✅   |   ✅   |   ✅   |                                                |
| Webhook de Notificação         |   ✅   |   ✅   |   ✅   | `header_name` / `header_value` excluídos (segredos) |

### Core — eventos de relacionamento (adição / remoção)

| Relacionamento                     | Adição | Remoção |
| ---------------------------------- | :-: | :----: |
| Achado → Revisores                 | ✅  |   ✅   |
| Achado → Tags                      | ✅  |   ✅   |
| Achado → Tags Herdadas             | ✅  |   ✅   |
| Produto → Tags                     | ✅  |   ✅   |
| Engajamento → Tags                 | ✅  |   ✅   |
| Engajamento → Tags Herdadas        | ✅  |   ✅   |
| Teste → Tags                       | ✅  |   ✅   |
| Teste → Tags Herdadas              | ✅  |   ✅   |
| Endpoint → Tags                    | ✅  |   ✅   |
| Endpoint → Tags Herdadas           | ✅  |   ✅   |
| Modelo de Achado → Tags            | ✅  |   ✅   |
| App Analysis (Tecnologia) → Tags   | ✅  |   ✅   |
| Objects/Product → Tags             | ✅  |   ✅   |

## Pro — ações rastreadas

| Objeto                            | Criação | Atualização | Exclusão | Notas                          |
| --------------------------------- | :----: | :----: | :----: | ------------------------------ |
| Achado Aprimorado                 |   ✅   |   ✅   |   ✅   | Complemento Pro do Achado      |
| Regra                              |   ✅   |   ✅   |   ✅   | Mecanismo de regras            |
| Ação de Regra                     |   ✅   |   ✅   |   ✅   |                                |
| Condição de Ação de Regra          |   ✅   |   ✅   |   ✅   |                                |
| Entrada de Filtro de Regra        |   ✅   |   ✅   |   ✅   |                                |
| Operação do Mecanismo de Regras   |   ✅   |   ✅   |   ✅   |                                |
| Mensagem de Operação do Mecanismo de Regras |   ✅   |   ✅   |   ✅   |                       |
| Tarefa Agendada                   |   ✅   |   ✅   |   ✅   |                                |
| Execução de Tarefa Agendada       |   ✅   |   ✅   |   ✅   |                                |
| Política de Mitigação             |   ✅   |   ✅   |   ✅   |                                |
| Configuração Ajustável            |   ✅   |   ✅   |   ✅   | Alterações de configuração do sistema |
| Estado do Feature Flag            |   ✅   |   ✅   |   ✅   | Ativação/desativação de flags + fixações do sistema |
| Definição do Feature Flag         |   ✅   |   ✅   |   ✅   | Metadados / sincronização de registro |
| Firewall de Nuvem                 |   ✅   |   ✅   |   ✅   | Campo `locked` excluído        |
| Máscara de IP do Firewall         |   ✅   |   ✅   |   ✅   |                                |

### Pro — RBAC / permissões

| Objeto                        | Criação | Atualização | Exclusão |
| ----------------------------- | :----: | :----: | :----: |
| Grupo                         |   ✅   |   ✅   |   ✅   |
| Papel                         |   ✅   |   ✅   |   ✅   |
| Associação a Grupo            |   ✅   |   ✅   |   ✅   |
| Papel Global                  |   ✅   |   ✅   |   ✅   |
| Atribuição de Grupo a Produto |   ✅   |   ✅   |   ✅   |
| Atribuição de Grupo a Tipo de Produto |   ✅   |   ✅   |   ✅   |
| Membro do Produto             |   ✅   |   ✅   |   ✅   |
| Membro do Tipo de Produto     |   ✅   |   ✅   |   ✅   |

### Pro — eventos de relacionamento (adição / remoção)

| Relacionamento              | Adição | Remoção |
| --------------------------- | :-: | :----: |
| Firewall de Nuvem → Faixas de IP  | ✅  |   ✅   |

## Configuração e retenção (Controles On-Premise)

| Configuração              | Variável de ambiente                  | Padrão            | Efeito                                                              |
| -------------------- | ------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Ativar log de auditoria | `DD_ENABLE_AUDITLOG`                  | `True`             | Quando definido como `False`, todos os triggers de histórico são desativados e nenhum evento é registrado |
| Período de retenção     | `DD_AUDITLOG_FLUSH_RETENTION_PERIOD`  | `-1` (nunca limpa) | Meses de histórico a manter; eventos mais antigos são excluídos em lotes pelo job de limpeza  |
| Tamanho do lote de limpeza     | `DD_AUDITLOG_FLUSH_BATCH_SIZE`        | `1000`             | Linhas excluídas por lote durante a limpeza                              |
| Máximo de lotes de limpeza    | `DD_AUDITLOG_FLUSH_MAX_BATCHES`       | `100`              | Limite do número de lotes por execução de limpeza                        |

## Observações e limitações

- **Segredos nunca são capturados.** As senhas de usuário e os valores de cabeçalho dos webhooks de notificação
  são explicitamente excluídos dos snapshots de eventos.
- **As atualizações só são registradas quando há uma mudança real.** Um salvamento que não altera nenhum
  valor de campo não gera um evento de atualização; campos gerenciados automaticamente, como
  `last_updated` isoladamente, não disparam um evento.
- **Eventos de autenticação não são capturados aqui.** Apenas
  mudanças de dados. As atividades de login, logout e tentativas de login malsucedidas são tratadas separadamente e não fazem parte deste log de auditoria.
