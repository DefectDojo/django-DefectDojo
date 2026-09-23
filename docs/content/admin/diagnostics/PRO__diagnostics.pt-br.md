---
title: Diagnósticos
description: 'Leia o registro entre subsistemas das tentativas de integração: o que
  é registrado, como filtrá-lo, como as credenciais são mantidas fora dele e quem
  pode ver o detalhe técnico'
weight: 1
audience: pro
---

Diagnósticos é um único registro de todas as tentativas que o DefectDojo faz para se comunicar com algo fora dele — e das tentativas que outros sistemas fazem para se comunicar com ele. Quando um ticket nunca aparece, um scan nunca é importado, ou um usuário não consegue fazer login, esta é a página que mostra o que aconteceu, quando, com qual configuração, e quem disparou a tentativa.

Diagnósticos é um recurso do **DefectDojo Pro**. Encontre-o em **Connect > Diagnostics**.

![The Diagnostics ledger, Errors view](images/diagnostics_errors.png)

## O que é registrado

Uma linha é gravada por tentativa, vinda de todo subsistema que se comunica para fora do DefectDojo:

| Fonte | O que gera linhas |
| --- | --- |
| **Connector** | Execuções de descoberta e sincronização dos conectores upstream |
| **Downstream integrator** | Envios (pushes) para Jira, GitHub, GitLab, ServiceNow e os demais conectores downstream |
| **Jira** | A integração legada do Jira: envios, comentários e pré-visualizações |
| **SSO (OIDC/OAuth2)** | Tentativas de login por meio de um provedor OAuth |
| **SAML** | Asserções SAML, incluindo falhas de assinatura e de atributos |
| **LDAP** | Binds e consultas (lookups) LDAP |
| **Import / Reimport** | Envios de scans, seja pela interface, pela API ou por agendamento |
| **Rules engine** | Avaliações de regras e as ações que elas tentam executar |
| **Scheduling** | Execuções agendadas, incluindo as que nunca chegaram a iniciar |
| **Sensei** | Varreduras de repositórios e execuções de correção |
| **Notification** | Envio de notificações de saída |
| **System** | Atividade em nível de instância que não pertence a nenhum produto |

As linhas são gravadas *ao lado* do subsistema, nunca em seu lugar. Cada adaptador está vinculado ao registro de origem e é deliberadamente à prova de falhas: se a gravação de uma linha de diagnóstico gerar um erro, esse erro é engolido e a operação original continua normalmente. Por isso, o Diagnósticos nunca pode ser a causa de uma falha em um envio, importação ou login.

Como as linhas são indexadas pelo registro que as originou, salvar novamente um registro de origem atualiza a linha de diagnóstico existente em vez de criar uma duplicata. Uma tentativa é uma linha durante toda a sua existência, desde `Queued`, passando por `Running`, até o resultado final.

### Campos de uma linha

| Campo | Significado |
| --- | --- |
| **Quando** | Quando a linha foi registrada; **Iniciado**, **Concluído** e **Duração** descrevem a própria tentativa |
| **Fonte** | O subsistema, conforme a tabela acima |
| **Provedor** | A ferramenta ou provedor específico dentro dessa fonte (`jira`, `github`, `okta`, o nome de um scanner) |
| **Operação** | O que foi tentado (`push`, `sync`, `login`, `reimport`, `rule_run`) |
| **Status** | `Queued`, `Running`, `Success`, `Failed`, `Timed out`, `Skipped` ou `Dry run` |
| **Severidade** | `Info`, `Warning`, `Error` ou `Critical` |
| **Resumo** | Um resultado em uma linha, seguro de ler rapidamente |
| **Gatilho** | O que disparou a tentativa: `UI`, `API`, `Scheduled`, `Webhook`, `Automatic`, `Command line` ou `System` |
| **Acionado por** | O usuário responsável, ou `System` para trabalho não supervisionado |
| **Ativo** | O produto ao qual a tentativa pertence; vazio significa nível de instância |
| **Objeto relacionado** | O achado, engajamento ou outro registro sobre o qual a tentativa tratava |
| **Configuração** | Qual configuração foi usada, por seu rótulo |
| **Referência externa** | O identificador retornado pelo outro sistema, como a chave de um issue criado |
| **ID de correlação** | Relaciona as linhas de uma mesma operação lógica |
| **Detalhe relatado** e **Contexto** | O detalhe técnico completo (restrito, veja [Quem vê o quê](#who-sees-what)) |

## As quatro visualizações

As abas acima da tabela são pontos de partida salvos, não filtros que você precisa reconstruir toda vez:

* **Errors** — falhas e timeouts. A primeira que você deve abrir.
* **Successes** — prova de que uma integração que funciona está de fato funcionando, útil quando alguém relata que "nada está sincronizando".
* **Never completed** — tentativas ainda em `Queued` ou `Running` muito depois do momento em que deveriam ter terminado. São os casos silenciosos: nada falhou, então nada foi relatado, mas também nada chegou.
* **All events** — tudo, sem filtro.

![All events, showing every source](images/diagnostics_all_events.png)

A visualização ativa faz parte da URL da página, então uma visualização pode ser compartilhada por link e sobrevive a uma atualização da página.

## Restringindo a lista

* **Intervalo de tempo** — 24 horas, 7 dias, 30 dias ou 90 dias, pelos botões no cabeçalho.
* **Contagens por fonte** — as contagens coloridas abaixo dos cartões de resumo também funcionam como filtros rápidos. Clique em uma para mostrar apenas aquela fonte; clique novamente (ou em **Clear source filter**) para voltar. No máximo uma fica ativa por vez.
* **Filtros e ordenação por coluna** — cada coluna permite filtrar e ordenar, incluindo Severidade e Fonte. A Severidade ordena por gravidade (`Critical` → `Info`) em vez de ordem alfabética, e a Fonte ordena pelo rótulo exibido, não pelo valor armazenado internamente.
* **Keyword Search** — pesquisa em todos os campos de texto ao mesmo tempo.
* **Preferências de colunas** — o seletor de colunas e os layouts salvos funcionam da mesma forma que em qualquer outra lista do Pro.

![A source count used as a quick filter](images/diagnostics_chip_filter.png)

Clique na lupa no início de uma linha para abrir a tentativa completa:

![A single event, including the redaction notice](images/diagnostics_detail.png)

## As credenciais são removidas antes da linha ser gravada

Erros de integração citam a requisição que falhou, e essas citações carregam segredos: um cabeçalho `Authorization`, um token em uma query string, uma senha dentro de uma URL de conexão. O Diagnósticos remove esses valores **na entrada**, de modo que o valor original nunca chega ao banco de dados e nenhuma mudança de ideia posterior pode expô-lo.

Duas coisas são higienizadas:

* **Valores sob chaves com formato de credencial** — qualquer coisa cuja chave pareça um segredo (`password`, `token`, `secret`, `api_key`, `authorization`, `private_key` e similares, em qualquer capitalização ou com traços ou espaços). Um pequeno conjunto de chaves é isento, porque só a *presença* delas importa, nunca o conteúdo.
* **Valores que parecem credenciais onde quer que apareçam** — cabeçalhos de autorização bearer e basic, JWTs, credenciais embutidas em URLs (`https://user:pass@host`), prefixos de token reconhecíveis de fornecedores e blocos PEM.

Cada um é substituído por `[redacted]`. A mensagem ao redor é mantida, para que o erro continue legível:

```text
401 Unauthorized: Authorization: [redacted]
upload rejected: https://svc:[redacted]@sftp.example/out/…
```

Valores longos são truncados, e contextos profundamente aninhados são achatados, para que um payload enorme não sobrecarregue a tabela.

Quando algo é removido de uma linha, a própria linha indica isso, em vez de deixar você se perguntando se o campo estava vazio ou foi esvaziado.

> **A redação é, por design, uma tentativa de melhor esforço.** O higienizador reconhece *formatos* de credenciais. Um segredo que se pareça com texto comum, sob uma chave que não pareça sensível, ainda pode ser registrado. Trate o Diagnósticos como um log operacional, não como um lugar onde a ausência de segredos é garantida — e mantenha o detalhe técnico restrito a quem realmente precisa dele.

## Quem vê o quê

O Diagnósticos é dividido por nível de acesso, porque o resumo de uma falha é útil para o dono de um produto, mas a requisição bruta por trás dela não é.

| | Superuser | Everyone else |
| --- | --- | --- |
| Linhas dos produtos aos quais têm autorização | Sim | Sim |
| Linhas em nível de instância (sem produto) | Sim | Não |
| Resumo, fonte, status, severidade, tempos, configuração | Sim | Sim |
| **Detalhe relatado**, **Contexto**, **IP remoto** | Sim | Ocultado, e identificado como ocultado |

Um usuário que não é superusuário vê que um detalhe existe e está sendo ocultado, em vez de um campo vazio que pareça um dado ausente. As linhas em nível de instância — SSO, SAML, LDAP e outras atividades que não pertencem a nenhum produto — são exclusivas para superusuários, já que não há associação a nenhum produto que pudesse conceder acesso a elas.

## Por quanto tempo os registros são mantidos

Uma tarefa agendada faz a limpeza do registro para que ele não cresça sem limite:

| Severidade | Mantido por |
| --- | --- |
| `Info` | 30 dias |
| `Warning`, `Error`, `Critical` | 180 dias |

Ambas as janelas são configuráveis com as configurações `DIAGNOSTIC_EVENT_INFO_RETENTION_DAYS` e `DIAGNOSTIC_EVENT_RETENTION_DAYS`. A exclusão é feita em lotes, para que uma purga grande não mantenha uma transação longa aberta.

## API

O registro é somente leitura pela API, em `/api/v2/diagnostic_events/`:

| Endpoint | Retorna |
| --- | --- |
| `GET /api/v2/diagnostic_events/` | A lista, com os filtros abaixo |
| `GET /api/v2/diagnostic_events/{id}/` | Um evento |
| `GET /api/v2/diagnostic_events/summary/` | As contagens por trás dos cartões do cabeçalho, incluindo os totais por fonte |
| `GET /api/v2/diagnostic_events/choices/` | Os valores válidos para `source`, `status`, `severity` e `trigger` |

Parâmetros úteis:

| Parâmetro | Efeito |
| --- | --- |
| `source`, `status`, `severity`, `trigger` | Aceitam vários valores separados por vírgula de uma vez |
| `failures_only=true` | Falhas e timeouts |
| `unresolved_only=true` | Tentativas ainda em fila ou em execução |
| `product_name` | Filtra pelo nome do produto |
| `object_model` | Filtra pelo tipo de registro sobre o qual a tentativa tratava |
| `o=` | Ordenação, com o prefixo `-` para inverter (`o=-created_at`) |

As mesmas regras de acesso se aplicam: um usuário que não é superusuário recebe linhas restritas aos seus produtos, com os campos restritos ocultados.

## Descobrindo o que deu errado

* **Um ticket nunca apareceu.** Filtre a Fonte pelo integrador (ou Jira) e leia o Status. `Failed` fornece o motivo no Resumo; `Queued` muito tempo depois do fato indica que o job nunca chegou a rodar, o que é um problema de worker ou de agendamento, e não de credencial.
* **Um usuário não consegue fazer login.** Filtre a Fonte por SSO, SAML ou LDAP, e leia a falha da tentativa dele — uma assinatura de asserção inválida, um bind rejeitado, um atributo incompatível. Essas linhas são em nível de instância, portanto exclusivas para superusuários.
* **Um scan não apareceu.** Filtre a Fonte por Import / Reimport. Observe o Gatilho para distinguir um envio agendado e não supervisionado de um envio manual de alguém, e o Acionado por para saber a quem perguntar.
* **Algo está tentando novamente sem parar.** Ordene por ID de correlação, ou filtre por um valor específico, para ver juntas todas as tentativas da mesma operação lógica.
* **"Nada está funcionando."** Abra primeiro o Successes para a mesma janela de tempo. Uma lista saudável ali transforma uma indisponibilidade vaga em algo específico.

## Relacionados

* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — ativando e desativando recursos opcionais do Pro
* [Connectors](/connectors/upstream/about/) — trazendo achados para dentro
* [Pro Integrations](/connectors/downstream/about/) — enviando achados para fora
* [Single Sign-On](/admin/sso/) — os provedores de identidade cujas tentativas de login aparecem aqui
