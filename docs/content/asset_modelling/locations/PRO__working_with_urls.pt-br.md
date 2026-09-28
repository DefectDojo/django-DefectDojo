---
title: Trabalhando com URLs
description: Uso cotidiano de Localizações de URL como substituição dos Endpoints
audience: pro
weight: 4
---

As Localizações de URL são a substituição funcional do antigo modelo de Endpoints. Elas armazenam os mesmos campos no formato de URL aos quais você já está acostumado — `protocol`, `host`, `port`, `path`, `query`, `fragment` — e cumprem o mesmo papel: identificar *onde* vive um Achado de aplicação web.

Esta página aborda o que muda quando você passa a usar Localizações de URL no dia a dia, as novas telas da interface e os endpoints de API a usar no lugar da antiga API de Endpoint.

## O Subtipo URL

Toda URL é uma Localização. Isso significa que uma URL tem, ao mesmo tempo:

- Os campos estruturados de URL (`protocol`, `user_info`, `host`, `port`, `path`, `query`, `fragment`, além de um `hash` usado para deduplicação).
- Os campos compartilhados de Localização (`location_type="url"`, uma string canônica `location_value` para exibição e busca, tags, tags herdadas, metadados e vínculos de referência com Ativos e Achados).

Quando você cria ou faz upload de uma URL, o DefectDojo a analisa nos campos estruturados e grava tanto a linha de URL quanto sua linha de Localização pai em uma única transação. A deduplicação de URL é uma correspondência exata entre os campos estruturados — duas URLs são consideradas iguais se todos os componentes coincidirem, com o colapso padrão de porta default (`http://example.com:80/` e `http://example.com/` resolvem para a mesma URL).

## Na Interface do Pro

Quando o recurso de Localizações está habilitado, a navegação expõe:

- **Locations / All** — Uma lista de todas as Localizações, tanto do subtipo URL quanto do subtipo Dependência. Filtre por tipo, status, Ativo, Achado ou tag.
- **Locations / URLs** — Uma lista restrita apenas às Localizações de URL. É o análogo mais próximo da antiga página de Endpoints.
- **New URL** — Um formulário para criar uma única URL com campos estruturados, tags e associações opcionais de Ativo/Achado.
- **Locations on an Asset** — A partir de qualquer Ativo, a aba **Locations** mostra as URLs e Dependências anexadas a esse Ativo, com contagens de status e ações rápidas.

Os fluxos de trabalho comuns da interface de Endpoints são preservados:

- **Atualizações de status em massa.** Selecione várias Localizações de URL e aplique um status (Ativo, Mitigado, Falso positivo, Risco aceito, Fora do escopo) às suas referências de Achado em uma única ação.
- **Adicionando URLs existentes a um Ativo.** Use **Add Existing** na aba Locations de um Ativo para vincular URLs já existentes no sistema, em vez de criar duplicatas.
- **Tags.** As tags aplicadas a uma Localização de URL propagam-se como tags herdadas nos Achados que a referenciam, da mesma forma que as tags de Endpoint faziam anteriormente.

## Modelo de Status

As Localizações de URL usam os mesmos rótulos de status único que todas as outras Localizações:

| Status | Significado |
| --- | --- |
| **Ativo** | O Achado nesta URL está aberto. |
| **Mitigado** | O Achado foi corrigido para esta URL. |
| **Falso positivo** | O Achado não é uma vulnerabilidade real para esta URL. |
| **Risco aceito** | O Achado é reconhecido, mas aceito nesta URL. |
| **Fora do escopo** | Esta URL está excluída do engajamento. |

Observe que o antigo modelo de Endpoint Status permitia múltiplas flags simultaneamente (por exemplo, `mitigated=True` e `false_positive=True`). As Localizações impõem apenas um status por vez. Se você migrou a partir de Endpoints, a flag mais específica foi preservada (veja a tabela de mapeamento em [Migração a partir de Endpoints](../pro__migrating_from_endpoints)).

As Asset References usam um status mais simples: apenas **Ativo** ou **Mitigado**, já que o status em nível de Ativo não precisa do mesmo detalhamento de auditoria.

## API REST

Use estes endpoints no lugar da antiga API de Endpoint:

| Tarefa | Endpoint |
| --- | --- |
| Listar URLs | `GET /api/v2/urls/` |
| Criar uma URL | `POST /api/v2/urls/` |
| Atualizar as tags ou metadados de uma URL | `PATCH /api/v2/urls/{id}/` |
| Listar todas as Localizações (URLs + Dependências) | `GET /api/v2/location/?location_type=url` |
| Vincular uma URL a um Achado | `POST /api/v2/location_findings/` |
| Vincular uma URL a um Ativo | `POST /api/v2/location_Assets/` |
| Atualizar o status de um vínculo de Achado | `PATCH /api/v2/location_findings/{id}/` |
| Remover um vínculo de Achado | `DELETE /api/v2/location_findings/{id}/` |

Os filtros em `/api/v2/urls/` incluem os campos estruturados de URL, além de `tag(s)`, `has_tags`, `Asset`, e ordenação por `host`, `Asset` ou contagem de achados ativos.

O antigo endpoint `/api/v2/endpoints/` ainda atende tráfego de **leitura** por meio de uma camada de compatibilidade — veja [Migração a partir de Endpoints](../pro__migrating_from_endpoints) para saber o que é preservado e onde essa camada difere do comportamento original. **Gravações** nos endpoints legados retornam `403` e devem ser migradas para os endpoints acima.

## Importando URLs a partir de Varreduras

As importações de scanner criam Localizações de URL automaticamente. Quando um parser emite uma URL para um Achado (da mesma forma que antes emitia um Endpoint), o importador:

1. Procura uma URL existente com campos estruturados correspondentes, ou cria uma.
2. Cria uma Finding Reference vinculando o Achado à URL com status **Ativo**.
3. Cria (ou reutiliza) uma Asset Reference para que a URL também apareça no Ativo pai.

Os parsers do DefectDojo que anteriormente criavam Endpoints foram atualizados para criar Localizações automaticamente no Pro.

## Coisas Que Se Comportam de Forma Diferente

Vale destacar algumas pequenas mudanças de comportamento:

- **Um status por par URL/Achado.** Como descrito acima, o modelo de múltiplas flags do Endpoint_Status é reduzido a um único status. Fluxos de trabalho que alternavam flags de forma independente precisam escolher uma única transição.
- **As tags residem na Localização, não na URL.** O subtipo URL não possui seu próprio conjunto de tags; as tags pertencem à Localização pai. Se você ler uma URL pela API, o campo `tags` vem de `location.tags`.
- **A deduplicação é por URL canônica, não por Ativo.** Dois Ativos que têm a mesma URL compartilham uma única Localização de URL subjacente e a referenciam duas vezes (uma Asset Reference cada). Isso é intencional e é o que permite relatórios entre Ativos.
- **O campo `endpoints` nos Achados.** Quando a flag está ativada, esse campo na API de Achado ainda retorna linhas, mas elas são projetadas a partir de Localizações de URL, em vez da tabela de Endpoint. Trate-o como somente leitura e grave por meio de `/api/v2/location_findings/`.
