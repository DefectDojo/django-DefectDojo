---
title: Migração a partir de Endpoints
description: O que acontece quando você migra dados existentes de Endpoint para Localizações
audience: pro
weight: 3
---

Quando você habilita as Localizações em uma instância existente do DefectDojo Pro, os dados já armazenados como Endpoints precisam ser transportados para o novo modelo de Localizações. Esta página descreve a migração, o que ela preserva e como a API legada de Endpoint se comporta depois que a migração é executada.

Observe que a migração é **de mão única**. Não existe um caminho de rollback automatizado que recrie Endpoints a partir de Localizações.

## O Que a Migração Faz

Para cada Endpoint existente, a migração vai:

1. **Criar uma Localização de URL** (ou reutilizar uma existente) usando os campos `protocol`, `userinfo`, `host`, `port`, `path`, `query` e `fragment` do Endpoint. A nova URL é automaticamente anexada a um objeto `Location` pai.
2. **Transferir as tags.** Cada tag do Endpoint é adicionada ao conjunto de tags da Localização.
3. **Transferir os metadados.** Cada linha `DojoMeta` anexada ao Endpoint é redirecionada para a nova Localização.
4. **Criar uma `LocationProductReference`** para que a URL apareça sob o Ativo (Produto) correto.
5. **Criar uma `LocationFindingReference` para cada `Endpoint_Status`**:

   | Flag do Endpoint_Status | Status resultante da Localização |
   | --- | --- |
   | `risk_accepted=True` | **Risco aceito** |
   | `false_positive=True` | **Falso positivo** |
   | `out_of_scope=True` | **Fora do escopo** |
   | `mitigated=True` | **Mitigado** |
   | (nenhum dos anteriores) | **Ativo** |

   O mapeamento é sensível à ordem: a *primeira* flag correspondente prevalece. Isso reduz intencionalmente as antigas combinações de múltiplas flags a um único status canônico usado pelas Localizações.


## O Que a Migração Não Faz

- Ela **não** cria Localizações de Dependência. Dados de SBOM e de bibliotecas nunca existiram como Endpoints, então não há nada para a migração converter. Para popular Dependências, faça upload de SBOMs (veja [Trabalhando com SBOMs](../pro__working_with_sboms)) ou execute novamente as varreduras com parsers que emitam dados de dependência.
- Ela **não** exclui as linhas originais de Endpoint ou Endpoint_Status. Elas permanecem no banco de dados para sustentar a API legada somente leitura. Não são usadas pela nova interface nem pelas importações após o recurso ser habilitado.

## API de Endpoint Após a Migração

Depois que as Localizações são habilitadas, a API legada de Endpoint entra em um modo de **compatibilidade de leitura**, projetado para manter as automações existentes funcionando sem alterações de código — mas apenas para tráfego de leitura.

### O Que Ainda Funciona

- `GET /api/v2/endpoints/` — Retorna linhas que *parecem* Endpoints, mas na verdade são projetadas a partir de linhas de Location Product Reference unidas a Localizações de URL. Os campos conhecidos (`protocol`, `host`, `port`, `path`, `query`, `fragment`, `tags`, `product`, `active_finding_count`) estão todos presentes.
- `GET /api/v2/endpoints/{id}/` — A busca de um único Endpoint funciona da mesma forma. O `id` é o ID original do Endpoint e é preservado ao longo da migração por meio do mapeamento de Asset Reference.
- `GET /api/v2/endpoint_status/` e `GET /api/v2/endpoint_status/{id}/` — Retornam linhas projetadas a partir de `LocationFindingReference`. Os campos booleanos legados `mitigated`, `false_positive`, `out_of_scope` e `risk_accepted` são reconstruídos.
- A filtragem por `protocol`, `host`, `port`, `path`, `query`, `fragment`, `product` e `tag(s)` continua funcionando.
- A ação `generate_report` em Endpoints individuais continua funcionando.

### O Que Retorna 403

- `POST`, `PUT`, `PATCH` e `DELETE` em `/api/v2/endpoints/` e `/api/v2/endpoint_status/` retornam todos `HTTP 403` com o corpo:

  > Writes to this endpoint are deprecated when V3_FEATURE_LOCATIONS is enabled

  Os clientes que gravam dados de Endpoint devem migrar para os novos endpoints de referência (`POST /api/v2/location_findings/`, `POST /api/v2/location_products/`) e para o endpoint de URL (`POST /api/v2/urls/`).

### Diferenças de Comportamento a Observar

Algumas coisas se comportam de maneira diferente em relação à API original de Endpoint:

- **Status único em vez de flags.** As Localizações têm apenas um status por vez. Se o seu código dependia de um Achado ser *ao mesmo tempo* `mitigated=True` *e* `false_positive=True` em um Endpoint_Status, isso deixa de ser representável — a migração escolhe a flag de maior prioridade (a ordem mostrada na tabela acima).
- **Campo `endpoint` no Endpoint_Status.** O campo legado `endpoint` é reconstruído buscando a Asset Reference correspondente. Em casos raros, quando o Ativo de um Achado não corresponde mais às referências de Ativo de sua Localização, esse campo pode ser nulo.
- **Paginação e ordenação.** Os campos de ordenação disponíveis na camada de compatibilidade de leitura são `host`, `product`, `id` e `active_finding_count`. Se o seu cliente ordena por outro campo, mude para um destes ou migre para os novos endpoints de Localizações.

## Tags e Metadados

As tags aplicadas a Endpoints se tornam tags no objeto Localização (não no subtipo URL). Os filtros baseados em tags na API legada continuam funcionando.

Os metadados de Endpoint são redirecionados para a Localização durante a migração. As automações existentes que leem metadados por meio de `/api/v2/endpoint_meta/` devem continuar funcionando; novos metadados devem ser gravados por meio dos endpoints de Localização.
