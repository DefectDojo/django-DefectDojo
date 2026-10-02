---
title: Visão Geral das Locations
description: O que são as Locations e por que elas substituem os Endpoints
audience: pro
weight: 1
---

**Locations** são uma nova ferramenta de modelagem de ativos no DefectDojo Pro. Elas substituem o modelo legado de **Endpoints** e absorvem os dados anteriores de **Components** (biblioteca), dando ao DefectDojo uma forma única e polimórfica de descrever *onde* um Achado vive — seja isso uma URL, uma dependência de software de um **SBOM**, ou, no futuro, um **ID de recurso em nuvem**, uma **imagem de contêiner** ou um **repositório de código**.

As Locations precisam estar habilitadas na sua instância antes que você possa usá-las. Você mesmo pode ativar as Locations na [página de Feature Flags](/admin/feature_flags/pro__feature_flags/) — não é necessário abrir uma solicitação de Suporte. Observe que as Locations não podem ser desativadas novamente depois de habilitadas.

## Por que Substituir os Endpoints?

O modelo original de Endpoints foi construído em torno de URLs e endereços IP — ele carregava campos de aplicação web como `protocol`, `host`, `port`, `path`, e uma tabela de status fixa que estava fortemente acoplada aos Achados. Três problemas surgiram a partir disso:

1. **Fidelidade limitada.** Os Endpoints não conseguiam descrever de forma clara ativos que não fossem URLs, como bibliotecas de terceiros, imagens de contêiner ou recursos em nuvem, mesmo com os scanners produzindo cada vez mais achados sobre essas coisas.
2. **Teto de desempenho.** As linhas de Endpoint_Status por Achado e o schema com formato de URL não escalavam bem em grandes volumes de clientes.
3. **Components eram cidadãos de segunda classe.** As bibliotecas de software existiam apenas como campos desnormalizados em um Achado, de modo que uma biblioteca não podia existir independentemente de uma vulnerabilidade — o que tornava impossível uma verdadeira gestão de SBOM.

As Locations resolvem os três problemas ao introduzir um **objeto `Location` base** com um payload tipado, além de **subtipos** dedicados para cada formato de ativo:

- **URL Locations** — equivalente funcional aos antigos Endpoints, com os mesmos campos de protocol/host/port/path/query/fragment.
- **Dependency Locations** — bibliotecas de software identificadas por [Package URL (pURL)](https://github.com/package-url/purl-spec), usadas para modelar o conteúdo de SBOMs.
- **[Source Code Locations](/asset_modelling/locations/pro__source_code_locations/)** — onde um achado de análise estática vive no código-fonte, identificado por caminho de arquivo e número de linha. Gerenciado pelo scan, e a base para [rastrear achados à medida que seu código se move](/triage_findings/finding_deduplication/pro__location_drift_matching/).

Entre os futuros tipos de Location em consideração estão IDs de recursos de provedores de nuvem (AWS ARN, Azure Resource ID, GCP Full Resource Name) e imagens de contêiner (registry/repository:tag e impressões digitais SHA256).

## Conceitos-Chave

### Locations e Subtipos

Uma **Location** é o pai compartilhado. Ela carrega:

- Um `Location Type` (por exemplo, `"url"`, `"dependency"`)
- Uma string canônica `Location Value` usada para exibição, busca e deduplicação
- `Tags` e tags herdadas do Ativo pai
- Metadados (pares personalizados de chave/valor)

Um **subtipo** (URL ou Dependency) contém os campos estruturados específicos daquele tipo de location. URLs e Dependencies sempre existem junto a um objeto Location pai; o `Location Value` do subtipo é gerado a partir de seus campos estruturados.

### References

As Locations não são anexadas diretamente a Produtos ou Achados. Em vez disso, dois objetos **Reference** as conectam:

- **Asset References** — relações que a Location tem com Ativos (por exemplo, `libFoo` é *de propriedade de* (owned by) o Ativo 6, *usada por* (used by) o Ativo 9). Cada referência carrega um status (`Active` ou `Mitigated`) e um **relacionamento** opcional ("Used By" ou "Owned By").
- **Finding References** — relações que a Location tem com Achados. Cada referência carrega um status mais detalhado (`Active`, `Mitigated`, `False Positive`, `Risk Accepted`, `Out of Scope`), além do auditor e do horário da auditoria.

Essa separação é o que permite que uma biblioteca exista em um Produto *sem* precisar de um Achado — uma capacidade que faltava no antigo modelo de Components.

### Associação Automática no Momento da Importação

Quando um parser produz um Achado que referencia uma URL ou biblioteca, o importador:

1. Procura uma Location existente que corresponda à URL ou ao pURL; se nenhuma existir, cria uma.
2. Cria uma Finding Reference vinculando o Achado à Location com status `Active`.
3. Cria (ou reutiliza) uma Asset Reference para que a Location também exista no Ativo pai.

Os parsers existentes foram atualizados para emitir dados de Location quando a feature flag está ativada, e para retornar ao modelo legado de Endpoint quando ela está desativada. Nenhuma reconfiguração é necessária quando as Locations estão habilitadas — a próxima importação será automaticamente roteada pelo pipeline de Locations.

## O que Está no MVP

| Capability | Status |
| --- | --- |
| Foundational `Location`, `URL`, `Dependency` models | Shipped |
| REST API for Locations and References | Shipped (read-only `Location`, full CRUD on References) |
| Endpoint API read-compatibility shim | Shipped |
| Endpoint → URL one-way migration command | Shipped |
| Parser updates (URLs and dependencies) | Shipped for the major parsers |
| SBOM upload (CycloneDX, SPDX v2/v3) | Shipped via `/api/v2/sbom-import/` |
| Pro UI for Locations, URLs, Dependencies | Shipped |
| pURL search/filter | Shipped |
| License tracking on dependencies | Partial (`license_expression` field) |
| SWID Tag SBOM format | Not in MVP |

## Para Onde Ir a Seguir

- **Habilite o recurso** — entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com) para ativar as Locations na sua instância.
- **Migre a partir dos Endpoints** — veja [Migrando dos Endpoints](../pro__migrating_from_endpoints) para saber o que a migração preserva e como a API legada de Endpoint se comporta depois.
- **Fluxos de trabalho do dia a dia com URLs** — veja [Trabalhando com URLs](../pro__working_with_urls).
- **SBOMs e dependências** — veja [Trabalhando com SBOMs](../pro__working_with_sboms).
