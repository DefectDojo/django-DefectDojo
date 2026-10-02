---
title: Trabalhando com SBOMs
description: Gerencie dependências de software e SBOMs como Localizações
audience: pro
weight: 5
---

O DefectDojo Pro modela bibliotecas de software como **Localizações de Dependência**. Uma Dependência é um subtipo de Localização identificado por uma [Package URL (pURL)](https://github.com/package-url/purl-spec) e destinado a representar uma única biblioteca ou pacote — `org.apache.logging.log4j:log4j-core@2.17.0`, `pypi/django@5.0.2`, `npm/react@18.2.0`, e assim por diante.

As Dependências substituem o antigo modelo de **Componentes**, que era anexado apenas a Achados. Com as Localizações, as bibliotecas podem existir independentemente de qualquer vulnerabilidade — você pode fazer upload de um SBOM para um Ativo e deixar que os Achados se anexem automaticamente às dependências que referenciam à medida que as varreduras chegam.

## O Que Uma Dependência Contém

Toda Dependência é identificada de forma exclusiva por uma pURL, decomposta em campos atômicos nos quais você pode pesquisar e filtrar:

| Campo | Significado | Exemplo |
| --- | --- | --- |
| `purl_type` | Ecossistema da biblioteca | `npm`, `pypi`, `maven`, `cargo`, `nuget`, `gem` |
| `namespace` | Fornecedor ou organização | `org.apache.logging` |
| `name` | Nome da biblioteca | `log4j-core` |
| `version` | Versão específica | `2.17.0` |
| `qualifiers` *(opcional)* | Detalhes de implementação | `arch=amd64` |
| `subpath` *(opcional)* | Caminho dentro de um arquivo compactado ou monorepo | `src/lib/foo` |
| `artifact_hashes` *(opcional)* | Fingerprints | Somas SHA256 |
| `license_expression` *(opcional)* | Expressão de licença SPDX | `Apache-2.0`, `MIT` |
| `file_path` *(opcional)* | Onde a biblioteca foi encontrada no projeto | `package-lock.json` |

Essa decomposição atômica é o que torna útil a pesquisa baseada em pURL: você pode perguntar *"todos os pacotes `pypi` no namespace `django` na versão 4.x"* e o DefectDojo consegue responder isso sem analisar uma string de texto livre.

## Owned-By vs Used-By

Quando uma Dependência é associada a um Ativo, a Asset Reference carrega um **relacionamento** opcional que descreve *como* a biblioteca pertence ao Ativo:

- **`owned_by`** — *"esta biblioteca é de propriedade deste Ativo"*. Use isso para bibliotecas próprias (first-party) que um Ativo publica ou mantém.
- **`used_by`** — *"esta biblioteca é usada por este Ativo"*. Use isso para dependências de terceiros que um Ativo consome.

A mesma biblioteca pode ser `owned_by` de um Ativo e `used_by` de vários outros, que é exatamente o relacionamento necessário para responder *"quem consome o pacote que minha equipe publica?"* durante a triagem de vulnerabilidades.

## Fazendo Upload de um SBOM

Para popular Dependências em massa, faça upload de um arquivo SBOM em relação a um Produto. O endpoint é:

```
POST /api/v2/sbom-import/
```

| Campo | Descrição |
| --- | --- |
| `product` | O ID do Produto (Ativo) de destino |
| `file` | O arquivo SBOM |
| `scan_type` | O formato do SBOM — veja os formatos suportados abaixo |
| `replace` *(opcional)* | Se `true`, associações de Produto obsoletas que não têm o suporte de uma referência de Achado existente são removidas. Padrão: `false` (cumulativo) |

O importador analisa o arquivo, extrai os registros `Dependency`, deduplica-os em relação às Localizações existentes (criando novas conforme necessário) e cria Asset References vinculando cada Dependência ao Produto. A interface do Pro expõe o mesmo fluxo de upload — veja a ação **Upload SBOM** na aba de Localizações de um Produto.

### Formatos Suportados

O MVP inclui parsers para os dois formatos de SBOM dominantes:

- **CycloneDX** — JSON e XML
- **SPDX** — JSON (v2 e v3), XML e tag-value

O formato SWID Tag ainda não é suportado.

### Substituir vs Anexar

Por padrão, uploads repetidos são **aditivos**: as dependências que já existem no Ativo são mantidas, novas são adicionadas e nada é removido. Isso corresponde ao fluxo de trabalho típico de atualizações incrementais de SBOM.

Defina `replace=true` para podar (prune). Quando o modo replace está ativado, após uma importação bem-sucedida o importador remove as associações de Produto que não estavam presentes no novo SBOM **e** que não são referenciadas atualmente por um Achado ativo. As referências vinculadas a Achados ativos são preservadas mesmo no modo replace, para que você não perca o contexto de vulnerabilidade apenas porque um novo SBOM omite um pacote.

## Achados Que Referenciam Bibliotecas

Quando um parser ingere uma vulnerabilidade vinculada a uma biblioteca — por exemplo, uma ferramenta de SCA reportando `CVE-2021-44228` contra `log4j-core@2.14.1` — o importador:

1. Procura uma Localização de Dependência existente pela pURL, ou cria uma nova.
2. Cria uma `LocationFindingReference` vinculando o Achado à Dependência com status **Ativo**.
3. Cria uma `LocationProductReference` para que a Dependência também apareça no Produto pai, caso ainda não apareça.

Como os Achados e os uploads de SBOM compartilham os mesmos objetos de Dependência subjacentes, um Achado ingerido *antes* de um upload de SBOM ficará visível retroativamente na visualização do SBOM, e vice-versa.

## API REST

| Tarefa | Endpoint |
| --- | --- |
| Fazer upload de um SBOM | `POST /api/v2/sbom-import/` |
| Listar Dependências | `GET /api/v2/dependencies/` |
| Criar uma Dependência manualmente | `POST /api/v2/dependencies/` |
| Listar Localizações de Dependência | `GET /api/v2/location/?location_type=dependency` |
| Vincular uma Dependência a um Achado | `POST /api/v2/location_findings/` |
| Vincular uma Dependência a um Produto (com `owned_by` / `used_by`) | `POST /api/v2/location_products/` |

Os filtros em `/api/v2/dependencies/` incluem os campos de componente da pURL, tags e ordenação por `name`, `version` e contagem de achados ativos.

## Na Interface do Pro

Quando as Localizações estão habilitadas, a navegação expõe:

- **Locations / Dependencies** — Lista global de todas as Dependências na instância, com filtros de pURL.
- **Locations on a Product/Asset** — Visualização por Ativo que mostra tanto URLs quanto Dependências, com a ação **Upload SBOM** disponível na aba Dependencies.
- **New Dependency** — Formulário para criar uma única biblioteca inserindo manualmente os componentes de sua pURL.
- **Findings detail** — Um Achado que envolve uma biblioteca mostra suas Localizações de Dependência ao lado de quaisquer Localizações de URL, para que você possa ver *"este CVE afeta `log4j-core@2.14.1` no Ativo 6 e no Ativo 9"* em um só lugar.

## O Que Não Está no MVP

- **Formato de SBOM SWID Tag** — Não é analisado. CycloneDX ou SPDX é obrigatório.
- **Pontuação de risco de licença** — O campo `license_expression` é capturado quando presente no SBOM, mas o DefectDojo ainda não sinaliza achados por incompatibilidade de licença. Relatórios baseados em licença estão no roadmap como um follow-up ao MVP de Localizações.
- **Localizações de imagem de contêiner e recurso de nuvem** — Subtipos futuros de Localização. Por enquanto, bibliotecas descobertas dentro de uma imagem de contêiner são registradas como Dependências; a própria imagem de contêiner ainda não é uma Localização de primeira classe.
