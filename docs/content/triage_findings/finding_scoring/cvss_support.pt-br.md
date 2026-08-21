---
title: Suporte a Versões do CVSS
description: Quais versões do CVSS o DefectDojo armazena, exibe e aceita em Achados
weight: 1
---

O DefectDojo oferece suporte a metadados CVSS em Achados, incluindo o padrão CVSS 4.0. Esta página descreve quais versões do CVSS são armazenadas de ponta a ponta, onde você pode inseri-las ou visualizá-las, e o que esperar em termos de cobertura por parte dos parsers.

## O que o DefectDojo armazena

Os Achados podem carregar os seguintes dados CVSS:

| Versão | Vetor armazenado | Pontuação armazenada | Construtor de vetor e calculadora na UI |
| --- | --- | --- | --- |
| **CVSS v4.0** | ✅ | ✅ | ✅ (UI Pro) |
| **CVSS v3 (v3.0 / v3.1)** | ✅ | ✅ | ✅ (UI Pro) |
| **CVSS v2** | Armazenado implicitamente através do campo **Severity** do Achado; nenhum campo de vetor v2 separado é armazenado | N/A | N/A |

Cada Achado possui campos dedicados `cvssv3` / `cvssv3_score` e `cvssv4` / `cvssv4_score` no modelo subjacente. Eles são acessíveis tanto pela API quanto pela UI.

## Onde inserir dados CVSS manualmente

Tanto o CVSSv3 quanto o CVSSv4 podem ser inseridos manualmente em um Achado:

- **Formulário Edit Finding** — cole uma string de vetor CVSS completa no campo correspondente. Ao salvar, o DefectDojo analisa o vetor e calcula a pontuação automaticamente.
- **Construtor de vetor (UI Pro)** — clique no botão 🛠️ ao lado da entrada CVSSv3 ou CVSSv4 no formulário Edit Finding para abrir o construtor de vetor. Monte o vetor interativamente e, em seguida, clique no botão da calculadora para gerar uma pontuação a partir do vetor resultante.

> As strings de vetor CVSSv4 e o construtor de vetor foram adicionados à UI Pro na v2.50.3 (22 de setembro de 2025), e o botão explícito da calculadora ao lado foi lançado na v2.51.1 (14 de outubro de 2025).

## Configurações de exibição

A visualização de Achado respeita duas configurações do sistema que controlam se os dados de CVSSv3 e CVSSv4 são renderizados para os usuários:

- **Enable CVSS 3 Display** — exibe vetores e pontuações CVSSv3 nos Achados.
- **Enable CVSS 4 Display** — exibe vetores e pontuações CVSSv4 nos Achados.

Ambas podem ser configuradas de forma independente em System Settings. Se ambas estiverem habilitadas, as duas versões são exibidas lado a lado nos Achados que carregam ambas.

## Cobertura de parsers e ferramentas

O DefectDojo pode armazenar dados CVSSv4 em qualquer Achado, mas **se um determinado parser preenche os campos de CVSSv4 depende da ferramenta de origem**:

- Se a ferramenta de origem emite vetores ou pontuações CVSSv4 em seu formato de exportação, o parser normalmente mapeará esses campos.
- Se a ferramenta emite apenas dados CVSSv2 ou CVSSv3, o parser não sintetizará um vetor v4 — não existe uma conversão embutida de v3 para v4.
- Alguns parsers mais antigos podem ainda não mapear os campos CVSSv4 mesmo que a ferramenta de origem os emita. Se você encontrar um parser que omite os campos CVSSv4 de uma ferramenta que os emite, por favor, abra um issue.

Enquanto isso, dois caminhos oferecem cobertura completa de CVSSv4 independentemente do suporte do parser:

1. **[Generic Findings Import](/supported_tools/parsers/generic_findings_import/)** — aceita colunas `CVSSV4` (vetor) e `CVSSV4_score` em CSV, e chaves `cvssv4` / `cvssv4_score` em JSON.
2. **[Universal Parser](/import_data/pro/specialized_import/universal_parser/)** (Pro) — oferece suporte a vetores CVSSv4 como um campo mapeável (adicionado na v2.57.0, 7 de abril de 2026). Use isso quando sua ferramenta emite JSON ou CSV com nomes de campos personalizados que os parsers embutidos não mapeiam.

A inserção manual no formulário Edit Finding permanece disponível como alternativa universal para qualquer ferramenta ou relatório que não flua o CVSSv4 automaticamente.
