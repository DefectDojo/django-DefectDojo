---
title: Report Builder
description: Métricas de desempenho e insights
summary: ''
date: 2026-01-20 17:33:00+00:00
lastmod: 2026-01-20 17:33:00+00:00
draft: false
weight: 2
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

O Report Builder permite transformar os dados do DefectDojo em relatórios elaborados e compartilháveis — resumos executivos, snapshots de compliance, pacotes POA&M, detalhamento técnico e muito mais — para públicos dentro e fora da sua equipe de segurança.

## Código aberto vs. DefectDojo Pro

Como você constrói relatórios depende de qual edição você está executando:

| | Código aberto | DefectDojo Pro |
|---|---|---|
| **Construir um relatório** | Sim — monte a partir de widgets | Sim — componha a partir de Blocks reutilizáveis |
| **Executar e obter a saída** | Sim (HTML, impressão em PDF) | Sim (PDF ou HTML salvos) |
| **Salvar Themes / Blocks / Templates reutilizáveis** | Não — reconstrua a cada vez | Sim |
| **Histórico persistente de relatórios gerados** | Não | Sim — listar, baixar, executar novamente |
| **Automação via API REST + LLM** | — | Sim — criação → execução → download completos |

Em resumo: o **código aberto** permite construir um relatório, executá-lo e exportar o resultado, mas não salva templates nem mantém um histórico de relatórios. O **DefectDojo Pro** transforma a criação de relatórios em blocos de construção reutilizáveis e personalizáveis, que você pode controlar pela interface, pela API REST ou por um LLM.

## Para onde ir a seguir

**DefectDojo Pro**

- **[Report Builder](report-builder/)** — conceitos (Themes, Blocks, Templates, Generated Reports) e um passo a passo completo pela interface.
- **[Automatizando relatórios com a API](report-builder-api/)** — crie, execute, monitore e baixe relatórios pela API REST, com um script completo.
- **[Construindo relatórios com um LLM](report-builder-llm/)** — deixe um LLM projetar, criar, executar e baixar relatórios para você.

**Código aberto**

- **[Usando o Report Builder](using-the-report-builder/)** — construa, execute e exporte um relatório com o construtor baseado em widgets.
