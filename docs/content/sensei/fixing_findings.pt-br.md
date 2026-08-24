---
title: Corrigindo achados com o Sensei
description: Verifique, faça a triagem de candidatos a correção automática e abra
  pull requests de correção
draft: false
audience: pro
weight: 3
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: o Sensei é um recurso exclusivo do DefectDojo Pro e atualmente está em BETA.</span>

Depois que um repositório é integrado, o Sensei aparece diretamente nos seus achados e no hub do Sensei. Esta página aborda a verificação de um repositório, a triagem de candidatos a correção automática e a correção de achados individuais. Você precisa de acesso mínimo de **Writer** ao produto de um achado para disparar uma correção.

## Verificar um repositório

As verificações importam achados para um engajamento nomeado a partir da branch. Você pode disparar uma verificação sob demanda a partir do hub do Sensei: abra as ações da linha de um repositório e escolha **Scan now**.

![Diálogo de verificação com o Sensei](images/scan_dialog.png)

Escolha a branch a ser verificada (o padrão é a branch padrão do repositório) e clique em **Start scan**. No modo hospedado pelo DefectDojo, as verificações também são executadas automaticamente quando um pull request é aberto.

## A coluna Sensei nos achados

Repositórios integrados adicionam uma coluna **Sensei** à tabela de achados. Cada achado exibe um botão **Fix** (ou o status atual da correção), permitindo corrigir sem sair da sua tela de triagem.

![Coluna Sensei na tabela de achados](images/findings_sensei_column.png)

O botão tem dois estados:

- **Fix:** o produto do achado está integrado ao Sensei. Clicar nele inicia uma correção.
- **Configure Product:** o produto do achado **ainda não** está integrado. Clicar nele leva você ao Sensei para integrar um repositório a esse produto; após a integração, o botão passa a ser **Fix**.

## Corrigir um único achado

Clicar em **Fix** (na tabela de achados ou no cabeçalho de detalhes de um achado) abre o diálogo **Fix with Sensei**. Escolha a branch base para a qual o pull request de correção deve apontar e, em seguida, clique em **Fix**.

![Diálogo Fix with Sensei](images/fix_with_sensei_dialog.png)

O Sensei gera uma correção e abre um pull request. O status de correção do achado é exibido como um selo (badge) que evolui de *in progress* → *PR open* (ou *failed*). Assim que o pull request é aberto, o selo aponta diretamente para ele.

![Detalhe do achado com o selo de status da correção](images/finding_detail_fix.png)

> **💡 Uma correção, um PR:** cada correção aprovada consome uma correção da sua cota e abre um pull request. Revise e faça o merge do PR no GitHub como faria com qualquer outro.

## Triagem de candidatos a correção automática

Quando um repositório tem correções automatizadas habilitadas, cada verificação prepara os achados correspondentes como **candidatos** na aba **Auto-fix Candidates** do hub do Sensei. Esse é o modelo de prévia antes de tudo do Sensei: os achados ficam preparados, mas **nada é executado (sem custo de LLM) até que você aprove**. A aprovação abre pull requests de correção e consome correções.

![Triagem de candidatos a correção automática](images/auto_fix_candidates.png)

Cada candidato exibe o achado, seu status, severidade, risco, prioridade, repositório de destino e branch do PR. Para corrigir:

- **Aprovar um:** clique em **Approve** em uma linha para abrir o seletor de branch e iniciar essa correção.
- **Aprovar vários:** selecione múltiplas linhas e use a ação de aprovação em lote.

Os achados aprovados permanecem listados como **In Progress** (ou **Failed**) até que seu pull request seja anexado, de modo que uma correção em andamento ou com falha nunca desaparece antes de produzir um PR.

> **🔎 Correção automática (hands-off):** se você habilitou *Automatically remediate candidates* no repositório, uma verificação em segundo plano abre PRs de correção para os candidatos preparados automaticamente, até o limite da sua cota de correções, sem aprovação manual.

## Acompanhar verificações e impacto

Dois locais no hub do Sensei ajudam você a acompanhar o que o Sensei fez:

- **Scan Activity:** um registro de cada execução de verificação e correção, com seu modo (Branch Scan, PR Scan, Fix (Finding)), gatilho (Manual, Webhook, Auto Remediated), status, tempo de execução e links para o engajamento ou o pull request que ela produziu.

  ![Registro do Scan Activity](images/scan_activity.png)

- **Fix Impact:** um resumo das correções aplicadas, com os ativos corrigidos com mais frequência, no topo do hub.

  ![Painel do Fix Impact](images/fix_impact.png)

Use as ações de linha **Scan now**, **Scan history**, **Configure** e **Re-stage candidates** para gerenciar cada repositório integrado ao longo do tempo (veja [Referência](/sensei/sensei_reference/#repository-row-actions)).
