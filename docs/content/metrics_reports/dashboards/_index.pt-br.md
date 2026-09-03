---
title: Painéis
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 1
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

O Painel é a página inicial do DefectDojo — um resumo do desempenho da sua equipe e um ponto de partida para monitorar as áreas que importam para você.

## Open Source vs. DefectDojo Pro

Como o painel funciona depende de qual edição você está executando:

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Painel inicial** | Um Painel Principal fixo para todos | Painéis **personalizáveis** por usuário |
| **Escolher o que aparece** | O superusuário ativa/desativa um conjunto fixo de gráficos | Cada usuário adiciona, configura e organiza **widgets** |
| **Múltiplos painéis nomeados** | Não | Sim — crie e alterne entre qualquer número de **layouts** |
| **Compartilhar / clonar / definir padrão** | — | Sim — publique layouts para sua equipe, clone modelos, defina seu padrão |
| **API REST + automação com LLM** | — | Sim — descubra o catálogo, crie layouts, renderize dados de widgets |

Em resumo: o **open source** oferece a todos os usuários o mesmo Painel Principal integrado, com um conjunto fixo de componentes. O **DefectDojo Pro** permite que cada usuário monte seus próprios painéis a partir de widgets, compartilhe-os e controle todo o sistema pela interface, pela API REST ou por um LLM.

## Próximos passos

**Open Source**

- **[Painel Principal do DefectDojo](introduction_dashboard/)** — a página inicial integrada: cartões de resumo, gráficos de severidade e como um superusuário os configura.

**DefectDojo Pro**

- **[Painéis Personalizáveis](custom-dashboards/)** — conceitos (layouts, widgets, o catálogo, compartilhamento) e um tour completo pela interface.
- **[Automatizando Painéis com a API](custom-dashboards-api/)** — descubra o catálogo de widgets, crie e atualize layouts, e renderize dados de widgets pela API REST, com um script completo.
- **[Construindo Painéis com um LLM](custom-dashboards-llm/)** — deixe um LLM projetar e construir painéis para você.
