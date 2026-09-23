---
title: Integração de Rastreamento de Problemas
description: Sincronize os achados do DefectDojo com seu sistema de rastreamento de
  problemas para agilizar a remediação e a responsabilização.
weight: 5
aliases:
- /pt-br/issue_tracking/
- /pt-br/issue_tracking/intro/
- /pt-br/issue_tracking/intro/intro/
---

## Visão geral

As integrações de rastreamento de problemas do DefectDojo conectam seus fluxos de gerenciamento de vulnerabilidades ao seu sistema de rastreamento de problemas já existente. Ao criar e atualizar issues automaticamente a partir dos achados de segurança, o DefectDojo ajuda a garantir que as vulnerabilidades fiquem visíveis, tenham um responsável e sejam tratadas dentro das mesmas ferramentas que suas equipes de desenvolvimento e operações já utilizam.

| Edição      | Integrações de Rastreamento de Problemas Suportadas |
|--------------|---------------------------------------|
| Community Edition  | * [Jira](/connectors/os_jira/os__jira_guide/)                          |
| Pro          | * [Jira](/connectors/downstream/downstream_toolreference/#jira) ([guia legado](/connectors/downstream/pro__jira_guide/))<br>* [Azure DevOps](/connectors/downstream/downstream_toolreference/#azure-devops-boards)<br>* [Bitbucket](/connectors/downstream/downstream_toolreference/#bitbucket)<br>* [Freshservice](/connectors/downstream/downstream_toolreference/#freshservice)<br>* [GitHub](/connectors/downstream/downstream_toolreference/#github)<br>* [GitLab Boards](/connectors/downstream/downstream_toolreference/#gitlab)<br>* [Linear](/connectors/downstream/downstream_toolreference/#linear)<br>* [PagerDuty](/connectors/downstream/downstream_toolreference/#pagerduty)<br>* [ServiceDesk Plus](/connectors/downstream/downstream_toolreference/#servicedesk-plus)<br>* [ServiceNow](/connectors/downstream/downstream_toolreference/#servicenow)<br>* [Shortcut](/connectors/downstream/downstream_toolreference/#shortcut)<br>* [Zendesk](/connectors/downstream/downstream_toolreference/#zendesk) |


Quando habilitado, o DefectDojo pode criar issues automaticamente, ou de forma seletiva a partir de Produtos ou Engajamentos. Conforme os Achados são atualizados no DefectDojo — resolvidos, mitigados ou reativados — as issues correspondentes podem ser mantidas em sincronia, garantindo que ambos os sistemas reflitam o estado atual do risco.

## O que é rastreado

Cada issue pode incluir detalhes-chave da vulnerabilidade, como severidade, descrição, evidências e orientações de remediação. Os vínculos entre o DefectDojo e o sistema de rastreamento de problemas fornecem rastreabilidade desde a descoberta até a resolução, apoiando relatórios, auditorias e melhoria contínua.

## Por que as integrações de rastreamento de problemas importam

Os achados de segurança são mais eficazes quando são acionáveis. Integrar o DefectDojo a um sistema de rastreamento de problemas preenche a lacuna entre a detecção e a remediação, incorporando o trabalho de segurança diretamente aos fluxos de trabalho de engenharia já estabelecidos. Isso reduz a troca de contexto, melhora a responsabilização e ajuda as equipes a remediar problemas mais rapidamente.
