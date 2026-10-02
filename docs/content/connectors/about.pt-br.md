---
title: Sobre os Conectores
description: O local unificado para Conectores Upstream e Downstream na interface
  do Pro
summary: ''
date: 2026-07-14 00:00:00+00:00
lastmod: 2026-07-14 00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Observação: Conectores são um recurso exclusivo do DefectDojo Pro.</span>

**Conectores** é o local único na interface do DefectDojo Pro para todas as ferramentas com as quais o DefectDojo se comunica, em ambas as direções. Ele reúne dois recursos que antes eram configurados em locais separados:

* **Conectores Upstream** (antigos **Conectores de API**) trazem achados e inventário de ativos *para dentro*, a partir dos seus scanners e ferramentas de segurança.
* **Conectores Downstream** (antigas **Integrações**) enviam achados *para fora*, para os seus sistemas de rastreamento de problemas e emissão de tickets.

Se você pensar no DefectDojo como o hub dos seus dados de segurança, os Conectores Upstream são a forma como os dados chegam, e os Conectores Downstream são a forma como o trabalho de remediação sai.

## Onde encontrar os Conectores

Na barra lateral da interface do Pro, abra o grupo **Connectors** no cabeçalho **Import**:

* **Connectors > Upstream Connectors** — substitui a antiga entrada **API Connectors** (anteriormente em Import).
* **Connectors > Downstream Connectors** — substitui a antiga entrada **Integrations** (anteriormente em Settings). Esta direção está atualmente em **Beta**.

Os favoritos e links diretos antigos continuam funcionando: as URLs legadas de **API Connectors** e **Integrations** redirecionam automaticamente para as novas páginas **Upstream Connectors** e **Downstream Connectors**.

## Quem pode ver o quê

* **Upstream Connectors** fica visível para usuários com Função Global de Reader ou superior.
* **Downstream Connectors** fica visível apenas para superusuários, e atualmente está em **Beta** para instâncias do DefectDojo Pro hospedadas na Cloud.

O grupo **Connectors** aparece na barra lateral se pelo menos uma das duas páginas estiver visível para você.

## As páginas de Connectors

As duas direções compartilham o mesmo layout renovado:

* Cada ferramenta é exibida como um **quadro** (tile) em largura total — logotipo à esquerda, o nome da ferramenta e uma breve descrição no centro, e um botão de ação à direita.
* Cada seção tem uma **caixa de busca** que filtra os quadros por nome da ferramenta enquanto você digita.

Na página **Upstream Connectors**:

* **Configured Connectors** lista os conectores que você já configurou. Cada quadro mostra um resumo de integridade operacional (status de integridade, última operação e contagens totais/mapeadas de registros) e um menu **Manage Configuration** com as ações **Manage Records & Operations**, **Edit Configuration** e **Delete Configuration**.
* **Available Connectors** lista as ferramentas suportadas que você ainda não configurou, cada uma com um botão **Add Configuration**.
* Um filtro no cabeçalho da página restringe ambas as seções por tipo de conector: **All**, **Asset** (ou **Product**, dependendo do vocabulário da sua instância) para conectores que importam inventário de ativos, e **Finding** para conectores que importam dados de vulnerabilidade.

Na página **Downstream Connectors**:

* **Available Integrations** lista todos os sistemas de rastreamento de problemas suportados. Os quadros das integrações já configuradas mostram uma contagem das Integration Instances existentes.

## Próximos passos

* Leia [Sobre os Conectores Upstream](/connectors/upstream/about/) e [adicione seu primeiro Conector Upstream](/connectors/upstream/add_edit/) para começar a importar achados automaticamente.
* Leia o [guia de Conectores Downstream](/connectors/downstream/about/) para enviar achados aos seus sistemas de rastreamento de problemas.
