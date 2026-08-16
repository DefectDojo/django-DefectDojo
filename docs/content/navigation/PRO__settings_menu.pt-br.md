---
title: O Menu de Configurações
description: Como a seção Configurações da barra lateral do DefectDojo Pro está organizada,
  a página de diretório Todas as Configurações, e como alternar entre o layout atual
  e o anterior
weight: 6
audience: pro
---

A seção Configurações da barra lateral agrupa todas as páginas administrativas do DefectDojo Pro. O layout que você vê depende de quando sua instância foi criada:

- **Novas instalações** abrem no layout reorganizado descrito abaixo.
- **Instalações existentes** mantêm o layout anterior até que um administrador ative o **Menu 2.0** (veja [Alternando layouts](#switching-layouts)).

De qualquer forma, **cada página de configurações mantém a mesma URL**. Favoritos, links salvos e qualquer coisa em seus próprios runbooks continuam funcionando independentemente de qual layout está ativo.

## O layout reorganizado

Configurações está dividido em sete grupos, nomeados pelo que você está tentando fazer, e não pela parte do sistema envolvida.

| Grupo | O que contém |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, E-mail, Feature Flags |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | As três páginas de Deduplicação, Finding Enrichment, Service Level Agreements, Prioritization Engines, Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status e — no DefectDojo Cloud — Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

Você só vê as entradas que sua conta tem permissão para abrir, e um grupo desaparece por completo quando nenhuma de suas páginas está disponível para você.

Duas convenções vale a pena conhecer:

- **Não há entradas "New" separadas.** Cada página de listagem tem um botão **New** que abre o formulário de criação, de modo que o menu traz uma entrada por catálogo em vez de duas. Se sua conta pode criar um registro mas não listá-los, a entrada do menu leva você diretamente ao formulário de criação.
- **Nada aninha mais de um nível abaixo de um grupo.** Chegar a uma página é, no máximo, Settings → grupo → página.

## All Settings

A primeira entrada da seção, **All Settings**, abre um diretório com todas as páginas de configurações que sua conta pode acessar, organizado nos mesmos grupos do menu e pesquisável por nome ou pelo que a página faz. Pesquisar `deduplication` encontra as três páginas de deduplicação *e* System Settings, porque System Settings também contém opções de deduplicação.

A última categoria, **Elsewhere in the app**, lista páginas que configuram o DefectDojo mas ficam em outras seções da barra lateral — os provedores de autorização, as configurações de Login e MFA, as instâncias do Jira, os conectores Upstream e Downstream, e o Universal Parser. Cada bloco é identificado com a seção à qual pertence.

## O que mudou de lugar

Se você está acostumado ao layout anterior:

| Antes | Agora |
| --- | --- |
| Settings → *(nível superior)* → Feature Flags | Settings → System → Feature Flags |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → E-mail Settings | Settings → System → E-mail |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(três páginas)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(catálogos de dados de referência)* | Settings → Configuration → *(inalterado)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(páginas de cloud)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

O grupo que era nomeado de acordo com seu pacote de licença — **Pro Settings** em uma instância Pro, **Enterprise Settings** em uma Enterprise — não existe mais. Suas páginas estão distribuídas entre System, Finding Workflow, Notifications e Operations.

## Alternando layouts

O **Menu 2.0**, na página [Feature Flags](/admin/feature_flags/pro__feature_flags/), controla qual layout está ativo. Ativá-lo ou desativá-lo reformata a barra lateral imediatamente; nenhuma reinicialização é necessária e nada mais na sua instância muda.

Novas instalações começam com ele ativado. Instalações existentes começam com ele desativado, de modo que uma atualização nunca reorganiza o menu de uma equipe no meio do expediente — ative-o quando seus administradores estiverem prontos.

Enquanto estiver desativado, a página **All Settings** fica indisponível e sua URL retorna Not Found.
