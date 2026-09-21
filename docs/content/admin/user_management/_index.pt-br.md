---
title: Gerenciamento de Usuários
description: Gerencie usuários, controle de acesso e autenticação no DefectDojo
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

A superfície de gerenciamento de usuários do DefectDojo é diferente em cada edição. Escolha a seção que corresponde à sua instalação.

## DefectDojo Open-Source

O DefectDojo open-source usa o modelo de **Usuários Autorizados**: um usuário recebe acesso a um Produto ou a um Tipo de Produto ao ser adicionado à lista de Usuários Autorizados desse registro. Superusuários e a equipe (staff) podem ver tudo.

* [Usuários Autorizados](./os__authorized_users/) — como conceder acesso a Produtos e Tipos de Produto

A autenticação no DefectDojo open-source é feita por usuário/senha local, além do fluxo de redefinição de senha.

## DefectDojo Pro

O DefectDojo Pro usa um sistema baseado em papéis (roles) com Membros, Grupos e Papéis Globais. Os usuários também podem receber acesso via SSO através de SAML ou de um dos provedores OAuth suportados.

* [Permissões no DefectDojo](./about_perms_and_roles/) — visão geral de Papéis, Associações, Papéis Globais e Permissões de Configuração
* [Definir as Permissões de um Usuário](./set_user_permissions/) — atribuindo Papéis, Papéis Globais e Permissões de Configuração
* [Compartilhar permissões: Grupos de Usuários](./create_user_group/) — atribuindo permissões a vários usuários de uma vez
* [Definir Permissões no Pro](./pro_permissions_overhaul/) — interface específica do Pro para gerenciar Membros e Permissões
* [Redefinindo credenciais de usuários em massa](./pro__resetting_user_credentials/) — rotacione tokens de API e force a redefinição de senha para vários usuários de uma vez
* [Tabelas de permissões por ação](./user_permission_chart/) — referência completa de cada permissão para cada Papel integrado
* [Papéis RBAC Personalizados](./pro__custom_rbac_roles/) — crie seus próprios papéis escolhendo permissões individuais
* [Single Sign-On](/admin/sso/) — configuração de SAML e OAuth para o Pro

## Migrando entre edições

Se você está migrando dos Usuários Autorizados do open-source para o RBAC do Pro, ou atualizando de uma versão open-source anterior à 3.0 que usava RBAC para o modelo atual de Usuários Autorizados, consulte as [notas de atualização da 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization). O acesso existente é preservado automaticamente.
