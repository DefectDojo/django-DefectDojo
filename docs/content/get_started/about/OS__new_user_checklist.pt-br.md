---
title: ☑️ Checklist do Novo Usuário
description: Comece a Usar o DefectDojo
draft: 'false'
weight: 3
audience: opensource
---

Aqui está uma referência rápida que você pode usar para garantir uma implementação bem-sucedida, partindo de uma tela em branco até um aplicativo totalmente funcional.  Este artigo pressupõe que você tenha o **DefectDojo Community Edition** instalado e em execução no seu ambiente.

A essência do DefectDojo é importar dados de segurança, organizá-los e apresentá-los para quem precisa saber.  Veja como alcançar isso no DefectDojo Open-Source:

### DefectDojo Open-Source

1. Os usuários do Open-Source podem começar criando seu primeiro [Product Type e Produto](/asset_modelling/os_hierarchy/product_hierarchy/).  Depois de criados, eles podem [importar um arquivo](/import_data/import_scan_files/os__import_scan_ui/) para um desses Produtos usando a UI.

2. Agora que você já tem dados no DefectDojo, considere expandir o layout do seu Produto com a [Visão Geral da Hierarquia de Produto](/asset_modelling/os_hierarchy/product_hierarchy/). A Hierarquia de Produto cria um inventário funcional dos seus apps, o que ajuda a dividir seus dados em categorias lógicas. Essas categorias podem ser usadas para aplicar regras de controle de acesso, ou para segmentar seus relatórios para a equipe correta.

3. Use o [Report Builder](/metrics_reports/reports/using-the-report-builder/#opening-the-report-builder) para resumir os dados que você importou. Os Relatórios podem ser usados para compartilhar rapidamente Achados com stakeholders, como os Product Owners.

Essa é a essência do DefectDojo - importar dados de segurança, organizá-los e apresentá-los para quem precisa saber.

Todos esses recursos podem ser automatizados, e como o DefectDojo suporta mais de 500 ferramentas (no momento em que este texto foi escrito), você já tem tudo o que precisa para criar um inventário de segurança funcional de toda a produção da sua organização.

### Recursos do Open-Source
- Sua organização usa Jira? Aprenda a usar nossa [integração com Jira](/connectors/os_jira/os__jira_guide/) para criar tickets no Jira a partir dos dados que você importa.
- Você planeja compartilhar o DefectDojo com muitos usuários na sua organização? Confira nossos guias de [gerenciamento de usuários](/admin/user_management/about_perms_and_roles/) e configure o controle de acesso baseado em papéis (RBAC).
- Pronto para mergulhar na automação? Aprenda a usar a [API do DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/) para importar automaticamente novos dados e construir um pipeline de CI/CD robusto.
