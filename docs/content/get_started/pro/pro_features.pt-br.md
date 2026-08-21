---
title: 📊 Lista de Recursos Pro
description: Lista de recursos do Pro no DefectDojo
draft: 'false'
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
- /pt-br/en/about_defectdojo/pro_features
---

Aqui está uma lista dos muitos recursos adicionais do DefectDojo Pro, com links para a documentação para vê-los em ação:

## UX Aprimorada

### UI Pro

A UI do DefectDojo foi reformulada no DefectDojo Pro para ser mais rápida, mais funcional, totalmente personalizável e melhor na navegação por volumes de dados de nível empresarial.  Também inclui um modo escuro.  
Veja nosso [Guia da UI Pro](/get_started/about/ui_pro_vs_os/) para mais informações.

![image](images/enabling_deduplication_within_an_engagement_2.png)

### Busca Global

Encontre qualquer Achado, Ativo, Engajamento e muito mais a partir de uma única caixa de busca na barra superior. A busca global do DefectDojo Pro abrange seus objetos com uma busca de texto completo do Postgres rápida e tolerante a erros de digitação.

Veja nosso [Guia de Busca Global](/navigation/pro__global_search/) para mais informações.

### Ativos/Organizações

O DefectDojo Pro permite uma visualização organizacional aprimorada para grandes listas de repositórios ou outras estruturas de negócio.  Veja a [documentação de Ativos/Organizações](/asset_modelling/pro_hierarchy/asset_hierarchy/) para mais detalhes.

![image](images/asset_hierarchy_diagram.png)

### Prioridade de Achados

O DefectDojo Pro pode pré-triar seus Achados por Prioridade e Risco, permitindo que sua equipe identifique e corrija primeiro os problemas mais críticos.
Veja nosso [Guia de Prioridade de Achados](/asset_modelling/pro_hierarchy/priority_sla/) para mais detalhes.

### Motor de Regras

O Motor de Regras do DefectDojo Pro permite programar ações automatizadas em massa e criar fluxos de trabalho personalizados para lidar com Achados e outros objetos, sem necessidade de experiência em programação.

Veja nosso [Guia do Motor de Regras](/automation/rules_engine/about) para mais informações.

![image](images/rules_engine_4.png)

### Sensei

O **Sensei** (BETA) do DefectDojo Pro é um recurso de varredura e correção com IA: conecte um repositório por meio de um GitHub App e o Sensei o varre, importa os achados e abre pull requests que os corrigem — com um fluxo de trabalho de pré-visualização em primeiro lugar, de modo que nada é executado (e nenhum custo de LLM é incorrido) até que você aprove.

Veja nosso [Guia do Sensei](/sensei/about_sensei/) para mais informações.

### Painéis e Relatórios Pro

Gere [relatórios e métricas instantâneos](/get_started/about/ui_pro_vs_os/#new-dashboards) para compartilhar a postura de segurança de suas aplicações e repositórios, avaliar suas ferramentas de segurança e analisar o desempenho da sua equipe na resolução de problemas de segurança.

Os gráficos da página inicial podem ser exportados como arquivos SVG, e os dados usados para criar os gráficos também podem ser exportados como uma tabela. 

Além disso, o DefectDojo Pro inclui vários novos [painéis de insights](/metrics_reports/pro_metrics/pro__overview/), oferecendo métricas aprimoradas para os diversos públicos do seu programa de segurança.

### Ajuste Fino de Deduplicação

As configurações avançadas de Deduplicação permitem ajustar com precisão a forma como o DefectDojo identifica e gerencia achados duplicados. Ajuste a Deduplicação de mesma ferramenta, **entre ferramentas**, e de reimportação para uma correspondência precisa entre todas as ferramentas de segurança escolhidas e os achados de vulnerabilidade. 

Veja nosso [Guia de Ajuste Fino de Deduplicação](/triage_findings/finding_deduplication/pro__deduplication_tuning/) para mais informações.

![image](images/deduplication_tuning.png)

## Importação simplificada

### Mais Opções de Importação

O DefectDojo Pro inclui quatro métodos adicionais de importação: [Universal Importer](/import_data/pro/specialized_import/external_tools/), [Upstream Connectors](/connectors/upstream/about/), [Universal Parser](/supported_tools/parsers/universal_parser/) e [Smart Upload](/import_data/pro/specialized_import/smart_upload/).

![image](images/pro_import_methods.png)


### Importações em Segundo Plano

Para relatórios de nível empresarial, o DefectDojo Pro oferece um método de upload otimizado que processa os Achados em segundo plano.

### Ferramentas de CLI

Construa rapidamente um pipeline de linha de comando para importar, reimportar e exportar dados para sua instância do DefectDojo Pro usando nossos aplicativos Universal Importer e DefectDojo-CLI; não é necessário criar scripts de API (disponível para Windows, Macintosh ou Linux).

Veja nosso [Guia de Ferramentas Externas](/import_data/pro/specialized_import/external_tools/) para mais informações.

### Upstream Connectors

O DefectDojo pode se conectar instantaneamente a ferramentas de varredura de nível empresarial para importar novos dados de Achados, criando um pipeline de Importação automatizado que funciona de forma imediata, sem a necessidade de configurar chamadas de API ou cron jobs. 

Veja nosso [Guia de Upstream Connectors](/connectors/upstream/about/) para mais informações.

![image](images/add_edit_connectors_2.png)

As ferramentas suportadas para Upstream Connectors incluem:

* Anchore
* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### Universal Parser (Beta)

Se você estiver usando uma ferramenta de varredura não suportada/personalizada, ou simplesmente desejar que o DefectDojo trate um relatório de forma um pouco diferente, use o Universal Parser do DefectDojo Pro para transformar qualquer relatório .json ou .csv em um conjunto acionável de Achados. Seu parser irá analisar e mapear os dados da forma que você quiser.

Veja nosso [Guia do Universal Parser](/import_data/pro/specialized_import/universal_parser//) para mais informações.

![image](images/universal_parser_3.png)

## Gerenciando recursos opcionais

Muitos dos recursos acima são opcionais e são disponibilizados por trás de uma feature flag, para que você possa adotá-los quando estiver pronto. Um superusuário pode ativar e desativar a maioria deles diretamente em **Settings > Feature Flags**, sem precisar contatar o suporte.

Veja o guia de [Feature Flags](/admin/feature_flags/pro__feature_flags/) para saber como ativar um recurso, e entender por que um recurso pode estar bloqueado ou indisponível para o seu tipo de instalação.

## Suporte

As assinaturas do DefectDojo Pro incluem suporte de classe mundial tanto para instalações on-premise quanto em Cloud.  Nossa equipe está disponível para ajudar sua organização a implementar e maximizar o uso do DefectDojo Pro.  Sua assinatura inclui:

- **Suporte Abrangente**: Tickets de suporte e assentos ilimitados estão disponíveis para atender toda a sua equipe.
- **Foco Dedicado de Engenharia**: Problemas relatados por usuários, bugs e solicitações de recursos recebem atenção prioritária de nossa equipe de engenharia.
- **Gerenciamento de SaaS**: Fornecemos monitoramento, manutenção e backups para todas as instâncias SaaS.
