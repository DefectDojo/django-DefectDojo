---
title: ❓ Perguntas frequentes
description: FAQ do DefectDojo
draft: 'false'
weight: 2
chapter: true
aliases:
- /pt-br/en/about_defectdojo/faq
---

Aqui estão algumas perguntas frequentes sobre como trabalhar com o DefectDojo - tanto no DefectDojo Pro quanto no DefectDojo OS.

## Perguntas gerais

### Como devo organizar meus testes de segurança no DefectDojo?

Embora o DefectDojo possa dar suporte a qualquer ambiente de segurança ou de testes, a equipe e as operações de segurança de cada organização são diferentes, portanto não existe uma abordagem única para usá-lo. Temos um artigo bem detalhado sobre [casos de uso comuns](/get_started/common_use_cases/common_use_cases/) com exemplos de como diferentes organizações aplicam o RBAC e o modelo de dados do DefectDojo para atender às suas necessidades.

### Quais são os fluxos de trabalho recomendados para testes de segurança no DefectDojo?

O DefectDojo tem como objetivo ser a fonte central de verdade para a postura de segurança da sua organização, e pode atender a diferentes necessidades dependendo dos requisitos da sua organização, como:

- Permitir que os usuários identifiquem achados duplicados entre scans e ferramentas, minimizando a fadiga de alertas.
- Aplicar SLAs em vulnerabilidades, garantindo que sua organização trate cada Achado dentro de um prazo adequado.
- [Enviar tickets](/connectors/issue_tracking/) para o Jira, ServiceNow ou outro software de rastreamento de projetos, permitindo que sua equipe de desenvolvimento integre a remediação de problemas ao seu processo padrão de release sem precisar aprender outra ferramenta de gerenciamento de projetos.
- Integrar-se a [pipelines de CI/CD](/import_data/import_scan_files/api_pipeline_modelling/) automatizados para ingerir automaticamente dados de relatórios de repositórios, até mesmo no nível de branch.
- Criar [relatórios](/metrics_reports/reports/) sobre qualquer conjunto de vulnerabilidades ou contexto de software, para compartilhar rapidamente resultados de scans ou atualizações de status com as partes interessadas.
- Estabelecer fluxos de trabalho de aceitação e mitigação, dando suporte ao rastreamento formal de gerenciamento de risco.


O DefectDojo é projetado para dar suporte e padronizar seu fluxo de trabalho de segurança atual. Todos esses métodos podem ser usados para aprimorar os processos da sua equipe e se adaptar à forma como você opera atualmente.

### Quais recursos estão disponíveis no DefectDojo Pro?

O DefectDojo Pro expande ainda mais os fluxos de trabalho acima, adicionando:

- Uma [UI aprimorada](/get_started/about/ui_pro_vs_os/) projetada para velocidade e eficiência ao navegar por volumes de dados de nível empresarial. Também inclui um modo escuro.
- A capacidade de [pré-triar seus Achados](/asset_modelling/pro_hierarchy/priority_sla/) por Prioridade e Risco, permitindo que sua equipe identifique e corrija primeiro os problemas mais críticos.
- Um [Rules Engine](/automation/rules_engine/about) para automatizar ações em massa via script e criar fluxos de trabalho personalizados para lidar com Achados e outros objetos, sem exigir experiência em programação.
- [Recursos aprimorados de geração de relatórios e métricas](/get_started/about/ui_pro_vs_os/#new-dashboards) para compartilhar facilmente a postura de segurança dos seus aplicativos e repositórios.
- [Configurações avançadas de deduplicação](/triage_findings/finding_deduplication/pro__deduplication_tuning/) para ajustar com precisão como o DefectDojo identifica e gerencia achados duplicados.
- Recursos de importação simplificados, como:
  - Um método de upload otimizado que processa os Achados em segundo plano.
  - A capacidade de criar rapidamente um [pipeline de linha de comando](/import_data/pro/specialized_import/external_tools/) usando nossos aplicativos Universal Importer e DefectDojo CLI, permitindo que você importe, reimporte e exporte dados facilmente para sua instância do DefectDojo Pro.
  - Um [Universal Parser](/import_data/pro/specialized_import/universal_parser/) para transformar qualquer relatório .json ou .csv em um conjunto acionável de Achados, deixando o DefectDojo Pro analisar os dados como você preferir.
  - [Connectors](/connectors/upstream/about/), que fornecem uma conexão instantânea com ferramentas suportadas para importar novos dados de Achados, para que você possa estabelecer um pipeline de importação automatizado sem precisar configurar chamadas de API ou cron jobs.

### Como o DefectDojo lida com o controle de acesso?

O DefectDojo pode ser usado por equipes grandes, e configurar o [RBAC (Controle de Acesso Baseado em Regras)](/admin/user_management/about_perms_and_roles/) é altamente recomendado, tanto para estabelecer adequadamente o contexto de cada membro da equipe quanto para controlar o acesso a determinadas partes da infraestrutura.

A atribuição de papéis e permissões geralmente ocorre no nível de Tipo de produto / Produto. Cada membro da equipe pode ser atribuído a um ou mais Produtos ou Tipos de produto, e pode receber um papel que determina como ele pode interagir com os dados de vulnerabilidade contidos ali (somente leitura, leitura e escrita, ou controle total). Para mais informações, consulte nosso [guia de RBAC](/admin/user_management/about_perms_and_roles/).

### Como o DefectDojo lida com o controle de acesso para uma equipe de usuários?

Seja você uma equipe de segurança de uma única pessoa em uma organização pequena ou um CISO supervisionando um grande número de projetos de software, você pode organizar facilmente o [Controle de Acesso Baseado em Papéis (RBAC)](/admin/user_management/about_perms_and_roles/) para estabelecer adequadamente o contexto de cada membro da equipe e controlar o acesso a determinadas partes da infraestrutura.

Geralmente, a atribuição de papéis e permissões ocorre no nível de [Tipo de produto/Produto](/asset_modelling/os_hierarchy/product_hierarchy/). Cada membro da equipe pode receber um papel referente a um ou mais Produtos ou Tipos de produto que determina como ele pode interagir com os dados de vulnerabilidade contidos ali (por exemplo, somente leitura, leitura e escrita, ou controle total).

## Fluxos de trabalho de importação

### Quais ferramentas são suportadas pelo DefectDojo?

O DefectDojo suporta relatórios de [mais de 500](/supported_tools/) ferramentas de segurança comerciais e open-source.

Se você está buscando adicionar uma nova ferramenta ao seu conjunto, temos uma lista de ferramentas Open-Source recomendadas que você pode conferir [aqui](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards).

### Qual é a diferença entre Import e Reimport?

Existem dois métodos diferentes para importar um único relatório de uma ferramenta de segurança:

- **Import** trata o relatório como um único registro pontual no tempo. Importar um relatório cria um Teste contendo os Achados resultantes.
- **[Reimport](/import_data/import_intro/reimport/)** é usado para atualizar um Teste existente com um novo conjunto de resultados. Se você tiver uma abordagem mais aberta para o seu processo de testes, pode Reimportar continuamente a versão mais recente do seu relatório para um Teste existente. O DefectDojo comparará os resultados do relatório recebido com seus dados existentes, registrará quaisquer alterações e ajustará os Achados no Teste para corresponder ao relatório mais recente.

Para entender a diferença, é útil pensar no Import como o registro de uma única instância de um evento de scan, e no Reimport como a atualização de um registro contínuo de scans.

Aqui está uma analogia: se você fosse um contador, poderia usar o Import para registrar um único recibo, enquanto usaria o Reimport para manter um livro-razão contínuo de despesas

Ambos os métodos também usam a Deduplicação de forma diferente: enquanto dois Testes Importados distintos no mesmo Produto identificarão e rotularão Achados duplicados separadamente, o Reimport não criará nenhum Achado que identificar como [duplicado](/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport/) dentro do Teste.

De forma geral, se o que você precisa é de um relatório pontual, o Import é o melhor método a ser usado. Se você está executando e ingerindo relatórios de uma ferramenta continuamente, o Reimport é o melhor método para manter tudo organizado.

### Como posso solucionar erros de Import?

O DefectDojo suporta uma ampla variedade de ferramentas. Se você estiver vendo um comportamento inconsistente ao importar um relatório, recomendamos verificar se a estrutura do arquivo corresponde ao que a ferramenta espera. Consulte nossa [Lista de parsers](/supported_tools/) para confirmar que sua ferramenta é suportada, e verifique se o formato do arquivo corresponde ao esperado pela ferramenta. Você também pode comparar a estrutura com nossos Testes unitários.

O DefectDojo Pro possui um método de importação Universal Parser que permite lidar com qualquer arquivo JSON, CSV ou XML. Os usuários do DefectDojo OS podem escrever parsers personalizados para o mesmo propósito.

Por fim, é sabido que os formatos de relatório de terceiros podem mudar sem aviso prévio: nossa comunidade OS agradece muito [PRs e contribuições](/get_started/contributing/how-to-write-a-parser/) para manter nossos parsers atualizados.

### Como devo lidar com arquivos de scan grandes?

Importar um relatório grande para o DefectDojo pode ser um processo demorado. Relatórios de 2MB contêm quantidades substanciais de dados, o que pode levar bastante tempo para ser convertido em Achados, dependendo do formato de relatório da ferramenta de segurança.

Nossa abordagem recomendada é dividir relatórios grandes antes da importação, refletindo diferentes subseções dos dados disponíveis. Se sua ferramenta de segurança puder filtrar resultados por projeto de software, aplicação ou outro contexto, exportar relatórios menores facilita para o DefectDojo lidar com os dados e categorizá-los. Isso também tem o benefício adicional de organizar proativamente seus Achados com base em como os dados foram divididos, o que resulta em uma geração de relatórios mais relevante e rápida.

O DefectDojo Pro pode processar relatórios em segundo plano. No entanto, os arquivos ainda precisam ser enviados e validados pelo DefectDojo antes que o processo de criação de Achados em segundo plano possa começar.

### Como conecto um pipeline de CI/CD ao DefectDojo?

Muitos dos recursos essenciais do DefectDojo podem ser totalmente automatizados. O CI/CD (ou qualquer tipo de importação automatizada) pode ser tratado chamando a [API REST do DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/).

Os usuários do **DefectDojo Pro** também têm acesso às [ferramentas de linha de comando](/import_data/pro/specialized_import/external_tools/) **Universal Importer / DefectDojo CLI**, que podem ser instaladas para execução em diversos ambientes automatizados.

## Gerenciamento de achados

### O que significa o status de um Achado?

Os Achados podem ter vários status. Um status de Ativo ou Inativo é sempre definido para um Achado, enquanto outros status, como Verificado, Falso positivo ou Fora do escopo, podem ser aplicados a seu critério.

Esses status são descritos em mais detalhes em nosso guia de [Definições de status de achados](/triage_findings/findings_workflows/finding_status_definitions/), junto com informações sobre como podem ser usados.

### Como posso excluir Achados do DefectDojo?

De forma geral, recomendamos manter os Achados fechados como "Inativos" em vez de excluí-los completamente, pois é importante manter registros históricos no trabalho de AppSec. Excluir um Achado removerá completamente todas as notas e o rastreamento de métricas desse Achado, o que pode levar a relatórios imprecisos ou a um arquivo incompleto.

Os Achados do DefectDojo podem ser excluídos de algumas formas:
- Executando uma ação de [Exclusão em massa](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings) sobre os Achados que você deseja excluir
- Chamando `DELETE /findings/{id}` através da API
- Excluindo um objeto pai, como um Teste, Engajamento, Tipo de produto ou Produto.
  - Observe que as subclasses não são preservadas independentemente do seu objeto pai: excluir um objeto pai como um Tipo de produto excluirá todos os Produtos, Engajamentos, Testes, Achados e Endpoints dentro do Tipo de produto. Por outro lado, excluir um Engajamento preservará os Produtos e Tipos de produto que o precedem.

## Relatórios e Jira

### Como posso gerar um relatório no DefectDojo?

Você pode criar rapidamente um relatório personalizado no DefectDojo usando o [Report Builder](/metrics_reports/reports/).

Os usuários do DefectDojo Pro também têm acesso a [painéis de Métricas de nível executivo](/get_started/about/ui_pro_vs_os/#new-dashboards) que podem reportar sobre Tipos de produto, Produtos ou outros dados em tempo real.

### Como posso integrar uma ferramenta de gerenciamento de projetos com o DefectDojo?

Tanto na edição Pro quanto na Open-Source do DefectDojo, os Achados no DefectDojo podem ser enviados ao Jira como Issues, o que permite integrar a remediação de problemas com sua equipe de desenvolvimento.

O DefectDojo Pro adiciona suporte para [Integrações adicionais de rastreamento de projetos](/connectors/issue_tracking/)**: ServiceNow, Azure DevOps, GitHub e GitLab.
