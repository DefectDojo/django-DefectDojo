---
title: Achados
description: Entendendo os Achados no DefectDojo Pro
audience: pro
weight: 5
---

Organizations	→ Assets → Engagements → Tests → **FINDINGS**

## Overview
**Achados** representam o nível mais baixo da Hierarquia de Produtos, onde vulnerabilidades individuais são rastreadas e gerenciadas, e servem como a principal forma pela qual o DefectDojo padroniza e orienta o processo de reporte e remediação das suas ferramentas de segurança. Independentemente de uma vulnerabilidade ter sido reportada no SonarQube, Acunetix ou na ferramenta personalizada da sua equipe, os Achados oferecem a capacidade de gerenciar cada vulnerabilidade da mesma forma.

Exemplos de Achados incluem:
- **Cookie Não Marcado como HttpOnly**
- **Versão Desatualizada (PHP)**
- **Avaliação de Código Fora de Banda (PHP)**
- **Versão Desatualizada (MySQL)**
- **Código-Fonte de Backup Detectado**
- **Cross-Site Scripting Cego**

Além de armazenar os dados da vulnerabilidade e fornecer um framework de remediação, o DefectDojo também aprimora seus Achados das seguintes formas:
- Adicionando automaticamente as pontuações EPSS relacionadas a um Achado para descrever sua explorabilidade
- Traduzindo automaticamente a métrica de severidade de uma ferramenta de segurança em uma pontuação de Severidade para cada Achado, o que atribui um SLA ao Achado de acordo com a configuração de SLA do seu Ativo. Para mais informações sobre a configuração de SLA, clique [aqui](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

No geral, os Achados são projetados para funcionar com a Hierarquia de Produtos, padronizando seus esforços e aplicando um método consistente a cada Ativo.

## Accessing Findings
Os Achados são acessíveis pela barra lateral. O submenu oferece acesso aos Achados Ativos e Mitigados, Todos os Achados (independentemente do status Aberto ou Fechado), Grupos de Achados, Modelos de Achados e o fluxo de Novo Achado. Achados individuais também são acessíveis a partir do Teste que os contém.

[Achados com Risco Aceito] (/triage_findings/findings_workflows/os__risk_acceptance/) são acessíveis a partir da seção **Aceitações de Risco** da barra lateral.

![image](images/profindings_ss1.png)

### Permissions
Todo Achado pertence a um Teste, o que permite que o DefectDojo preserve qual scan ou avaliação identificou originalmente a vulnerabilidade.

Como os Achados pertencem a Testes, o acesso aos Achados é determinado pelo acesso do Usuário ao Ativo que contém o Teste. Os Testes não possuem listas de controle de acesso independentes.

## Findings View
As visualizações de Achado contêm uma variedade de tabelas para ajudar a interpretar o status de um Achado rapidamente.

### Finding Overview
- **Descrição**: A descrição do Achado (adicionada automaticamente dependendo do tipo de Achado, ou criada manualmente).
- **Mitigação**: Passos sugeridos para mitigar.
- **Política de Mitigação Geral**: A política de mitigação padronizada para o Achado selecionado.
As políticas de mitigação podem ser encontradas e editadas na barra lateral em **Configuration** → **Mitigation Policies**.
- **Impacto**: Impacto potencial de deixar o Achado sem solução.
- **Referências**: URL para referência cruzada com a descrição específica que a ferramenta de scan de terceiros dá ao Achado. Por exemplo, as Referências podem ser links para uma entrada relevante em um catálogo de Achados, ou uma única URL de advisory.
- **Arquivos**: Quaisquer arquivos que tenham sido adicionados para contextualizar o Achado.
- **Notas**: Notas deixadas por Usuários relacionadas ao Achado. Marcar uma nota como Privada significa que ela não será incluída em nenhum relatório gerado que contenha o Achado selecionado.

### Metadata
- **ID**: O ID exclusivo do Achado no DefectDojo.
- **Organização, Ativo, Engajamento e Teste**: Os objetos pai do Achado selecionado.
- **Status**: O status do Achado (por exemplo, Ativo, Verificado, Falso positivo, Duplicado, Fora do escopo e Em Revisão de Defeito).
- **Severidade**: A classificação de severidade daquele Achado, aplicada automaticamente.
    - Como mencionado acima, o DefectDojo traduz automaticamente a métrica de severidade de uma ferramenta de segurança em uma pontuação de Severidade para cada Achado, o que atribui um SLA ao Achado de acordo com a configuração de SLA do seu Ativo.
- **Risco**: Um sistema de classificação de 4 níveis que leva em conta a explorabilidade de um Achado e é aplicado automaticamente.
    - Detalhes sobre como a prioridade, o risco e os SLAs são calculados podem ser encontrados [aqui](/asset_modelling/pro_hierarchy/priority_sla/#main-content). Mais detalhes sobre as definições de status e nível de risco do Achado podem ser encontrados [aqui](/triage_findings/findings_workflows/finding_status_definitions/).
- **Prioridade**: Uma classificação numérica calculada, aplicada a todos os Achados, que permite entender rapidamente as vulnerabilidades em contexto.
- **Idade**: Há quanto tempo existe o Achado selecionado.
- **SLA**: A data limite prevista para a resolução do Achado.
- **Tipo**: Se o Achado foi detectado por uma ferramenta de segurança de aplicação estática ou dinâmica (Static, Dynamic ou Static/Dynamic).
- **Localização e Linha**: O arquivo e o número da linha em que o Achado selecionado foi encontrado.
- **Nome e Versão do Componente**: O nome e a versão do componente em que o Achado selecionado foi encontrado.
- **Data de Descoberta**: A data em que o Achado foi descoberto.
- **Data e Versão de Remediação Planejada**: A data em que o Achado deve ser remediado, e a versão do componente afetado na qual a correção será implementada.
- **Serviço**: Serviços Conectados (partes autocontidas de funcionalidade dentro de um Ativo) que são afetados pelo Achado selecionado. Quando preenchido, esse campo é incluído na correspondência de deduplicação (ou seja, Achados com campos de Serviço idênticos serão deduplicados).
- **Relator**: O Usuário que revelou o Achado.
- **CWE**: A classificação de fraqueza CWE do Achado. Um Achado pode ter **múltiplos CWEs** — um CWE primário, mais quaisquer CWEs adicionais fornecidos pela ferramenta de reporte. O CWE primário é o utilizado para deduplicação legada e cálculo de hash code; o conjunto completo de CWEs também pode ser usado para correspondência por meio dos Hash Code Fields baseados em conjunto do Pro (veja [Ajuste de Deduplicação](/triage_findings/finding_deduplication/pro__deduplication_tuning/#set-based-hash-code-fields-vulnerability-ids-and-cwes)).
    - Um CWE descreve uma *classe* de fraqueza (por exemplo, "SQL Injection"), não uma instância específica de vulnerabilidade — é para isso que servem os IDs de Vulnerabilidade.
- **IDs de Vulnerabilidade**: Identificadores de vulnerabilidade publicamente reconhecidos associados ao Achado, como CVE, GHSA, ou outras referências de advisory padronizadas. No DefectDojo Pro, eles também são usados para realizar consultas de EPSS e KEV.
    - Os IDs de Vulnerabilidade são armazenados como registros de primeira classe, de modo que o mesmo CVE é rastreado uma única vez e compartilhado por todo Achado que o referencia. Você pode revisá-los — junto com seus valores de EPSS e KEV — no **Vulnerability Explorer**. Veja [EPSS / KEV](/triage_findings/finding_scoring/epss_kev/#viewing-kevepss-in-the-vulnerability-explorer).
- **Unique ID From Tool**: Um identificador estável atribuído pela ferramenta de origem a uma instância específica de Achado. Os Unique IDs devem permanecer consistentes entre scans repetidos, permitindo que a ferramenta reconheça o mesmo Achado ao longo do tempo.
    - Diferentemente dos IDs de Vulnerabilidade, esse valor é proprietário da ferramenta de reporte e não é uma referência pública de vulnerabilidade.
        - Exemplo: `finding-12345`
- **Vulnerability ID From Tool**: Um identificador proprietário de vulnerabilidade ou regra, atribuído pela ferramenta de origem para descrever o tipo de vulnerabilidade detectada.
    - Diferentemente do Unique ID From Tool, esse identificador não é exclusivo de um Achado individual e pode aparecer em vários Achados que correspondem à mesma regra de detecção.
    - Diferentemente dos IDs de Vulnerabilidade, esses identificadores são específicos da ferramenta de reporte e não são padronizados publicamente.
        - Exemplo: `semgrep.rule.lang.security.sql-injection`
- **EPSS Score / Percentile**: A pontuação e o percentil de EPSS para o CVE.
- **Known Exploited**: Se há confirmação de que a vulnerabilidade foi explorada.
- **Ransomware Used**: Se houve uso de ransomware na exploração da vulnerabilidade.
- **KEV Date**: A data em que o Achado foi adicionado ao catálogo KEV.
- **Found By**: O tipo de ferramenta que identificou a vulnerabilidade.
- **CVSSv3 and CVSSv4 Vector and Score**: O vetor e a pontuação CVSS3 e CVSS4 do Achado selecionado.
- **Integrator Tickets**: Números de tickets de rastreadores de issues de terceiros associados ao Achado.

### Vulnerable Endpoints
Esta seção inclui uma tabela dos Endpoints afetados pelo Achado selecionado, junto com quaisquer metadados relevantes.

### Additional Details
- **Request/Response Pairs**: Uma cópia da mensagem enviada pelo cliente e da resposta do servidor à requisição.
- **Steps to Reproduce**: Passos para reproduzir o Achado.
- **Severity Justification**: Descrição por escrito de por que uma determinada classificação de Severidade foi associada ao Achado.

## Findings Data
Os Achados exigem os seguintes metadados:
- **Nome**
- **Data**
- **Severidade**
- **Descrição**

Além dos metadados correspondentes às tabelas na visualização de um Achado, os campos de metadados opcionais incluem:
- **Tags**: Quaisquer tags que tenham sido adicionadas ao Achado.
- **Owners**: O grupo de usuários que será responsável pelo Achado selecionado.
- **Push to Jira**: Envia o Achado para o Jira para fins de emissão de tickets.
- **Push to Integrator**: Envia o Achado para quaisquer rastreadores de issues de terceiros integrados.
- **Configurações de risco e prioridade**: Oferece a opção de substituir o cálculo automático que o DefectDojo faz do risco e da prioridade do Achado.
- **Endpoints a adicionar**: Endpoints vulneráveis que podem ser afetados pelo Achado selecionado e que não estão refletidos na lista anterior de sistemas/endpoints.
- **Revisão de defeito solicitada por**: Registra quem solicitou uma revisão de defeito para a falha em questão.
- **Objeto de origem SAST, número da linha e caminho do arquivo**: Objeto de origem, número da linha e caminho do arquivo do vetor de ataque.
- **Objeto de destino (sink) SAST**: Objeto de destino do vetor de ataque.
- **Número de ocorrências**: Número de ocorrências na ferramenta de origem quando várias vulnerabilidades foram encontradas e agregadas pelo scanner.
- **Data de publicação**: A data em que a vulnerabilidade foi publicada.
- **Estimativa de esforço**: O nível de esforço envolvido na correção do Achado (por exemplo, Baixo, Médio ou Alto).

Os metadados exatos disponíveis dependerão do parser/scanner que revelou o Achado. Alguns fornecem apenas informações básicas, como título e severidade, enquanto outros incluem vetores CVSS, componentes vulneráveis, endpoints, pares de requisição/resposta e outros metadados específicos do scanner.

Esses metadados melhoram a filtragem, os relatórios e a priorização em todo o seu programa de segurança, permitindo o rastreamento de longo prazo e a análise de tendências. Detalhes adicionais e descrições de metadados podem ser encontrados [aqui](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page).

### Deduplication
O DefectDojo inclui recursos de deduplicação que ajudam a identificar e gerenciar Achados que representam a mesma vulnerabilidade subjacente. À medida que os resultados de scan são importados de uma ou mais ferramentas, o DefectDojo usa uma lógica de correspondência configurável para identificar Achados que representam a mesma vulnerabilidade.

A deduplicação evita que a mesma vulnerabilidade apareça múltiplas vezes quando descoberta repetidamente pelo mesmo scanner ou por scanners diferentes, permitindo que o histórico de remediação permaneça vinculado a um único Achado.

Mais informações sobre deduplicação podem ser encontradas [aqui](/triage_findings/finding_deduplication/about_deduplication/).

### Reimport
A função de Reimportação do DefectDojo permite que os Achados sejam atualizados à medida que novos resultados de scan são importados. Quando um scan é reimportado, o DefectDojo compara os resultados recebidos com os Achados existentes e atualiza os registros correspondentes em vez de criar registros inteiramente novos. Isso preserva contexto valioso, como mudanças de status, histórico de remediação, comentários e informações de propriedade, fornecendo um registro contínuo do ciclo de vida de um Achado ao longo de múltiplos ciclos de teste.

Mais informações sobre a função de Reimportação podem ser encontradas [aqui](/import_data/import_intro/reimport/).

### Risk Acceptances
As Aceitações de Risco são um status especial que pode ser aplicado aos Achados para documentar formalmente e operacionalizar a decisão de reconhecê-los sem remediá-los imediatamente.

Mais informações sobre Aceitações de Risco podem ser encontradas [aqui](/triage_findings/findings_workflows/pro__risk_acceptance/).

### Statuses
Cada Achado criado no DefectDojo possui um Status que comunica informações relevantes e ajuda sua equipe a acompanhar o progresso na resolução dos problemas.

Mais informações sobre Status podem ser encontradas [aqui](/triage_findings/findings_workflows/finding_status_definitions/).

## Working with Findings

### Creating Findings
Embora a maioria dos Achados seja gerada automaticamente por meio de importações de scan e integrações, o DefectDojo também oferece suporte à criação manual de Achados. Achados manuais são úteis para rastrear vulnerabilidades e questões de segurança identificadas por meio de testes de penetração, revisões de arquitetura, avaliações de conformidade, programas de bug bounty, engajamentos de consultoria ou outras atividades que não produzem saída de scanner.

Os Achados podem ser adicionados manualmente clicando em **Novo Achado** na seção **Findings** da barra lateral, ou selecionando **Adicionar Achado** no menu de engrenagem do Teste ao qual você deseja adicionar o Achado.

### Editing Findings
O menu kebab ⋮ ao lado dos Achados contém as seguintes funções:
- **Editar Achado**: Edita o Achado.
- **Copiar Achado**: Cria uma cópia do Achado em outro Teste. A cópia pode ser salva em qualquer Teste dentro do mesmo Engajamento para o qual você tenha permissão de edição. Copiar é útil quando a mesma vulnerabilidade precisa ser rastreada separadamente em mais de um contexto de Teste.
- **Fechar Achado**: Inicia o processo de fechamento do Achado.
- **Solicitar Revisão**: Inicia o processo de Revisão por Pares e altera o status do Achado para "Under Review." Mais informações sobre Revisões por Pares podem ser encontradas [aqui](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Adicionar Aceitação de Risco**: Inicia o processo de Aceitação de Risco. Mais informações podem ser encontradas [aqui](/triage_findings/findings_workflows/pro__risk_acceptance/).
- **Adicionar Arquivo**: Inicia o processo de adicionar um arquivo ao Achado (veja a seção abaixo).
- **Adicionar Nota**: Inicia o processo de adicionar uma nota ao Achado.
- **Adicionar Campo Personalizado**: Abre um pop-up que permite adicionar e definir um campo personalizado para aplicar ao Achado.
- **Push to Jira**: Envia o Achado para o Jira para fins de emissão de tickets.
- **Push to Integrator**: Envia o Achado para quaisquer rastreadores de issues de terceiros integrados.
- **Excluir Achado**: Exclui o Achado selecionado.
- **Histórico do Achado**: Revela o histórico do Achado selecionado.

#### Attaching Files to Findings
Você pode anexar arquivos a qualquer Achado para fornecer contexto adicional — por exemplo, uma captura de tela de uma vulnerabilidade em ação ou uma imagem de prova de conceito.

Os tipos de arquivo suportados incluem:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Para anexar um arquivo a um Achado, clique em **Adicionar Arquivo** no menu kebab ⋮ ou no menu de engrenagem do Achado selecionado. Digite um Título para o arquivo, escolha o arquivo no seu computador e clique em **Enviar**.

O arquivo então aparecerá na seção Arquivos da tabela **Test Overview** dentro da visualização do Achado.

#### Bulk Edit Findings
Os Achados podem ser editados em massa a partir de uma Lista de Achados, como a tabela de Todos os Achados acessível pela barra lateral, ou a partir da tabela de Achados dentro de um Teste específico.

Mais informações sobre como editar Achados em massa podem ser encontradas [aqui](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings).

### Closing Findings
Depois que o trabalho em um Achado for concluído, você pode fechá-lo manualmente clicando em **Fechar Achado** no menu kebab ⋮ ou no menu de engrenagem do Achado. Alternativamente, se um scan for reimportado no DefectDojo e não contiver um Achado registrado anteriormente, esse Achado registrado anteriormente será fechado automaticamente.

Se você não quiser que nenhum Achado seja fechado, é possível desabilitar esse comportamento no formulário de Reimportação de Scan:

- Desmarque a caixa de seleção Close Old Findings se estiver usando a UI
- Defina close_old_findings como False se estiver usando a API ​

### Deleting Findings
A exclusão de um Achado pode ser feita a partir do menu kebab ⋮ ou do menu de engrenagem do Achado. Essa ação não pode ser desfeita.

Para fins de auditoria, recomenda-se fechar os Achados remediados em vez de excluí-los.

## Finding Groups
**Grupos de Achados** permitem tratar múltiplos Achados relacionados como uma única unidade lógica para triagem, relatórios e coordenação de remediação.

Por exemplo, um scan pode produzir 10 Achados de SQL injection em diferentes endpoints. Em vez de gerenciar cada um independentemente, você pode agrupá-los em um único Grupo de Achados que represente o problema mais amplo de SQL injection.

Um Grupo de Achados não substitui os Achados individuais. Cada Achado continua existindo com sua própria severidade, status, metadados, comentários e histórico de remediação. Um Grupo de Achados simplesmente fornece uma camada organizacional adicional acima dos Achados que ele contém.

### Accessing Finding Groups
Os Grupos de Achados podem ser acessados pela barra lateral. O submenu oferece acesso aos Grupos de Achados Abertos e Fechados, bem como a Todos os Grupos de Achados (independentemente do status de Aberto).

![image](images/profindings_ss1.png)

### Creating Finding Groups
Os Grupos de Achados podem ser criados manualmente ou automaticamente.

Vale destacar que os Grupos de Achados só podem ser criados a partir dos Achados contidos em um único Teste. Achados de Testes, Engajamentos ou Produtos diferentes não podem ser adicionados ao mesmo Grupo de Achados.

#### Manual Finding Groups
Para realizar ações de Grupo de Achados manualmente:
1. Navegue até uma lista de Achados dentro de um Teste.
2. Selecione o(s) Achado(s) que deseja adicionar a um Grupo de Achados clicando na caixa de seleção correspondente do Achado.
3. Clique no botão **Finding Group** que aparece no topo da lista de Achados.
4. Clique na ação correspondente que deseja realizar.
    - **Adicionar a Novo Grupo de Achados**: Cria um novo Grupo de Achados que inclui os Achados selecionados.
    - **Adicionar a Grupo de Achados Existente**: Adiciona os Achados selecionados a um Grupo de Achados pré-existente.
    - **Remover de Grupo de Achados**: Remove os Achados selecionados de quaisquer Grupos de Achados dos quais faziam parte anteriormente.
5. Clique em **Enviar**.

Observe que o agrupamento ficará desabilitado a menos que todo achado selecionado seja editável, não esteja agrupado e esteja no mesmo Teste.

Além disso, observe que a única ação possível ao selecionar Achados na lista Todos os Achados é remover os Achados selecionados de qualquer Grupo de Achados. Isso ocorre porque, como mencionado, os Grupos de Achados só podem ser criados a partir dos Achados contidos em um único Teste.

#### Automatic Finding Groups
Ao importar um scan, o recurso **Group By** dentro do menu recolhível **Optional Fields** pode criar Grupos de Achados automaticamente com base em um método de agrupamento escolhido. Isso é útil quando um scanner produz muitos Achados relacionados que devem ser gerenciados em conjunto.

A caixa de seleção adjacente **Create Finding Groups for all Findings** desempenha duas funções:
- **Marcada**: Cria um Grupo de Achados para cada Achado importado, mesmo que esse Achado seja o único membro do grupo.
- **Desmarcada**: Cria Grupos de Achados somente quando há de fato múltiplos Achados para agrupar.

![image](images/profindings_ss2.png)

Se nenhuma opção for selecionada no menu suspenso Group By durante a importação (por exemplo, **Finding Title** na captura de tela acima, etc.), nenhum agrupamento ocorrerá.

Se o critério de agrupamento (por exemplo, nome do componente, ID de vulnerabilidade, título do Achado, etc.) não estiver preenchido no Achado, nenhum grupo será criado para ele, nem ele será adicionado a um Grupo de Achados pré-existente.

Se um scan for importado e revelar 10 Achados que não são agrupados, e o mesmo scan for reimportado com os Achados agrupados, os 10 primeiros Achados não serão adicionados a esse Grupo de Achados (ou seja, o Grupo de Achados incluirá apenas os 10 Achados da reimportação, não os 10 Achados da importação inicial).

## Finding Templates
**Modelos de Achado** permitem que os Usuários criem modelos reutilizáveis para vulnerabilidades e questões de segurança relatadas com frequência. Um modelo pode incluir informações padronizadas, como título, descrição, impacto, passos para reproduzir, mitigação, referências e outros metadados do Achado.

Os Modelos de Achado são mais úteis em situações em que os Usuários precisam criar Achados manuais repetidamente e desejam evitar reinserir as mesmas informações de apoio a cada vez.

### Accessing Finding Templates
Os Modelos de Achado são encontrados no submenu Findings, na barra lateral.

![image](images/profindings_ss1.png)

### Creating Finding Templates
Os Modelos de Achado podem ser criados clicando no botão **New Finding Template** no canto superior esquerdo da visualização de Modelos de Achado.

A página seguinte fornece uma visão geral dos metadados que serão aplicados a um Achado quando um Modelo de Achado for usado.

### Applying Finding Templates
Os Modelos de Achado diferem entre o DefectDojo OS e o DefectDojo Pro. No Pro, os Modelos de Achado não podem ser aplicados a Achados pré-existentes, nem podem ser criados a partir de Achados pré-existentes.

No entanto, você pode adicionar manualmente um Achado a um Teste com base em um Modelo de Achado usando o menu kebab ⋮ ao lado do Teste na visualização do Engajamento pai, ou usando o menu de engrenagem na visualização do Teste.

![image](images/profindings_ss3.png)

![image](images/profindings_ss4.png)

## Reporting
O construtor de relatórios do DefectDojo permite montar um relatório personalizado a partir de um conjunto de widgets de conteúdo, executá-lo e exportar o resultado (por exemplo, imprimindo-o em PDF). Relatórios personalizados podem resumir os Achados ou Endpoints que você deseja compartilhar com um público externo, e podem incluir branding e texto padrão.

Mais informações sobre o Report Builder do DefectDojo podem ser encontradas [aqui](/metrics_reports/reports/report-builder/).

### Export Findings
Páginas que exibem uma lista de Achados ou uma lista de Engajamentos possuem uma opção de exportação em CSV e Excel no canto superior esquerdo. Para Achados, também há a opção de realizar uma Exportação Rápida, que abrirá uma nova aba com tabelas de metadados referentes a cada Achado.
