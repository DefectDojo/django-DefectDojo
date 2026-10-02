---
title: Achados
description: Entendendo os Achados no DefectDojo OS
audience: opensource
weight: 5
---

Organizações	→ Ativos → Engajamentos → Testes → **ACHADOS**

## Visão geral

**Achados** representam o nível mais baixo da Hierarquia de Produtos, onde vulnerabilidades individuais são rastreadas e gerenciadas, e são a principal forma pela qual o DefectDojo padroniza e orienta o processo de relato e remediação das suas ferramentas de segurança. Independentemente de uma vulnerabilidade ter sido relatada no SonarQube, no Acunetix ou na ferramenta personalizada da sua equipe, os Achados permitem gerenciar cada vulnerabilidade da mesma forma.

Exemplos de Achados incluem:
- Cookie não marcado como HttpOnly
- Versão desatualizada (PHP)
- Avaliação de código fora de banda (PHP)
- Versão desatualizada (MySQL)
- Código-fonte de backup detectado
- Cross-Site Scripting cego

Além de armazenar os dados da vulnerabilidade e fornecer uma estrutura de remediação, o DefectDojo também aprimora seus Achados das seguintes formas:
- Adicionando automaticamente as pontuações EPSS relacionadas a um Achado para descrever sua explorabilidade
- Traduzindo automaticamente a métrica de severidade de uma ferramenta de segurança em uma pontuação de Severidade para cada Achado, o que confere um SLA ao Achado de acordo com a configuração de SLA do seu Ativo. Para mais informações sobre a configuração de SLA, clique [aqui](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).

No geral, os Achados são projetados para funcionar em conjunto com a Hierarquia de Produtos, padronizando seus esforços e aplicando um método consistente a cada Ativo.

## Acessando Achados

Os Achados são acessíveis pela barra lateral. O submenu oferece acesso a Achados Abertos e Fechados, Todos os Achados (independentemente do status Aberto ou Fechado), [Achados com Risco Aceito](/triage_findings/findings_workflows/os__risk_acceptance/), além dos Templates de Achados. Achados individuais também são acessíveis a partir do Teste que os contém.

![image](images/osfindings_ss1.png)

### Permissões

Todo Achado pertence a um Teste, o que permite que o DefectDojo preserve qual varredura ou avaliação identificou originalmente a vulnerabilidade.

Como os Achados pertencem a Testes, o acesso aos Achados é determinado pelo acesso do Usuário ao Ativo que contém o Teste. Os Testes não possuem listas de controle de acesso independentes.

## Visualização de Achados
As visualizações de Achado contêm uma variedade de tabelas para ajudar a interpretar o status de um Achado rapidamente. Isso inclui:
- **Visão geral**
    - **ID**: O número de ID exclusivo desse Achado.
    - **Severidade**: A classificação de severidade desse Achado, aplicada automaticamente.
        - Como mencionado acima, o DefectDojo traduz automaticamente a métrica de severidade de uma ferramenta de segurança em uma pontuação de Severidade para cada Achado, o que confere um SLA ao Achado de acordo com a configuração de SLA do seu Ativo.
    - **SLA**: A data limite prevista para a resolução do Achado.
    - **Status**: O status do Achado (por exemplo, Ativo, Verificado, Falso positivo, Duplicado, Fora do escopo e Em revisão de defeito).
    - **Tipo de Achado**: Se o Achado é Estático (SAST) ou Dinâmico (DAST).
    - **Data de descoberta**: A data em que o Achado foi descoberto.
    - **CWE**: A classificação CWE do Achado.
    - **ID da vulnerabilidade**: IDs de vulnerabilidades em avisos de segurança associados ao Achado (por exemplo, CVE ou outras fontes).
    - **Encontrado por**: A ferramenta que revelou o Achado.
- **Achados semelhantes**: Outros Achados dentro do mesmo Ativo que não são duplicatas exatas, mas possuem valores semelhantes para vulnerability ID, CWE, file_path, número de linha, etc.
- **Histórico de importação**: Lista de importações/reimportações que criaram/fecharam/reativaram esse Achado em qualquer Teste.
- **Endpoints/sistemas vulneráveis**: Endpoints/Sistemas que o Achado revela estarem vulneráveis.
- **Descrição**: A descrição do Achado (adicionada automaticamente dependendo do tipo de Achado, ou criada manualmente).
- **Mitigação**: Passos sugeridos para mitigação.
- **Impacto**: Impacto potencial de deixar o Achado sem resolução.
- **Passos para reproduzir**: Passos para reproduzir o Achado.
- **Justificativa de severidade**: Descrição escrita do motivo pelo qual uma determinada classificação de Severidade foi associada ao Achado.
- **Referências**: URL para referência cruzada com a descrição específica do Achado feita pela ferramenta de varredura de terceiros. Por exemplo, as Referências podem ser links para uma entrada relevante em um catálogo de Achados, ou uma única URL de aviso.
- **Notas**: Notas deixadas por Usuários relacionadas ao Achado. Marcar uma nota como privada significa que ela não será incluída em nenhum relatório gerado que inclua o Achado selecionado.

## Dados dos Achados

Os Achados exigem os seguintes metadados:
**Título**
**Data**
**Severidade**
**Descrição**

Além dos metadados correspondentes às tabelas na visualização de um Achado, os campos de metadados opcionais incluem:
- **Grupo**: Grupos de Achados que incluem o Achado selecionado.
- **Vetor e pontuação CVSS3/CVSS4**: O vetor e a pontuação CVSS3 e CVSS4 do Achado selecionado.
- **Pares de solicitação e resposta**: Uma cópia da mensagem enviada pelo cliente e da resposta do servidor à solicitação.
- **Endpoints a adicionar**: Endpoints vulneráveis que podem ser afetados pelo Achado selecionado e que não estão refletidos na lista anterior de sistemas/endpoints.
- **Pontuação e percentil EPSS**: Pontuação e percentil EPSS para o CVE.
- **Data de adição ao KEV**: A data em que o Achado foi adicionado ao catálogo KEV.
- **Disponibilidade e versão da correção**: Define se há uma correção disponível para a vulnerabilidade, e a versão do componente afetado na qual a correção foi implementada.
- **Usuário que solicitou uma revisão de defeito**: Registra quem solicitou uma revisão de defeito para a falha em questão.
- **Número da linha**: Número da linha de origem do vetor de ataque.
- **Caminho do arquivo**: Arquivos identificados que contêm a falha.
- **Nome e versão do componente**: Nome e versão do componente afetado.
- **ID exclusivo da ferramenta**: ID técnico exclusivo da vulnerabilidade na ferramenta de origem.
- **ID de vulnerabilidade da ferramenta**: ID técnico não exclusivo na ferramenta de origem.
- **Objeto de origem SAST, número da linha e caminho do arquivo**: Objeto de origem, número da linha e caminho do arquivo do vetor de ataque.
- **Objeto de destino SAST**: Objeto de destino (sink) do vetor de ataque.
- **Número de ocorrências**: Número de ocorrências na ferramenta de origem quando várias vulnerabilidades foram encontradas e agregadas pelo scanner.
- **Data de publicação**: Data em que o Achado foi publicado.
- **Serviço**: Serviços conectados (partes autocontidas de funcionalidade dentro de um Ativo) que são afetados pelo Achado selecionado. Quando preenchido, esse campo é incluído na correspondência de deduplicação (ou seja, Achados com campos de Serviço idênticos serão deduplicados).
- **Data e versão de remediação planejada**: A data em que o Achado está planejado para ser remediado, e a versão do componente afetado na qual a correção será implementada.
- **Esforço para correção**: O nível de esforço envolvido na correção do Achado (por exemplo, Baixo, Médio ou Alto).
- **Tags**: Quaisquer tags que tenham sido adicionadas ao Achado.

Os metadados exatos disponíveis dependerão do parser/scanner que revelou o Achado. Alguns fornecem apenas informações básicas, como título e severidade, enquanto outros incluem vetores CVSS, componentes vulneráveis, endpoints, pares de solicitação/resposta e outros metadados específicos do scanner.

Esses metadados melhoram a filtragem, a geração de relatórios e a priorização em todo o seu programa de segurança, permitindo o rastreamento de longo prazo e a análise de tendências. Detalhes adicionais e descrições de metadados podem ser encontrados [aqui](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page).

### Deduplicação

O DefectDojo inclui capacidades de deduplicação que ajudam a identificar e gerenciar Achados que representam a mesma vulnerabilidade subjacente. À medida que os resultados de varredura são importados de uma ou mais ferramentas, o DefectDojo usa uma lógica de correspondência configurável para identificar Achados que representam a mesma vulnerabilidade.

A deduplicação evita que a mesma vulnerabilidade apareça várias vezes quando descoberta repetidamente pelo mesmo scanner ou por scanners diferentes, permitindo que o histórico de remediação permaneça vinculado a um único Achado.

Mais informações sobre deduplicação podem ser encontradas [aqui](/triage_findings/finding_deduplication/about_deduplication/).

### Reimportação

A função de Reimportação do DefectDojo permite que os Achados sejam atualizados à medida que novos resultados de varredura são importados. Quando uma varredura é reimportada, o DefectDojo compara os resultados recebidos com os Achados existentes e atualiza os registros correspondentes em vez de criar registros totalmente novos. Isso preserva um contexto valioso, como alterações de status, histórico de remediação, comentários e informações de propriedade, fornecendo um registro contínuo do ciclo de vida de um Achado ao longo de vários ciclos de teste.

Mais informações sobre a função de Reimportação podem ser encontradas [aqui](/import_data/import_intro/reimport/#main-content).

### Aceitações de Risco

As Aceitações de Risco são um status especial que pode ser aplicado aos Achados para documentar formalmente e operacionalizar a decisão de reconhecê-los sem remediá-los imediatamente.

Mais informações sobre Aceitações de Risco podem ser encontradas [aqui](/triage_findings/findings_workflows/os__risk_acceptance/).

### Status

Cada Achado criado no DefectDojo tem um Status que comunica informações relevantes e ajuda sua equipe a acompanhar o progresso na resolução dos problemas.

Mais informações sobre Status podem ser encontradas [aqui](/triage_findings/findings_workflows/finding_status_definitions/).

## Trabalhando com Achados

### Criando Achados

Embora a maioria dos Achados seja gerada automaticamente por meio de importações de varreduras e integrações, o DefectDojo também oferece suporte à criação manual de Achados. Os Achados manuais são úteis para rastrear vulnerabilidades e questões de segurança identificadas por meio de testes de penetração, revisões de arquitetura, avaliações de conformidade, programas de bug bounty, engajamentos de consultoria ou outras atividades que não produzem saída de scanner.

Para criar um Achado manualmente:
1. Navegue até o Teste no qual deseja adicionar manualmente o Achado, clique no sinal + (mais) e depois clique em **Novo Achado**.

![image](images/osfindings_ss2.png)

2. Isso abre o formulário de Novo Achado, que você pode preencher com qualquer informação relevante sobre seu Achado.

3. Selecione **Adicionar Outro Achado** para adicionar manualmente outro Achado, ou **Concluído** para finalizar o processo de criação manual do Achado.

O Achado agora aparecerá na lista de Achados contidos no Teste original.

É importante notar que adicionar manualmente um Achado a partir da barra superior criará automaticamente um Engajamento e um Teste ad hoc para conter o novo Achado, em vez de adicioná-lo ao Teste que está sendo visualizado no momento (veja a imagem abaixo). Isso ocorre porque a barra superior diz respeito ao Ativo como um todo. Se você deseja adicionar manualmente um Achado a um Teste específico e já existente, é melhor fazer isso a partir do próprio Teste, conforme descrito nos passos 1 a 3 acima.

![image](images/osfindings_ss3.png)

### Editando Achados

#### Menu Kebab ⋮

O menu kebab ⋮ ao lado dos Achados contém as seguintes funções:
- **Visualizar**: Abre e exibe o Achado.
- **Editar**: Edita o Achado.
- **Copiar**: Cria uma cópia do Achado. A cópia pode ser salva em qualquer um dos Testes contidos no Engajamento correspondente.
- **Solicitar Revisão por Pares**: Inicia o processo de Revisão por Pares e altera o status do Achado para "Em revisão". Mais informações sobre Revisões por Pares podem ser encontradas [aqui](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Registrar Interação com o Achado**: Registra a interatividade com o Achado no histórico do Achado.
- **Transformar Achado em Template**: Cria automaticamente um Template de Achado com base no Achado selecionado.
- **Aplicar Template ao Achado**: Permite aplicar um Template de Achado pré-existente a um Achado.
- **Fechar Achado**: Inicia o processo de fechamento do Achado.
- **Adicionar Aceitação de Risco**: Inicia o processo de Aceitação de Risco. Mais informações podem ser encontradas [aqui](/triage_findings/findings_workflows/os__risk_acceptance/#main-content).
- **Ver Histórico**: Revela o histórico do Achado selecionado.
- **Excluir**: Exclui o Achado selecionado.

#### Anexando Arquivos aos Achados
Você pode anexar arquivos a qualquer Achado para fornecer contexto visual — por exemplo, uma captura de tela de uma vulnerabilidade em ação ou uma imagem de prova de conceito.

Os tipos de arquivo compatíveis incluem:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

Para anexar um arquivo a um Achado:
1. Abra o Achado ao qual deseja anexar um arquivo.
2. Abra o menu de ações (o botão ☰ no canto superior direito do Achado) e clique em Gerenciar Arquivos.

![image](images/OS_manage_files_menu.png)

3. Na página Adicionar arquivos, digite um Título para o arquivo e escolha o arquivo do seu computador. Você pode adicionar até três arquivos por vez; salve e retorne para adicionar mais, se necessário.

![image](images/OS_manage_files_form.png)

4. Clique em **Salvar**.

O arquivo é então listado no painel **Arquivos** do Achado. Arquivos de imagem aparecem como miniaturas:

![image](images/OS_finding_files_panel.png)

#### Edição em Massa de Achados

Os Achados podem ser editados em massa a partir de uma lista de Achados, como a tabela de Todos os Achados acessível pela barra lateral, ou a partir da tabela de Achados dentro de um Teste específico.

Mais informações sobre como editar Achados em massa podem ser encontradas [aqui](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings).

### Fechando Achados

Depois que o trabalho em um Achado é concluído, você pode fechá-lo manualmente clicando em **Fechar Achado** dentro do menu kebab ⋮ ou do menu de ações ☰ do Achado. Alternativamente, se uma varredura for reimportada no DefectDojo e não contiver um Achado registrado anteriormente, o Achado registrado anteriormente será fechado automaticamente.

Se você não quiser que nenhum Achado seja fechado, pode desabilitar esse comportamento na Reimportação:

- Desmarque a caixa de seleção Close Old Findings, se estiver usando a UI
- Defina close_old_findings como False, se estiver usando a API ​

### Excluindo Achados

A exclusão de um Achado pode ser feita a partir do menu kebab ⋮ ou do menu de ações ☰ do Achado. Essa ação não pode ser desfeita.

Para fins de auditoria, recomenda-se fechar os Achados remediados, em vez de excluí-los.

## Grupos de Achados

Os **Grupos de Achados** permitem tratar múltiplos Achados relacionados como uma única unidade lógica para triagem, geração de relatórios e coordenação de remediação.

Por exemplo, uma varredura pode produzir 10 Achados de injeção de SQL em diferentes endpoints. Em vez de gerenciar cada um independentemente, você pode agrupá-los em um único Grupo de Achados que represente o problema mais amplo de injeção de SQL.

Um Grupo de Achados não substitui os Achados individuais. Cada Achado continua existindo com sua própria severidade, status, metadados, comentários e histórico de remediação. Um Grupo de Achados simplesmente fornece uma camada organizacional adicional acima dos Achados que ele contém.

### Acessando Grupos de Achados

Os Grupos de Achados podem ser acessados pela barra lateral. O submenu oferece acesso a Grupos de Achados Abertos e Fechados, bem como a Todos os Grupos de Achados (independentemente do status Aberto).

![image](images/osfindings_ss1.png)

### Criando Grupos de Achados


Os Grupos de Achados podem ser criados manual ou automaticamente.

Notavelmente, os Grupos de Achados só podem ser criados a partir dos Achados contidos em um único Teste. Achados de Testes, Engajamentos ou Produtos diferentes não podem ser adicionados ao mesmo Grupo de Achados.

#### Grupos de Achados Manuais

Para realizar manualmente ações de Grupo de Achados:
1. Navegue até uma lista de Achados dentro de um Teste.
2. Selecione o(s) Achado(s) que deseja adicionar a um Grupo de Achados clicando na caixa de seleção correspondente.
3. Clique na caixa de seleção **Grupo**.
4. Clique na ação correspondente que deseja realizar.
    - **Criar**: Cria um Grupo de Achados que inclui os Achados selecionados.
    - **Adicionar a**: Adiciona os Achados selecionados a um Grupo de Achados pré-existente.
    - **Remover de qualquer grupo**: Remove os Achados selecionados de quaisquer Grupos de Achados dos quais faziam parte anteriormente.
    - **Agrupar por**: Agrupa os Achados selecionados com base na opção escolhida (por exemplo, nome do componente, caminho do arquivo, título do Achado, etc.)
5. Clique em **Enviar**.

![image](images/osfindings_ss4.png)

Observe que a única ação possível ao selecionar Achados na lista Todos os Achados é remover os Achados selecionados de qualquer Grupo de Achados. Isso ocorre porque, como mencionado, os Grupos de Achados só podem ser criados a partir dos Achados contidos em um único Teste.

#### Grupos de Achados Automáticos

Ao importar uma varredura, o recurso "Agrupar por" pode criar automaticamente Grupos de Achados com base em um método de agrupamento escolhido. Isso é útil quando um scanner produz muitos Achados relacionados que devem ser gerenciados em conjunto.

A caixa de seleção adjacente **Criar Grupos de Achados para todos os Achados** realiza duas funções:
- **Marcada**: Cria um Grupo de Achados para cada Achado importado, mesmo que esse Achado seja o único membro do grupo.
- **Desmarcada**: Cria Grupos de Achados somente quando há de fato múltiplos Achados para agrupar.

![image](images/osfindings_ss5.png)

Se nenhuma opção for selecionada no menu suspenso Agrupar por durante a importação, nenhum agrupamento ocorrerá.

Se o critério de agrupamento (por exemplo, nome do componente, ID de vulnerabilidade, etc.) não estiver preenchido no Achado, ele não terá um grupo criado nem será adicionado a um Grupo de Achados pré-existente.

Se uma varredura for importada revelando 10 Achados que não são agrupados, e a mesma varredura for reimportada e os Achados forem agrupados, os primeiros 10 Achados não serão adicionados a esse Grupo de Achados (ou seja, o Grupo de Achados incluirá apenas os 10 Achados da reimportação, não os 10 Achados da importação inicial e subsequente).

## Templates de Achados

**Templates de Achados** permitem que os Usuários criem templates reutilizáveis para vulnerabilidades e problemas de segurança comumente relatados. Um template pode incluir informações padronizadas, como título, descrição, impacto, passos para reproduzir, mitigação, referências e outros metadados de Achado.

Os Templates de Achados são mais úteis em situações em que os Usuários precisam criar Achados manuais repetidamente e desejam evitar reinserir as mesmas informações de apoio todas as vezes.

### Acessando Templates de Achados

Os Templates de Achados são encontrados no submenu de Achados na barra lateral.

![image](images/osfindings_ss6.png)

### Criando Templates de Achados

Os Templates de Achados podem ser criados clicando no botão + (mais) no canto superior direito da visualização de Templates de Achados.

A página seguinte fornece uma visão geral dos metadados que serão aplicados a um Achado quando um Template de Achado for usado.

Você também pode usar um Achado pré-existente como base para um novo Template de Achado clicando em **Transformar Achado em Template** dentro do menu kebab ⋮ do Achado.

### Aplicando Templates de Achados

Os Templates de Achados podem ser aplicados a Achados clicando no botão **Aplicar Template ao Achado** dentro do menu kebab ⋮ do Achado selecionado.

![image](images/osfindings_ss7.png)

A página seguinte permitirá que você selecione o template a ser aplicado ao Achado em questão, e então decida se deseja manter, substituir ou combinar os metadados do Achado com o template.

### Relatórios

O construtor de relatórios do DefectDojo permite montar um relatório personalizado a partir de um conjunto de widgets de conteúdo, executá-lo e exportar o resultado (por exemplo, imprimindo-o em PDF). Relatórios personalizados podem resumir os Achados ou Endpoints que você deseja compartilhar com um público externo, e podem incluir branding e texto padrão.

Mais informações sobre o Construtor de Relatórios do DefectDojo podem ser encontradas [aqui](/metrics_reports/reports/using-the-report-builder/).

#### Exportar Achados

Páginas que exibem uma lista de Achados ou uma lista de Engajamentos têm uma opção de exportação em CSV e Excel no menu suspenso no canto superior direito.

Em qualquer página de lista de Achados, abra o menu suspenso no canto superior direito para exportar os Achados visíveis como um arquivo CSV ou Excel. A lista de Engajamentos também pode ser exportada como CSV ou Excel usando o mesmo menu suspenso na página de lista de Engajamentos.
