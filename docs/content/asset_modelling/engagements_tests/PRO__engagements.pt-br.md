---
title: Engajamentos
description: Entendendo Engajamentos no DefectDojo Pro
audience: pro
weight: 3
---

Organizações → Assets → **ENGAJAMENTOS** → Testes → Achados 

## Visão Geral

Na Hierarquia de Assets do DefectDojo, os Engajamentos são contêineres limitados por tempo ou por pipeline que representam grupos de Testes relacionados dentro de um Asset específico. Se você tem um esforço de teste planejado, seja em uma base rotineira ou pontual, um Engajamento oferece um local para armazenar todos os resultados relacionados.

Exemplos de Engajamentos incluem: 
- Testes de penetração pontuais
- Varreduras recorrentes mensais ou trimestrais
- Períodos de revisão de bug bounty
- Execuções de pipeline de CI/CD (para equipes que tratam cada pipeline como seu próprio Engajamento)
- Ciclos de lançamento de código (por exemplo, "revisão de segurança do lançamento v4.2")

### Tipos de Engajamento 

O DefectDojo suporta dois tipos de Engajamento: **Interativo** e **CI/CD**. Esses tipos determinam como os Testes são normalmente criados e como os resultados de varredura são importados.

Um Engajamento Interativo é normalmente executado por um engenheiro. Engajamentos Interativos são focados em testar uma aplicação enquanto ela está em execução, usando um teste automatizado, um testador humano ou qualquer atividade que "interaja" com a funcionalidade da aplicação. 

Um Engajamento de CI/CD é destinado à integração automatizada com um pipeline de CI/CD. Engajamentos de CI/CD têm como objetivo importar dados como uma ação automatizada, acionada por uma etapa do processo de lançamento.

| **Categoria**                | **Engajamentos Interativos**                             | **Engajamentos de CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Caso de Uso Principal**   | Testes de segurança manuais ou pontuais                            | Testes de segurança automatizados e recorrentes dentro de pipelines             |
| **Duração**           | Limitada no tempo e finita                                        | Duração potencialmente infinita                                      |
| **Frequência**          | Periódica ou pontual                                          | Contínua ou a cada commit                                           |
| **Fluxo de Trabalho**           | Testador humano executa a ferramenta → importa os resultados manualmente            | Pipeline executa a ferramenta → envia os resultados automaticamente para o DefectDojo    |
| **Método de Importação de Resultados** | Upload manual via UI ou CLI                                 | Importação orientada por API via automação (por exemplo, CLI, conectores, cron jobs, scripts de pipeline) |
| **Tipo de Teste Típico** | Testes de penetração, exercícios de red team, avaliações manuais   | Análise estática, varredura de dependências, varredura de contêineres           |

### Dados do Engajamento 

Como os contêineres que organizam a atividade de teste, os Engajamentos podem armazenar ou rastrear uma variedade de dados:

- Datas de início e término alvo
- Descrição e notas de escopo
- Status (em andamento, planejado, concluído, etc.)
- Responsável / Lead
- Testes associados (por exemplo, varreduras, pen tests, testes manuais, etc.)
- Achados e Tipos de Achado (por exemplo, ativo, mitigado, risco aceito, duplicado, etc.) 
- Modelos de ameaça ou informações de aceitação de risco
- Tags
- Arquivos e notas
- Configurações de projeto do Jira
- Detalhes do ambiente (por exemplo, staging vs. produção)
- IDs de build (se vinculado a CI/CD)
- Dados históricos de Testes anteriores dentro do Engajamento 

## Acessando Engajamentos 

Os Engajamentos são acessíveis pela barra lateral. O submenu fornece acesso a Engajamentos Ativos e Todos os Engajamentos, além da opção de criar novos Engajamentos.

![image](images/engagement_ss13.png)

Alternativamente, os Engajamentos dentro de um Asset podem ser acessados na janela na parte inferior da visualização do Asset.

![image](images/engagement_ss14.png)

### Permissões 

Os Engajamentos ficam abaixo dos Assets e acima dos Testes na hierarquia de objetos. Dessa forma, o acesso a um Asset concede automaticamente acesso a todos os Engajamentos dentro desse Asset. Os Engajamentos não possuem listas de controle de acesso independentes.

## Trabalhando com Engajamentos

### Criar Engajamentos 

Antes de criar um Engajamento, você deve primeiro ter [criado um Asset](/asset_modelling/engagements_tests/pro__assets/#create-assets) para contê-lo. 

Existem várias maneiras de criar um Engajamento: 

- No menu suspenso de Engajamentos na seção Gerenciar da barra lateral
    - Você precisará selecionar o Asset ao qual atribuir o Engajamento ao preencher o formulário de Novo Engajamento

![image](images/engagement_ss1.png)

- O ícone de engrenagem localizado no canto superior direito da visualização de um Asset

![image](images/engagement_ss9.png)

- O botão "+ New Engagement" encontrado na lista de Engajamentos dentro de um Asset

![image](images/engagement_ss2.png)

- Se você ainda não criou um Engajamento dentro de um Asset, pode fazê-lo durante a importação de uma varredura. 

![image](images/engagement_ss3.png)

Todo Engajamento deve ter os seguintes campos definidos:
- Tipo (Interativo ou CI/CD)
- Um nome exclusivo 
- Datas de início e término alvo 
    - Isso determinará a aparência do Engajamento na seção Calendário
- Asset 
- Status 

#### Status do Engajamento 

Os Engajamentos podem ser marcados com diferentes status no momento da criação. O status também pode ser alterado posteriormente nas configurações do Engajamento. 

Um Engajamento pode ter qualquer um dos seguintes status: 
- Não Iniciado
- Bloqueado
- Cancelado 
- Concluído 
- Em Andamento 
- Em Espera 
- Agendado 
- Aguardando Recurso 

Alterar o status de um Engajamento para "Concluído" significa que a maioria das operações de escrita (por exemplo, adicionar testes, importar varreduras) ficará indisponível ou oculta. Outros status não afetam materialmente a funcionalidade do Engajamento, servindo mais para fins de filtragem/informação.

### Editar Engajamentos 

Os Engajamentos podem ser editados clicando em **Edit Engagement** no menu de engrenagem. O mesmo menu também pode ser acessado clicando no menu kebab ⋮ à esquerda do Asset na visualização Todos os Assets. 

Todos os campos subsequentes que podem ser editados também estão disponíveis quando o Engajamento está sendo criado. 

![image](images/engagements_ss99.png)

### Copiar Engajamentos 

Você pode duplicar Engajamentos facilmente selecionando "Copy Engagement" nas configurações do Engajamento. Isso criará uma cópia exata do Engajamento original dentro do Asset pai, incluindo os metadados, Testes e Achados presentes nele.

### Fechar Engajamentos 

Os Engajamentos são fechados selecionando **Close Engagement** nas configurações do Engajamento. Uma vez fechado, o status do Engajamento será alterado para "Concluído". Ainda assim, a maioria das operações de escrita (por exemplo, adicionar testes, importar varreduras) permanecerá disponível.

Fechar um Engajamento não altera o status dos Achados em nenhum dos Testes do Engajamento. Os Achados permanecem ativos, mitigados ou com risco aceito de acordo com seu próprio ciclo de vida, e continuam acessíveis para visualização e geração de relatórios.

Se o Engajamento estiver vinculado a um Épico do Jira (veja **[Integração com o Jira: Habilitar Mapeamento de Épico de Engajamento](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**), fechar o Engajamento acionará uma tarefa assíncrona que fecha o Épico do Jira associado em seu Espaço do Jira conectado.

### Reabrir Engajamentos 

Se um Engajamento estiver fechado, ele pode ser reaberto selecionando **Reopen Engagement** em suas configurações. Isso tornará o Engajamento ativo novamente e retornará seu status para "Em Andamento". 

### Engajamentos Expirados 

Um Engajamento expira assim que sua data de término alvo é ultrapassada.

Em comparação com fechar ou excluir um Engajamento, a expiração de um Engajamento não tem impacto direto em sua funcionalidade, servindo principalmente como um mecanismo de monitoramento/notificação.  

Uma vez expirado, uma tag "Overdue" aparecerá ao lado do Engajamento, mas isso não restringirá nenhuma de suas funcionalidades. O status do Engajamento continuará aparecendo como "Em Andamento". 

Embora não esteja habilitada por padrão, há uma opção nas configurações do sistema para fechar automaticamente um Engajamento depois que ele tiver expirado por um determinado número de dias. 

![image](images/engagement_ss15.png)

### Excluir Engajamentos

A exclusão de um Engajamento pode ser realizada selecionando **Delete Engagement** nas configurações do Engajamento. Essa ação não pode ser desfeita.

Excluir um Engajamento também excluirá o seguinte:
Qualquer Teste associado ao Engajamento
Todos os Achados dentro desses Testes
Qualquer mapeamento de Épico do Jira vinculado (o Épico em si permanecerá no Jira, mas o vínculo entre o DefectDojo e o Jira será removido)
Todas as notas e uploads de arquivos associados ao Engajamento

Para fins de auditoria, recomenda-se fechar quaisquer Engajamentos concluídos, em vez de excluí-los.

| **Operação** | **Resultados** | **Reversível** |
|----------|---------|------------|
| **Fechar** | Marca como inativo; os dados permanecem; pode ser reaberto | Sim (reabrir) |
| **Expirar** | Apenas aviso visual; fechamento automático opcional; notificações | N/A |
| **Excluir** | Remove permanentemente o Engajamento, Testes, Achados, notas, arquivos e quaisquer mapeamentos de Épico do Jira (os Épicos permanecem no Jira) | Não |

## Integração com o Jira

Os Engajamentos podem ser vinculados a um Espaço do Jira conectado, permitindo que os Achados dentro do Engajamento sejam enviados ao Jira como Issues. Para obter um guia completo sobre a configuração do Jira, veja **[Conectando o DefectDojo ao Jira](/connectors/downstream/pro__jira_guide/)**.

### Mapeamento de Épico de Engajamento

Quando **Enable Engagement Epic Mapping** está marcado nas configurações do Jira de um Produto, os Engajamentos serão enviados ao Jira como Épicos. Os Achados dentro do Engajamento são enviados como Issues filhas do Épico, espelhando a hierarquia Engajamento → Achados do DefectDojo na estrutura Épico → Issue do Jira.

Para mais informações sobre essa configuração, veja **[Habilitar Mapeamento de Épico de Engajamento](/connectors/downstream/pro__jira_guide/#enable-engagement-epic-mapping)**.

### Configurações do Jira em Nível de Engajamento

Por padrão, os Engajamentos herdam suas configurações do Jira do Asset pai (Produto). No entanto, Engajamentos individuais podem sobrepor essas configurações para usar configurações diferentes do Jira. As seguintes configurações podem ser personalizadas por Engajamento:

- **Project Key** — direciona os Achados para um Espaço do Jira diferente
- **Issue Template** — usa um modelo diferente para Issues criadas a partir deste Engajamento
- **Custom Fields** — aplica mapeamentos de campos personalizados diferentes
- **Jira Labels** — marca Issues com labels específicas do Engajamento
- **Default Assignee** — atribui Issues a um membro diferente da equipe

Essas configurações são acessíveis na página **Edit Engagement**. Para mais detalhes, veja **[Configurações do Jira em Nível de Engajamento](/connectors/downstream/pro__jira_guide/#engagement-level-jira-settings)**.
