---
title: Engajamentos
description: Entendendo os Engajamentos no DefectDojo OS
audience: opensource
weight: 3
---

Organizações → Ativos → **ENGAJAMENTOS** → Testes → Achados

## Visão geral

Na hierarquia de produtos do DefectDojo, os Engajamentos são contêineres limitados por tempo ou por pipeline que representam grupos de Testes relacionados dentro de um Produto específico. Se você tiver um esforço de teste planejado e agendado, seja em uma base rotineira ou pontual, um Engajamento oferece um local para armazenar todos os resultados relacionados.

Exemplos de Engajamentos incluem:
- Testes de penetração pontuais
- Varreduras mensais ou trimestrais recorrentes
- Períodos de revisão de bug bounty
- Execuções de pipeline de CI/CD (para equipes que tratam cada pipeline como seu próprio Engajamento)
- Ciclos de lançamento de código (por exemplo, "revisão de segurança do lançamento v4.2")

### Tipos de Engajamento

O DefectDojo oferece suporte a dois tipos de Engajamento: **Interativo** e **CI/CD**. Esses tipos determinam como os Testes normalmente são criados e como os resultados das varreduras são importados.

Um Engajamento Interativo normalmente é conduzido por um engenheiro. Os Engajamentos Interativos são focados em testar uma aplicação enquanto ela está em execução, usando um teste automatizado, um testador humano, ou qualquer atividade que "interaja" com a funcionalidade da aplicação.

Um Engajamento de CI/CD é destinado à integração automatizada com um pipeline de CI/CD. Os Engajamentos de CI/CD têm como objetivo importar dados como uma ação automatizada, acionada por uma etapa no processo de lançamento.

| **Categoria**                | **Engajamentos Interativos**                             | **Engajamentos de CI/CD**                                              |
|------------------------|--------------------------------------------------------------|--------------------------------------------------------------------|
| **Caso de Uso Principal**   | Testes de segurança manuais ou pontuais                            | Testes de segurança automatizados e recorrentes dentro de pipelines             |
| **Duração**           | Limitada no tempo e finita                                        | Duração potencialmente infinita                                      |
| **Frequência**          | Periódica ou pontual                                          | Contínua ou por commit                                           |
| **Fluxo de Trabalho**           | Testador humano executa a ferramenta → importa os resultados manualmente            | Pipeline executa a ferramenta → envia os resultados automaticamente ao DefectDojo    |
| **Método de Importação de Resultados** | Upload manual via UI ou CLI                                 | Importação orientada por API via automação (por exemplo, CLI, conectores, cron jobs, scripts de pipeline) |
| **Tipo de Teste Típico** | Testes de penetração, exercícios de red team, avaliações manuais   | Análise estática, varredura de dependências, varredura de contêineres           |

### Dados do Engajamento

Como contêineres que organizam a atividade de teste, os Engajamentos podem armazenar ou rastrear uma variedade de dados:

- Datas de início e término previstas
- Descrição e notas de escopo
- Status (em andamento, planejado, concluído, etc.)
- Responsável / Líder
- Testes associados (por exemplo, varreduras, testes de penetração, testes manuais, etc.)
- Achados e Tipos de Achado (por exemplo, ativo, mitigado, risco aceito, duplicado, etc.)
- Modelos de ameaça ou informações de aceitação de risco
- Tags
- Arquivos e notas
- Configurações do projeto Jira
- Detalhes do ambiente (por exemplo, staging vs. produção)
- IDs de build (se vinculado a CI/CD)
- Dados históricos de Testes anteriores dentro do Engajamento

## Acessando Engajamentos

Os Engajamentos são acessíveis pela barra lateral. O submenu oferece acesso a Engajamentos Ativos e Todos os Engajamentos, além da opção de visualizar os Engajamentos organizados por Produto, tipos de Teste e Ambientes.

![image](images/engagement_ss17.png)

Alternativamente, os Engajamentos dentro de um Produto específico podem ser acessados pelo submenu da opção Engajamentos na barra superior.

![image](images/engagement_ss18.png)

### Permissões

Os Engajamentos ficam abaixo dos Produtos e acima dos Testes na hierarquia de objetos. Assim, o acesso a um Produto concede automaticamente acesso a todos os Engajamentos dentro desse Produto. Os Engajamentos não possuem listas de controle de acesso independentes.

## Trabalhando com Engajamentos

### Criar Engajamentos

Existem várias abordagens para criar um Engajamento. Cada abordagem exige que você primeiro crie um Produto para contê-lo.

Depois de criar um Produto, você pode adicionar um novo Engajamento Interativo ou de CI/CD na seção Engajamentos da barra de navegação do Produto.

![image](images/engagement_ss4.png)

Todo Engajamento deve ter os seguintes campos definidos:
- Tipo (Interativo ou CI/CD)
- Um nome exclusivo
- Datas de início e término previstas
    - Isso determinará a aparência do Engajamento na seção Calendário
- Produto
- Status

#### Status de Engajamento

Os Engajamentos podem receber diferentes status no momento da criação. O status também pode ser alterado posteriormente nas configurações do Engajamento.

Um Engajamento pode ter qualquer um dos seguintes status:
- Não iniciado
- Bloqueado
- Cancelado
- Concluído
- Em andamento
- Em espera
- Agendado
- Aguardando recurso

Alterar o status de um Engajamento para "Concluído" significa que a maioria das operações de escrita (por exemplo, adicionar testes, importar varreduras) ficará indisponível ou oculta. Outros status não afetam materialmente a funcionalidade do Engajamento, servindo mais para fins de filtragem/informação.

### Editar Engajamentos

Os Engajamentos podem ser editados clicando no botão **Editar** dentro das configurações do Engajamento. Todos os campos subsequentes que podem ser editados também estão disponíveis quando o Engajamento está sendo criado.

### Copiar Engajamentos

Você pode duplicar facilmente os Engajamentos navegando até a lista de Engajamentos dentro de um Produto e clicando no botão **Copiar** dentro do menu kebab ⋮ ao lado do Engajamento a ser copiado. Isso criará uma cópia exata do Engajamento original dentro do Produto pai, incluindo os metadados, Testes e Achados contidos nele.

![image](images/engagement_ss19.png)

### Fechar Engajamentos

Os Engajamentos podem ser fechados navegando até a lista de Engajamentos dentro de um Produto e clicando em "Fechar" dentro do menu kebab ⋮ do Engajamento escolhido.

![image](images/engagement_ss20.png)

Depois de fechado, o status do Engajamento será alterado para "Concluído". Ainda assim, a maioria das operações de escrita (por exemplo, adicionar testes, importar varreduras) permanecerá disponível.

Fechar um Engajamento não altera o status dos Achados dentro de nenhum dos Testes do Engajamento. Os Achados permanecem ativos, mitigados ou com risco aceito de acordo com seu próprio ciclo de vida, e continuam acessíveis para visualização e geração de relatórios.

Se o Engajamento estiver vinculado a um Épico do Jira (consulte **[Integração com o Jira: Habilitar Mapeamento de Épico de Engajamento](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**), fechar o Engajamento acionará uma tarefa assíncrona que fecha o Épico do Jira associado no seu Espaço Jira conectado.

### Reabrir Engajamentos

Se um Engajamento estiver fechado, ele pode ser reaberto clicando em **Reabrir** dentro do menu kebab ⋮ na tabela de Engajamentos Fechados. Isso tornará o Engajamento ativo novamente e retornará seu status para "Em andamento".

![image](images/engagement_ss21.png)

### Engajamentos Expirados

Um Engajamento expira quando sua data de término prevista é ultrapassada.

A expiração do Engajamento não tem impacto direto sobre sua funcionalidade, servindo principalmente como um mecanismo de monitoramento/notificação.

Depois de expirado, uma notificação vermelha "X dias em atraso" aparecerá no campo "Duração" do Engajamento, mas isso não restringirá nenhuma funcionalidade do Engajamento. O status do Engajamento continuará aparecendo como "Em andamento".

Embora não esteja habilitada por padrão, existe uma opção nas configurações do sistema para fechar automaticamente um Engajamento depois que ele estiver expirado por um determinado número de dias.

![image](images/engagement_ss22.png)

### Excluir Engajamentos

A exclusão de um Engajamento pode ser realizada selecionando **Excluir** nas configurações do Engajamento. Essa ação não pode ser desfeita.

Excluir um Engajamento também excluirá o seguinte:
- Quaisquer Testes associados ao Engajamento
- Todos os Achados contidos nesses Testes
- Quaisquer mapeamentos de Épico do Jira vinculados (o Épico em si permanecerá no Jira, mas o vínculo entre o DefectDojo e o Jira será removido)
- Todas as notas e arquivos enviados associados ao Engajamento

Para fins de auditoria, recomenda-se fechar os Engajamentos concluídos, em vez de excluí-los.

| **Operação** | **Resultados** | **Reversível** |
|----------|---------|------------|
| **Fechar** | Marca como inativo; os dados permanecem; pode ser reaberto | Sim (reabrir) |
| **Expirar** | Apenas aviso visual; fechamento automático opcional; notificações | N/A |
| **Excluir** | Remove permanentemente o Engajamento, Testes, Achados, notas, arquivos e quaisquer mapeamentos de Épico do Jira (os Épicos permanecem no Jira) | Não |

## Integração com o Jira

Os Engajamentos podem ser vinculados a um Espaço Jira conectado, permitindo que os Achados dentro do Engajamento sejam enviados ao Jira como Issues. Para um guia completo sobre a configuração do Jira, consulte **[Conectando o DefectDojo ao Jira](/connectors/os_jira/os__jira_guide/)**.

### Mapeamento de Épico de Engajamento

Quando a opção **Habilitar Mapeamento de Épico de Engajamento** está marcada nas configurações do Jira de um Produto, os Engajamentos são enviados ao Jira como Épicos. Os Achados dentro do Engajamento são enviados como Issues filhas abaixo do Épico, espelhando a hierarquia Engajamento → Achados do DefectDojo na estrutura Épico → Issue do Jira.

Para mais informações sobre essa configuração, consulte **[Habilitar Mapeamento de Épico de Engajamento](/connectors/os_jira/os__jira_guide/#enable-engagement-epic-mapping-for-products)**.

### Configurações do Jira em Nível de Engajamento

Por padrão, os Engajamentos herdam suas configurações do Jira do Produto pai. No entanto, Engajamentos individuais podem substituir essas configurações para usar configurações diferentes do Jira. As seguintes configurações podem ser personalizadas por Engajamento:

- **Chave do Projeto** — direciona os Achados para um Espaço Jira diferente
- **Template de Issue** — usa um template diferente para Issues criadas a partir deste Engajamento
- **Campos Personalizados** — aplica mapeamentos de campos personalizados diferentes
- **Labels do Jira** — marca Issues com labels específicas do Engajamento
- **Responsável Padrão** — atribui Issues a um membro diferente da equipe

Essas configurações são acessíveis na página **Editar Engajamento**. Para mais detalhes, consulte **[Configurações do Jira em Nível de Engajamento](/connectors/os_jira/os__jira_guide/#engagement-level-jira-settings)**.
