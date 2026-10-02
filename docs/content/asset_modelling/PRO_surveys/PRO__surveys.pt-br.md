---
title: Pesquisas
description: Entendendo as Pesquisas no DefectDojo Pro
audience: pro
weight: 2
---

No DefectDojo, um modelo de Pesquisa é um conjunto reutilizável de Perguntas que serve para coletar informações de desenvolvedores, equipes e partes interessadas internas e externas. Eles podem ser usados para reunir informações antes do início do trabalho, garantir alinhamento entre indivíduos e equipes à medida que o trabalho avança, e permitir uma análise retrospectiva após a conclusão do trabalho. 

No DefectDojo, um sistema de Pesquisas é composto por três componentes:
- **Modelos de Pesquisa**, que agrupam e ordenam as Perguntas. 
- **Implantações de Pesquisa**, que são instâncias ativas que coletam respostas.
- **Respostas**, que são as respostas enviadas pelos Usuários.

Criar um modelo de Pesquisa não o torna automaticamente disponível para respostas. Para coletar respostas, um modelo de Pesquisa precisa ser implantado.

## Permissões

A seção Surveys na barra lateral só é visível para Usuários com status de Superusuário, e somente Superusuários podem criar modelos de Pesquisa, criar Perguntas e implantar Pesquisas. 

Usuários sem status de Superusuário ainda podem responder a Pesquisas que sejam compartilhadas com eles, mas não podem criá-las ou gerenciá-las, nem às Perguntas associadas.

## Acessando Pesquisas e Perguntas 

Usuários com status de Superusuário podem acessar Pesquisas e Perguntas na barra lateral clicando na opção **Surveys**. O submenu oferece acesso a **All Surveys** e **All Questions**, além da opção de criar novas Pesquisas e Perguntas.

![image](images/pq_ss1.png)

### Acessando Pesquisas 

A visualização All Surveys inclui uma tabela contendo todos os modelos de Pesquisa, incluindo seu ID, nome, descrição e status ativo. A tabela pode ser filtrada usando palavras-chave, e pode ser reorganizada clicando no cabeçalho de cada coluna. 

### Acessando Perguntas 

A visualização All Questions inclui uma tabela de Perguntas que podem ser adicionadas a uma Pesquisa. A tabela pode ser filtrada usando palavras-chave, e pode ser reorganizada clicando no cabeçalho de cada coluna. 

## Gerenciando Modelos de Pesquisa 

### Criar Modelos de Pesquisa 

Os modelos de Pesquisa podem ser criados clicando em **New Survey** na barra lateral, ou clicando no botão **New Survey** no topo da visualização All Surveys. 

![image](images/pq_ss2.png)

O modelo de Pesquisa precisa receber um nome e uma descrição, e ter pelo menos uma Pergunta escolhida no menu suspenso antes de ser criado.

#### Adicionar Perguntas a um Modelo de Pesquisa Já Existente 

Para adicionar Perguntas a um modelo de Pesquisa já existente, clique no ícone de kebab ⋮ à esquerda da Pesquisa desejada, clique em **Edit Survey**, selecione quaisquer novas Perguntas a serem adicionadas à Pesquisa no menu suspenso e, em seguida, clique em **Submit**.

Como boa prática, recomenda-se fortemente evitar modificar ou adicionar Perguntas a um modelo de Pesquisa enquanto ele possui implantações ativas. Adicionar novas Perguntas não afetará as Respostas existentes, mas essas Respostas terão sido enviadas sem responder às Perguntas recém-adicionadas, o que pode resultar em dados incompletos.

### Criar Perguntas 

Assim como os modelos de Pesquisa, as Perguntas podem ser criadas clicando em **New Question** na barra lateral, ou clicando no botão **New Question** no topo da visualização All Questions. 

#### Tipos de Pergunta 

Ao criar uma nova Pergunta, ela pode ser formatada como uma pergunta baseada em texto ou como uma pergunta de múltipla escolha, selecionando **Text Question** ou **Choice Question** no topo da visualização New Question. 

![image](images/pq_ss3.png)

#### Ordem das Perguntas 

Determine a ordem de uma Pergunta atribuindo a ela um número de ordem. Por exemplo, se uma Pergunta tiver 1 no campo Order, essa Pergunta aparecerá acima de uma Pergunta com 2 no campo Order. 

#### Respostas Opcionais 

Tanto as perguntas baseadas em texto quanto as de múltipla escolha podem ser marcadas como **Optional** clicando na caixa de seleção correspondente. 

#### Permitindo Múltiplas Respostas 

Um número ilimitado de respostas possíveis pode ser adicionado a uma pergunta de múltipla escolha. Clicar na caixa de seleção **Allow Multiple Selections** permite que múltiplas respostas sejam selecionadas (disponível apenas para perguntas de múltipla escolha).

### Editando Perguntas 

Para alterar uma Pergunta, navegue até a visualização All Questions, clique no ícone de kebab ⋮ à esquerda da Pergunta a ser alterada, clique em Edit Question, faça a alteração desejada e finalize a alteração clicando em Submit. As Perguntas não podem ser excluídas. 

![image](images/pq_ss4.png)

É importante evitar editar Perguntas que fazem parte de Questionários ativos ou adicionar Perguntas a Questionários ativos. Fazer isso não afetará nenhuma resposta coletada anteriormente, mas pode resultar em dados incompletos ou não confiáveis. 

## Implantando Pesquisas 

Depois que um modelo de Pesquisa é criado com sucesso, implantar uma Pesquisa cria uma instância ativa que aceita respostas.

Para implantar uma Pesquisa, navegue até a visualização All Surveys, clique no ícone de kebab ⋮ à esquerda da Pesquisa a ser implantada, clique em **Open Survey**, defina a data de expiração e clique em Submit. 

Se você quiser implantar a mesma Pesquisa novamente, siga o mesmo processo. Todas as implantações aparecerão na tabela Open Survey Instances na visualização da Pesquisa, e podem ser distinguidas por seu ID, horário de criação e data de expiração. 

![image](images/pq_ss10.png)

Uma Pesquisa se encerrará na data escolhida, no mesmo horário em que foi implantada. Por exemplo, se você implantar uma Pesquisa às 8h00 do dia 1º de fevereiro de 2026 e agendar seu encerramento para 1º de março de 2026, a pesquisa se encerrará às 8h00 da manhã de 1º de março de 2026. 

Depois que uma Pesquisa é aberta, sua data e horário de expiração não podem ser alterados. Se um prazo diferente for necessário, uma nova implantação precisa ser criada.

Depois que uma data de expiração passa, não será mais possível enviar respostas para aquela implantação da Pesquisa, mas a implantação continuará aparecendo na tabela Open Survey Instances na visualização daquela Pesquisa. 

#### Compartilhando uma Pesquisa 

Depois que uma Pesquisa é implantada, ela pode ser compartilhada com outros Usuários clicando no ícone ↗ à esquerda da Pesquisa na tabela Open Survey Instances na visualização do modelo de Pesquisa. Isso revelará um link exclusivo daquela implantação, que pode ser copiado e compartilhado com os destinatários pretendidos. 

![image](images/pq_ss5.png)

![image](images/pq_ss9.png)

#### Encerrando uma Pesquisa 

Para encerrar uma Pesquisa, clique no **X** vermelho à esquerda da Pesquisa na tabela Open Survey Instances na visualização do modelo de Pesquisa.

![image](images/pq_ss13.png)

Conforme observado na seção Responses mais adiante, isso apenas impedirá o envio de novas respostas. As Respostas enviadas anteriormente permanecerão visíveis na tabela Responses na parte inferior da visualização do modelo de Pesquisa.

## Respondendo a Pesquisas

Para responder a uma Pesquisa, os não Superusuários precisam ter o link compartilhado diretamente com eles, seguindo as instruções na seção [Compartilhando uma Pesquisa](#sharing-a-survey) acima. Os Superusuários também podem responder usando o mesmo link.

#### Habilitando Respostas Anônimas 

Por padrão, as Pesquisas só são acessíveis a Usuários do DefectDojo. Para permitir que partes externas respondam a Pesquisas do DefectDojo, certifique-se de que a opção **Enable Anonymous Survey Responses** esteja ativada em **System Settings**, encontrada em **Settings > System** na barra lateral (dentro do submenu **Pro Settings** em instâncias que ainda utilizam o layout de menu anterior).

![image](images/pq_ss6.png)

As respostas externas aparecerão como anônimas porque não há um ID de usuário do DefectDojo associado à resposta. 

Se o escopo de uma Pesquisa incluir Usuários tanto internos quanto externos, especifique o nome do Engajamento na descrição no momento da criação, o que permitirá a filtragem dos resultados.

![image](images/pq_ss7.png)

![image](images/pq_ss8.png)

## Gerenciando Respostas 

Um único modelo de Pesquisa pode ser implantado várias vezes simultaneamente. Todas as respostas de múltiplas implantações do mesmo modelo de Pesquisa serão exibidas juntas na tabela Responses na parte inferior da visualização daquela Pesquisa. 

![image](images/pq_ss11.png)

Mesmo depois que uma implantação de Pesquisa expira ou é encerrada, suas respostas permanecem visíveis na tabela Responses na parte inferior da visualização da Pesquisa, desde que o modelo de Pesquisa em si não tenha sido excluído. Essas respostas são permanentes e não podem ser removidas.

Como mostrado na imagem abaixo, não há atualmente nenhuma implantação de Pesquisa aberta, mas as respostas de implantações anteriores ainda estão presentes na tabela Responses.

![image](images/pq_ss12.png)

### Excluindo Modelos de Pesquisa

Para excluir um Modelo de Pesquisa, navegue até a visualização All Surveys, clique no ícone de kebab ⋮ à esquerda da Pesquisa escolhida, e clique em **Delete Survey**. Isso exclui permanentemente o modelo de Pesquisa e todas as implantações e Respostas associadas. Esta ação não pode ser desfeita.
