---
title: Questionários
description: Entendendo os Questionários no DefectDojo OS
audience: opensource
weight: 2
---

No DefectDojo, um Questionário é um conjunto reutilizável de perguntas que coleta informações de desenvolvedores, equipes e partes interessadas tanto internas quanto externas. Eles podem ser usados para reunir informações antes do início do trabalho, garantir o alinhamento entre indivíduos e equipes à medida que o trabalho avança, e permitir uma análise retrospectiva após a conclusão do trabalho.

## Modelos de Questionário

Um modelo de Questionário define a estrutura e o conteúdo do Questionário, incluindo seu nome, descrição e Perguntas associadas. Criar um modelo de Questionário não o torna automaticamente disponível para receber respostas. Para coletar respostas, um modelo de Questionário deve ser implantado como um **Questionário Geral** ou um **Questionário Vinculado**.

### Questionários Gerais e Vinculados

Os Questionários Gerais e Vinculados diferem de várias formas, incluindo como são distribuídos, quem pode responder e onde as respostas são armazenadas.

| Questionários Gerais | Questionários Vinculados |
|---|---|
| Exigem publicação | Não exigem publicação |
| Exigem uma data de expiração | Permanecem ativos se o Engajamento ainda estiver ativo |
| Permitem respostas anônimas | Não permitem respostas anônimas |
| São compartilháveis interna e externamente | São compartilháveis apenas internamente |
| Não permitem alterar respostas | Permitem alterar respostas |
| Respostas só ficam visíveis após a expiração | Respostas ficam visíveis imediatamente |
| Respostas ficam visíveis em "Todos os Questionários" | Respostas ficam visíveis dentro do Engajamento |
| Podem ser convertidos em um Engajamento | Já está vinculado a um Engajamento |

#### Ciclo de Vida da Implantação do Questionário

Os modelos de Questionário seguem ciclos de vida diferentes, dependendo do tipo de implantação:

**Questionários Gerais**
Modelo → Publicado → Aceita Respostas → Expira → Conversão Opcional em Engajamento

**Questionários Vinculados**
Modelo → Vinculado ao Engajamento → Aceita Respostas → Permanece ativo enquanto o Engajamento estiver ativo

#### Separação de Respostas

Um único modelo de Questionário pode ser implantado várias vezes simultaneamente, tanto como Questionário Geral quanto Vinculado. Cada implantação cria seu próprio conjunto independente de respostas.

Se o mesmo modelo de Questionário for implantado como um Questionário Geral e também vinculado a um Engajamento, as respostas enviadas por meio de cada implantação são armazenadas de forma independente e não são combinadas. Isso permite que o mesmo modelo de Questionário seja reutilizado em diferentes contextos, mantendo os conjuntos de respostas separados.

## Acessando Questionários e Perguntas

Questionários e Perguntas podem ser acessados na barra lateral clicando na opção **Questionários**. O submenu oferece acesso a **Todos os Questionários** e **Todas as Perguntas**.

![imagem](images/q_ss1.png)

Vale destacar que o acesso às visualizações Todos os Questionários e Todas as Perguntas é restrito a Usuários com status de Superusuário. Apenas Superusuários podem criar modelos de Questionário, criar Perguntas e implantar Questionários. Usuários sem status de Superusuário ainda podem responder aos Questionários Gerais compartilhados com eles, bem como responder aos Questionários Vinculados dos Engajamentos aos quais têm acesso, mas não podem criá-los nem gerenciá-los.

### Questionários

A visualização de Todos os Questionários inclui duas tabelas:
- **Questionários**
    - Esta seção inclui todos os modelos de Questionário existentes.
- **Questionários Gerais**
    - Esta seção inclui todos os Questionários Gerais que estão atualmente abertos para respostas.

Ambas as seções podem ser filtradas por nome, descrição ou status de atividade.

### Perguntas

A visualização de Todas as Perguntas inclui uma tabela de Perguntas que podem atualmente ser adicionadas a um Questionário. Ela também pode ser filtrada pelo status opcional de cada Pergunta, pelo conteúdo ou pelo tipo de pergunta (por exemplo, pergunta de texto ou pergunta de múltipla escolha).

## Gerenciando Modelos de Questionário

### Criar Questionários

Novos Questionários podem ser criados usando o botão Criar Questionário na visualização Todos os Questionários.

![imagem](images/q_ss2.png)

Depois de incluir um nome e uma descrição, o Questionário pode ser criado sem Perguntas (que podem ser adicionadas posteriormente) ou as Perguntas podem ser adicionadas imediatamente.

#### Adicionar Perguntas Imediatamente a um Novo Questionário

Se as Perguntas estiverem sendo adicionadas imediatamente, selecione todas as Perguntas aplicáveis no menu suspenso que aparece em seguida. Você também pode criar uma nova Pergunta para adicionar ao Questionário clicando no sinal + à direita do menu suspenso.

![imagem](images/q_ss12.png)

Depois que todas as Perguntas aplicáveis tiverem sido selecionadas, clique em **Atualizar Perguntas do Questionário** para adicionar todas as Perguntas selecionadas ao Questionário.

#### Adicionar Perguntas a um Questionário Já Existente

Para adicionar Perguntas a um Questionário já existente, clique no nome do Questionário na tabela de Questionários, clique em **Editar Perguntas**, selecione quaisquer novas Perguntas a adicionar ao Questionário no menu suspenso e, em seguida, clique em **Atualizar Perguntas do Questionário**.

### Criar Perguntas

Novas Perguntas podem ser criadas usando o botão **Criar Pergunta** na visualização Todas as Perguntas.

![imagem](images/q_ss3.png)

Além disso, as Perguntas também podem ser criadas no momento de decidir quais Perguntas adicionar a um Questionário, clicando no sinal + à direita do menu suspenso.

#### Tipos de Pergunta

Ao criar uma nova Pergunta, ela pode ser formatada como uma pergunta baseada em texto ou como uma pergunta de múltipla escolha, selecionando **Texto** ou **Múltipla Escolha** no menu suspenso.

#### Permitindo Múltiplas Respostas e Respostas Opcionais

O número máximo de respostas permitidas em uma pergunta de múltipla escolha é seis. Marcar a caixa de seleção **Múltipla Escolha** permite que várias respostas sejam selecionadas (disponível apenas para perguntas de múltipla escolha). As Perguntas também podem ser marcadas como **Opcional** ao clicar na caixa de seleção correspondente.

Consulte a seção [Editando Perguntas](#editing-questions) para saber como adicionar respostas adicionais a uma pergunta de múltipla escolha.

#### Ordem das Perguntas

Determine a ordem de uma Pergunta atribuindo a ela um número de ordem. Por exemplo, se uma Pergunta tiver 1 no campo Ordem, essa Pergunta aparecerá acima de uma Pergunta com 2 no campo Ordem.

![imagem](images/q_ss13.png)

### Editando Perguntas

Depois que uma Pergunta é criada, ela pode ser editada acessando o submenu Todas as Perguntas e clicando na Pergunta a ser alterada. As Perguntas não podem ser excluídas.

É importante evitar editar Perguntas que fazem parte de Questionários ativos. Se qualquer parte de uma Pergunta for alterada (por exemplo, ordem, status opcional, correção de um erro de digitação, adição de uma resposta possível etc.) e essa Pergunta fizer parte de um Questionário ativo que já tenha recebido respostas, todas as respostas enviadas anteriormente serão invalidadas e será necessário reenviá-las.

#### Editando Perguntas de Texto

Após a criação, as únicas alterações que podem ser feitas em Perguntas baseadas em texto são a ordem, o status opcional e a formulação da pergunta.

#### Editando Perguntas de Múltipla Escolha

Embora o número padrão de respostas possíveis para uma pergunta de múltipla escolha seja seis, esse número pode ser aumentado depois que o Questionário for criado. Para isso, clique na Pergunta na visualização Todas as Perguntas, clique no sinal **+** à direita do menu suspenso Choices, adicione a nova resposta e clique em **Submit**.

![imagem](images/q_ss16.png)

![imagem](images/q_ss17.png)

A opção recém-criada não será adicionada automaticamente ao Questionário. Para adicioná-la, clique no menu suspenso **Choices** e selecione a opção recém-adicionada. Uma marca de seleção aparecerá ao lado dela, indicando que ela agora está incluída como uma resposta possível no Questionário.

![imagem](images/q_ss18.png)

## Implantando Questionários

Depois que um modelo de Questionário é criado com sucesso, ele pode ser implantado para aceitar respostas. O processo de implantação é ligeiramente diferente, dependendo do tipo de Questionário.

### Implantação de Questionário Geral

Para implantar um Questionário Geral:
1. Acesse a visualização Todos os Questionários.
2. Clique no **+** no lado direito da tabela de Questionários Gerais.
3. Selecione o Questionário a ser implantado.
4. Defina a data de expiração.
5. Clique em **Adicionar Questionário**.

#### Compartilhando um Questionário Geral

Depois de implantado, um Questionário Geral pode ser compartilhado clicando em **Compartilhar Questionário** na coluna Ações da tabela de Questionários Gerais. Isso gerará um link que você pode compartilhar com os destinatários pretendidos, além de permitir confirmar se o Questionário está formatado como esperado antes de fazer isso.

![imagem](images/q_ss14.png)

Observe o seguinte:
- Nenhuma resposta a um Questionário Geral ficará visível até que o Questionário tenha expirado.
- Não é possível alterar a data de expiração depois que o Questionário tiver sido publicado.
- O horário padrão de expiração de um Questionário é meia-noite (por exemplo, um Questionário com expiração em 31 de dezembro de 2026 só ficará visível até as 23:59:59 dessa data).
- Não é possível definir um horário de expiração personalizado.

Consulte [Habilitando Respostas Anônimas](#enabling-anonymous-responses) abaixo para saber como permitir respostas de Usuários externos.

### Implantação de Questionário Vinculado

Para implantar um Questionário Vinculado:
1. Acesse o Engajamento que será vinculado ao Questionário.
2. Clique na seta para baixo na tabela **Additional Features**.
3. Clique no **+** no lado direito da subtabela de Questionários.
4. Selecione o Questionário a ser vinculado no menu suspenso.
5. Clique em **Adicionar Questionário** ou em **Adicionar Questionário e Responder**.

O Questionário Vinculado agora estará ativo para qualquer Usuário com acesso ao Engajamento.

#### Compartilhando um Questionário Vinculado

Para compartilhar o Questionário Vinculado diretamente com Usuários internos do DefectDojo, clique no menu kebab ⋮ e selecione **Compartilhar Questionário** no menu suspenso. Um link aparecerá, que pode ser copiado e encaminhado ao destinatário pretendido.

![imagem](images/q_ss10.png)

Como mencionado, os Questionários Vinculados só podem ser compartilhados com Usuários do DefectDojo.

## Respondendo Questionários

O fluxo de resposta é ligeiramente diferente dependendo se o Questionário é Geral ou Vinculado.

### Respondendo a um Questionário Geral

Para responder a um Questionário Geral, os usuários que não são Superusuários precisam receber o link diretamente de um Superusuário, conforme descrito [aqui](#sharing-a-general-questionnaire).

#### Habilitando Respostas Anônimas

Por padrão, os Questionários Gerais só podem ser acessados por Usuários do DefectDojo. Para permitir que partes externas respondam aos Questionários do DefectDojo, certifique-se de que a opção **Allow Anonymous Survey Responses** esteja ativada nas Configurações do Sistema, encontradas na seção **Configurations** da barra lateral.

![imagem](images/q_ss4.png)

![imagem](images/q_ss5.png)

As respostas externas aparecerão como anônimas porque não há nenhum ID de usuário do DefectDojo associado à resposta.

Se o escopo de um Questionário incluir Usuários tanto internos quanto externos, crie um Questionário Geral e especifique o nome do Engajamento na descrição no momento da criação, o que permitirá filtrar os resultados.

![imagem](images/q_ss8.png)

![imagem](images/q_ss9.png)

### Respondendo a Questionários Vinculados

Para responder a um Questionário Vinculado:
1. Acesse a visualização do Engajamento.
2. Expanda a tabela Additional Features.
3. Expanda a subtabela de Questionários.
4. Clique no menu kebab ⋮ do Questionário Vinculado.
5. Clique em **Responder Questionário**.

![imagem](images/q_ss15.png)

Os Questionários Vinculados não permitem respostas externas/anônimas porque é necessário ter acesso ao DefectDojo para acessar o Engajamento.

## Respostas

Como mencionado, cada implantação de um modelo de Questionário cria seu próprio container de respostas. Vincular o mesmo modelo de Questionário a vários Engajamentos resulta em conjuntos de respostas separados, e publicar um Questionário Geral não afeta os conjuntos de respostas dos Questionários Vinculados.

### Respostas de Questionário Geral

Depois que a expiração de um Questionário Geral tiver passado:
- Não será mais possível enviar respostas adicionais.
- Todas as respostas anteriores serão salvas e ficarão visíveis.
- O Questionário será listado como um Questionário de Engajamento Respondido e Não Atribuído no painel do DefectDojo.

Há três ações que podem ser realizadas quando a janela de respostas de um Questionário for encerrada: **Ver Respostas**, **Criar Engajamento** e **Atribuir Usuário**.

#### Visualizando Respostas do Questionário

Selecionar **Ver Respostas** exibirá todas as respostas do Questionário.

#### Criando um Engajamento a partir de um Questionário

Após a expiração, um Questionário Geral pode ser conectado a um Ativo por meio de um Engajamento, selecionando a ação **Criar Engajamento**. Selecione um Ativo na lista suspensa que aparece em seguida e clique em **Criar Engajamento**. Um novo Engajamento poderá então ser criado e receber detalhes específicos, semelhantes aos de outros Engajamentos no DefectDojo, como Descrição, Versão, Status, Tags etc.

![imagem](images/q_ss6.png)

![imagem](images/q_ss7.png)

#### Atribuir Usuário

A ação Atribuir Usuário solicitará que um Usuário seja selecionado no menu suspenso de Usuários disponíveis. Selecione um Usuário no menu suspenso e clique em **Atribuir Questionário**, o que tornará esse Usuário o proprietário do Questionário.

### Respostas de Questionário Vinculado

Os Questionários Vinculados permanecem disponíveis enquanto o Engajamento associado estiver ativo. Dessa forma, as respostas ficam visíveis a qualquer momento.

O menu kebab ⋮ de um Questionário Vinculado inclui várias funções para gerenciar o Questionário e suas respostas:
- **Responder Questionário**: Esta opção aparece se um Usuário ainda não tiver respondido ao Questionário Vinculado. Depois de respondido, as opções Ver Respostas e Editar Respostas serão exibidas.
- **Ver respostas**: Permite que os Usuários vejam todas as respostas do Questionário até o momento.
- **Editar Respostas**: Permite que Usuários individuais editem suas Respostas anteriores.
- **Atribuir Usuário**: Atribui o questionário a um Usuário.
- **Vincular a um Engajamento Diferente**: Abre um menu suspenso com outros Engajamentos aos quais o Questionário pode ser atribuído.
- **Compartilhar Questionário**: Gera um link para compartilhar o Questionário com Usuários internos.
- **Excluir Questionário**: Desvincula o Questionário do Engajamento e exclui todas as respostas coletadas anteriormente.

## Excluindo Questionários

Excluir Questionários Gerais e Vinculados tem efeitos posteriores diferentes, dependendo do resultado pretendido com a exclusão.

### Excluindo Questionários Gerais

Excluir um Questionário Geral da tabela de Questionários Gerais na seção Todos os Questionários excluirá todas as respostas coletadas nessa implantação antes da exclusão. Quaisquer Questionários Vinculados que usem o mesmo modelo de Questionário não serão excluídos.

### Excluindo Questionários Vinculados

Excluir um Questionário Vinculado desvinculará o Questionário do Engajamento. Todas as respostas coletadas dentro do Engajamento antes da exclusão serão perdidas. Os Questionários Gerais implantados anteriormente usando o mesmo modelo de Questionário não serão afetados.

### Excluindo Modelos de Questionário

Para excluir completamente um modelo de Questionário, selecione-o na tabela de Questionários na visualização Todos os Questionários e clique em **Excluir Questionário**. Isso exclui permanentemente o modelo de Questionário e todas as respostas associadas de todas as implantações. Esta ação não pode ser desfeita.
