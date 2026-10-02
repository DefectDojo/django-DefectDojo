---
title: Aceitações de Risco
description: Aproveitando as Aceitações de Risco no DefectDojo Pro
audience: pro
weight: 2
aliases:
- /pt-br/en/working_with_findings/findings_workflows/risk_acceptances/
---

**Aceitações de Risco** são um status especial que pode ser aplicado a Achados usando objetos de **Aceitação de Risco Completa** ou o fluxo de **Aceitação de Risco Simples**. As Aceitações de Risco são usadas para documentar formalmente e operacionalizar a decisão de reconhecer um Achado vulnerável sem corrigi-lo imediatamente.

O DefectDojo Pro inclui recursos aprimorados de Aceitação de Risco para escalar decisões de gestão de risco, incluindo:
- **Aceitações de Risco entre Produtos**: uma única Aceitação de Risco pode ser aplicada em vários produtos, permitindo agrupar todas as instâncias de Achados iguais ou semelhantes em todo o seu portfólio de Ativos em um único objeto de Aceitação de Risco.
- **Gestão em Massa de Aceitação de Risco**: filtre e pesquise Achados específicos por IDs de vulnerabilidade e aplique a Aceitação de Risco a todos os resultados simultaneamente, independentemente do Ativo ao qual pertençam.

### Acessando Achados com Risco Aceito

A barra lateral apresenta uma seção para Aceitações de Risco que inclui três subseções em seu menu suspenso:
- **Achados com Risco Aceito**
    - Esta seção inclui uma tabela de todos os Achados que tiveram o risco aceito, seja como parte de um objeto de Aceitação de Risco Completa ou usando o fluxo de Aceitação de Risco Simples.
- **Todas as Aceitações de Risco**
    - Esta seção inclui uma tabela de todos os objetos de Aceitação de Risco Completa, organizados em ordem cronológica.
- **Nova Aceitação de Risco**
    - Clicar nesta opção na barra lateral iniciará o fluxo para criar um objeto de Aceitação de Risco Completa.

![Barra lateral de aceitação de risco](images/RA_image1.png)

## Criando Aceitações de Risco

Quando um Achado tem o risco aceito, ocorre o seguinte:

- O status do Achado deixará de ser “Ativo”.
- O status do Achado será alterado para “Risco aceito”.
- O Achado deixará de ser contabilizado nas Métricas, mas continuará aparecendo no Teste do qual se originou.

Os Achados podem ter o risco aceito de duas maneiras: podem ser adicionados a objetos de Aceitação de Risco Completa ou por meio do fluxo de Aceitação de Risco Simples.

### Aceitações de Risco Completas

Uma Aceitação de Risco Completa permite que os Usuários aceitem o risco de vários Achados, agrupando-os em um único objeto, independentemente do Ativo, Engajamento ou Teste do qual se originaram.

Se a política organizacional exigir aceitações de risco formais e documentadas, ou se os Usuários quiserem que as aceitações de risco expirem automaticamente após uma determinada data, a Aceitação de Risco Completa é a melhor escolha, pois ela registra o processo interno de tomada de decisão e pode servir como fonte da verdade.

Cada Aceitação de Risco Completa adiciona contexto adicional à Aceitação de Risco, como:
- O nome do objeto de Aceitação de Risco.
- O proprietário do objeto de Aceitação de Risco.
- A recomendação de segurança e a decisão sobre como tratar o(s) Achado(s).
- Qualquer comprovação associada à recomendação ou decisão.
- Detalhes sobre a recomendação ou decisão.
- O Usuário que aceita o risco associado à decisão.
- A data de expiração.
    - Se o status do Achado retornará a “Ativo” após a expiração.
    - Se o SLA será reiniciado após a expiração.

A expiração é exclusiva dos objetos de Aceitação de Risco Completa e permite que quaisquer Achados que tiveram o risco aceito sejam reexaminados no momento apropriado. Quando uma Aceitação de Risco expira, os Achados voltam a ser definidos como Ativo.

Se você não especificar uma data, serão usados os dias de Aceitação de Risco Padrão / Expiração Padrão de Aceitação de Risco definidos na página de Configurações do Sistema.

#### Como Concluir uma Aceitação de Risco Completa

Um objeto de Aceitação de Risco Completa pode ser criado de três maneiras diferentes:
- Usando o botão **Nova Aceitação de Risco** na barra lateral.
- Usando o botão **Adicionar Aceitação de Risco** em um Achado individual.
- Clicando no botão **Ações de Aceitação de Risco** que aparece após selecionar um ou vários Achados dentro de uma tabela.

##### Nova Aceitação de Risco (Barra Lateral)

Ao clicar em Nova Aceitação de Risco na barra lateral, será aberta uma página na qual o Usuário pode estabelecer os dados e detalhes associados a um novo objeto de Aceitação de Risco Completa. A segunda página permitirá que o Usuário filtre e selecione os Achados a serem adicionados a esse objeto.

##### Adicionar Aceitação de Risco (Individual)

Com um Achado individual aberto, clique no ícone de engrenagem no canto superior direito da visualização e selecione **Adicionar Aceitação de Risco**. A partir daí, você poderá adicionar o Achado a um objeto de Aceitação de Risco Completa existente ou criar um novo objeto.

![Aceitação de Risco no submenu do Achado](images/RA_image2.png)

##### Ações de Aceitação de Risco (Tabela)

Com um ou mais Achados selecionados em uma tabela, clique no botão **Ações de Aceitação de Risco** que aparece na parte superior e selecione **Adicionar a Novo Objeto de Aceitação de Risco** ou **Adicionar a Objeto de Aceitação de Risco Existente**, preenchendo os campos obrigatórios.

Os Achados só podem ser adicionados a uma única Aceitação de Risco por vez.  Se o botão Ações de Aceitação de Risco estiver desabilitado, provavelmente é porque um dos Achados selecionados já foi adicionado a um objeto de Aceitação de Risco Completa.

![Botão de ações de aceitação de risco](images/RA_image5.png)

##### Editando Aceitações de Risco Completas

Depois que um objeto de Aceitação de Risco Completa é criado, você pode editar os detalhes do objeto, enviar um arquivo com a comprovação da Aceitação de Risco ou excluir o objeto por completo clicando no ícone de engrenagem no canto superior direito da visualização do objeto.

Os Achados também podem ser adicionados e removidos do objeto usando o mesmo menu. Alternativamente, os Achados podem ser removidos do objeto clicando no menu kebab ⋮ ao lado de um Achado individual, clicando em **Ações de Atualização em Massa** e selecionando **Não Aceitar Risco** no menu suspenso Status de Aceitação de Risco Simples.

Por fim, se você adicionar Achados a um objeto de Aceitação de Risco Completa e, posteriormente, excluir esse objeto, os Achados nele contidos terão seu status revertido automaticamente para “Ativo”.

### Aceitações de Risco Simples

As Aceitações de Risco Simples não têm metadados ou data de expiração associados. Elas são mais adequadas quando ainda é necessário rastrear Achados com risco aceito para fins de conformidade, mas não há necessidade de um objeto para rastrear ou alterar o status dos Achados afetados.

A Aceitação de Risco Simples não é habilitada por padrão, mas pode ser ativada na seção de Campos Opcionais das configurações do Ativo, após clicar no ícone de engrenagem no canto superior direito da visualização do Ativo.

![Habilitando a aceitação de risco simples](images/RA_image3.png)

Uma vez habilitada, a Aceitação de Risco Simples pode ser executada a partir da tabela de Achados dentro da visualização de um Teste.

#### Como Concluir uma Aceitação de Risco Simples

Você pode concluir o fluxo de Aceitação de Risco Simples a partir da tabela Todos os Achados (acessível pela barra lateral) ou da tabela de Achados dentro de um teste específico. O fluxo é idêntico em ambos os casos.

Selecione os Achados para os quais deseja aceitar o risco e clique no botão **Ações de Atualização em Massa** que aparece na parte superior da tabela. Em seguida, selecione **Aceitar Risco** no menu suspenso Status de Aceitação de Risco Simples. Como os Achados tiveram o risco aceito de forma simples, não há um objeto de Aceitação de Risco Completa associado. Os Achados que tiveram o risco aceito ficam acessíveis no menu **Achados com Risco Aceito** na barra lateral.

![Ações de aceitação de risco na tabela](images/RA_image4.png)

Por outro lado, se você quiser deixar de aceitar o risco de Achados que já tiveram o risco aceito anteriormente, selecione **Não Aceitar Risco**. Se um Achado teve o risco aceito de forma simples, o risco precisa ser desfeito antes de adicioná-lo a um objeto de Aceitação de Risco Completa.

## Permissões e Visibilidade da Aceitação de Risco

A visibilidade da Aceitação de Risco **é controlada por uma permissão mínima distinta da visibilidade do Achado**.  Um usuário que pode visualizar um Achado não tem automaticamente permissão para visualizar uma Aceitação de Risco que contenha esse Achado.

### Papel mínimo para ações de Aceitação de Risco

| Ação | Papel mínimo no Ativo (Produto) pai |
| --- | --- |
| Visualizar uma Aceitação de Risco | Writer |
| Adicionar ou Editar uma Aceitação de Risco | Writer |

Para o quadro completo de permissões por papel que lista as permissões de Aceitação de Risco junto com outras ações no nível de Ativo, consulte [Quadros de permissão de ação](/admin/user_management/user_permission_chart/#role-permission-chart).

## Expirando e Reinstaurando uma Aceitação de Risco

Uma Aceitação de Risco que expirou é marcada como **Expirada** ao lado de sua data de expiração na tabela de Aceitações de Risco, para que você possa identificar rapidamente quais delas não estão mais suprimindo seus Achados.

O menu de engrenagem em uma Aceitação de Risco — na tabela ou em sua página de detalhes — oferece a opção aplicável entre:

- **Expirar Aceitação de Risco**, em uma que ainda está ativa.  Ela expira imediatamente em vez de aguardar sua data de expiração, e seus Achados são reativados de acordo com as configurações **Reativar Achados Expirados** e **Reiniciar SLA ao Expirar**.
- **Reinstaurar Aceitação de Risco**, em uma que já expirou.  Seus Achados voltam a ter o risco aceito, e ela expira após o número de dias definido na configuração **Dias Padrão do Formulário de Aceitação de Risco**.

Ambas exigem a mesma permissão necessária para editar a Aceitação de Risco, e ambas pedem confirmação antes de prosseguir.  Para reinstaurar por um período específico em vez da janela padrão, edite a data de expiração em vez de usar a ação Reinstaurar — veja abaixo.

## Quando a Data de Expiração de uma Aceitação de Risco é Alterada

A data de expiração de uma Aceitação de Risco pode ser editada a qualquer momento após sua criação.  A forma como o DefectDojo responde depende de a Aceitação de Risco estar atualmente ativa ou já ter expirado.

### Editando a data em uma Aceitação de Risco ativa

Se uma Aceitação de Risco ainda não expirou — sua data de expiração está no futuro, ou acabou de passar mas a tarefa periódica de expiração ainda não a processou — editar a data é simples:

- A nova data é salva como está.  Se o usuário escolher `2027-01-15`, a Aceitação de Risco armazena `2027-01-15`.
- Os Achados vinculados continuam com o risco aceito.
- O objeto de Aceitação de Risco permanece ativo.

### Adiantando a data em uma Aceitação de Risco já expirada

Se a Aceitação de Risco **já expirou** — ou seja, a tarefa periódica já processou sua expiração, os Achados vinculados foram definidos novamente como Ativo conforme as configurações de expiração da Aceitação de Risco, e a Aceitação de Risco está no estado expirado — editar a data de expiração para um valor futuro dispara um fluxo de **reinstauração**:

- A Aceitação de Risco é reinstaurada e deixa de estar no estado expirado.
- Todo Achado que estava vinculado à Aceitação de Risco e está atualmente Ativo tem o risco aceito novamente (retorna a Risco aceito / Inativo).
- Os status de Endpoint desses Achados são atualizados para refletir a nova aceitação.
- Um comentário é publicado em quaisquer issues do Jira vinculadas, registrando a reinstauração.

A data que você inserir é a data que será salva.  A configuração do sistema **Dias Padrão do Formulário de Aceitação de Risco** (padrão: 180) só é usada quando você não solicita uma data específica — por exemplo, ao usar a ação **Reinstaurar**, que reinstaura a Aceitação de Risco sem editar sua data de expiração e, portanto, a define como hoje + N dias.

### Movendo a data para trás ou para uma data ainda no passado

Mover a data de expiração para uma data mais próxima, mas ainda no futuro, não tem comportamento especial — a Aceitação de Risco permanece ativa e a nova data é salva.

Mover a data para uma data no passado não expira imediatamente a Aceitação de Risco a partir do formulário de edição; a próxima tarefa periódica de expiração a identificará e aplicará o comportamento padrão de expiração (Achados reativados de acordo com a configuração **Reativar Achados Expirados** da Aceitação de Risco, com reinício do SLA aplicado se **Reiniciar SLA ao Expirar** estiver definido).

### O que a API expõe

Os consumidores da API podem observar o estado de expiração no objeto de Aceitação de Risco por meio dos campos `expiration_date`, `expiration_date_handled` e `expiration_date_warned`:

- `expiration_date` é a data configurada.
- `expiration_date_handled` é `null` enquanto a Aceitação de Risco está ativa, e recebe um timestamp quando a tarefa periódica processa a expiração.  Uma Aceitação de Risco está "expirada" precisamente quando `expiration_date_handled` não é nulo.
- `expiration_date_warned` é definido quando o sistema envia a notificação de aviso de expiração.

Quando ocorre uma reinstauração, tanto `expiration_date_handled` quanto `expiration_date_warned` são redefinidos para `null`, e `expiration_date` passa a conter a data enviada — ou hoje + N dias quando a reinstauração for disparada sem uma nova data.  Ferramentas que monitoram mudanças de estado nas Aceitações de Risco podem usar o campo `expiration_date_handled` como o indicador canônico de "esta Aceitação de Risco está atualmente expirada?".

Expirar e reinstaurar também estão disponíveis diretamente, sem que seja necessário editar `expiration_date`:

- `POST /api/v2/risk_acceptance/{id}/expire/` expira imediatamente.  Retorna `400` se já tiver expirado.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` reinstaura uma que expirou, aceitando novamente os Achados que ela abrange.  Retorna `400` se ainda não tiver expirado.  Envie `expiration_date` para escolher por quanto tempo; omita para usar hoje + N dias.

Ambas aceitam um `reason` opcional, que é registrado como uma nota na Aceitação de Risco junto com quem realizou a ação.  Ambas exigem a mesma permissão necessária para editar a Aceitação de Risco.

## Boas Práticas de Aceitação de Risco

Embora seja possível afetar Achados dentro de objetos de Aceitação de Risco Completa usando fluxos de Aceitação de Risco Simples (e vice-versa), geralmente é preferível adotar exclusivamente um dos processos como padrão, em vez de manter ambos habilitados ao mesmo tempo.

Por exemplo, se os objetos de Aceitação de Risco Completa forem a abordagem padrão e um Achado tiver o risco aceito de forma simples, isso pode causar confusão caso não haja um objeto associado que contenha o Achado afetado. Da mesma forma, se os Achados costumam ter o risco aceito de forma simples, pode causar confusão semelhante adicionar alguns Achados a um objeto de Aceitação de Risco Completa quando não existem esses objetos para a maioria dos outros Achados.
