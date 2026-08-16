---
title: Aceitações de Risco
description: Aproveitando as Aceitações de Risco no DefectDojo OS
audience: opensource
weight: 2
---

**Aceitações de Risco** são um status especial que pode ser aplicado a Achados para documentar formalmente e operacionalizar a decisão de reconhecê-los sem corrigi-los de imediato.

Ao contrário do DefectDojo Pro, as Aceitações de Risco no DefectDojo OS não são objetos independentes. Em vez disso, as Aceitações de Risco estão vinculadas apenas a Engajamentos. Dessa forma, elas só podem conter Achados do Engajamento em que residem. Se 3 instâncias do mesmo Achado aparecerem em um Teste em 3 Engajamentos diferentes, serão necessárias 3 Aceitações de Risco diferentes para aceitar totalmente esses Achados.

### Acessando Aceitações de Risco

As Aceitações de Risco incluem Achados específicos do(s) Teste(s) de cada Engajamento. Por isso, elas podem ser acessadas a partir do Engajamento que contém o Teste do qual esses Achados se originam.

![imagem](images/OS_RA_image1.png)

Uma lista completa dos Achados individuais com risco aceito pode ser visualizada no submenu **Risk Accepted Findings**, dentro da seção **Findings** na barra lateral.

![imagem](images/OS_RA_image2.png)

## Criando Aceitações de Risco

Quando um Achado tem seu Risco Aceito, o seguinte ocorre:
- O status do Achado deixa de ser "Active", mas ele continua consultável, exportável em relatórios e auditável.
- O status do Achado é alterado para "Risk Accepted."
- O Achado deixa de ser contabilizado nas Métricas, mas continua aparecendo no Teste do qual se originou.

Achados podem ter o Risco Aceito de duas maneiras: podem ser adicionados manualmente a uma **Aceitação de Risco Completa**, ou por meio do fluxo de **Aceitação de Risco Simples**.

### Aceitações de Risco Completas

Uma Aceitação de Risco Completa permite que Usuários aceitem o risco de vários Achados dentro de um Engajamento e os agrupem em uma única unidade. Se a política organizacional exigir aceitações de risco formais e documentadas, ou se os Usuários quiserem disparar determinadas ações quando uma Aceitação de Risco expirar, as Aceitações de Risco Completas são a melhor escolha, pois registram o processo interno de tomada de decisão e podem servir como fonte da verdade.

Cada Aceitação de Risco Completa adiciona contexto adicional, como:
- O nome da Aceitação de Risco.
- O responsável (owner) pela Aceitação de Risco.
- A recomendação de segurança e a decisão sobre como tratar o(s) Achado(s).
- Qualquer prova associada à recomendação ou decisão.
- Detalhes sobre a recomendação ou decisão.
- O Usuário que aceita o risco associado à decisão.
- A data de expiração.
    - Se o status do Achado deve retornar para "Active" após a expiração.
    - Se o SLA deve ser reiniciado após a expiração.

A expiração é exclusiva das Aceitações de Risco Completas e permite que quaisquer Achados que tiveram o Risco Aceito sejam reexaminados no momento apropriado. Quando uma Aceitação de Risco Completa expira, todos os Achados voltam a ficar Ativos. Se você não especificar uma data, será usada a data padrão definida em Default Risk Acceptance / Default Risk Acceptance Expiration na página de Configurações do Sistema.

É importante destacar que, como as Aceitações de Risco Completas ficam restritas a Engajamentos individuais, não existe uma única seção onde seja possível visualizar todas as Aceitações de Risco Completas. Elas só podem ser vistas dentro do respectivo Engajamento que contém os Achados incluídos na Aceitação de Risco Completa.

#### Como Criar uma Aceitação de Risco Completa

Para criar uma Aceitação de Risco Completa, navegue até a visualização do Engajamento e clique no símbolo **+** na caixa de Aceitação de Risco.

![imagem](images/OS_RA_image3.png)

Em seguida, preencha os detalhes da Aceitação de Risco Completa e selecione os Achados a serem incluídos. **Accepted Findings** contém uma lista suspensa com todos os Achados disponíveis para adicionar à Aceitação de Risco. A lista de Achados dentro do Engajamento aparece em ordem decrescente de severidade (Achados Críticos no topo, Achados Baixos na parte inferior). Se um Achado já tiver tido o Risco Aceito anteriormente, ele não aparecerá na lista suspensa.

Depois de concluída, a Aceitação de Risco Completa aparecerá dentro da caixa de Aceitação de Risco na visualização do Engajamento.

Uma Aceitação de Risco também pode ser criada clicando no botão **Add Risk Acceptance** no menu kebab (⋮) de um Achado individual.

![imagem](images/OS_RA_image7.png)

#### Interagindo com Aceitações de Risco Completas

Depois que uma Aceitação de Risco Completa é criada, ela pode ser aberta para visualizar os Achados que foram adicionados a ela, bem como quaisquer detalhes inseridos no momento da criação (por exemplo, a data, o responsável, a decisão, a expiração etc.).

Para remover um Achado de uma Aceitação de Risco Completa, clique no botão **Remove** dentro da tabela de Achados Aceitos.

![imagem](images/OS_RA_image8.png)

A visualização da Aceitação de Risco Completa também inclui, na parte inferior, uma tabela com todos os demais Achados dos Testes daquele Engajamento. A partir dali, você pode selecionar Achados adicionais e incluí-los nessa Aceitação de Risco Completa.

Além disso, há uma função de Notas que permite aos Usuários incluir contexto adicional na Aceitação de Risco Completa. Todas as notas públicas aparecerão em quaisquer Relatórios gerados para a Aceitação de Risco Completa. Notas marcadas como **Private** ficam visíveis apenas para seu autor e para superusuários, e não são incluídas nos relatórios.

É importante destacar que, se uma Aceitação de Risco Completa for excluída por completo, os Achados nela contidos terão seu status revertido automaticamente para "Active."

### Aceitações de Risco Simples

Enquanto a Aceitação de Risco Completa vem habilitada por padrão, a Aceitação de Risco Simples precisa ser habilitada manualmente, seja na criação de um Ativo (Asset), seja nas configurações do Ativo.

![imagem](images/OS_RA_image4.png)

Uma Aceitação de Risco Simples pode ser realizada de uma de duas maneiras:
1. Na visualização de um Teste, usando o menu de Edições em Massa (Bulk Edits) que aparece depois de selecionar um ou mais Achados na tabela de Achados.

![imagem](images/OS_RA_image5.png)

2. Clicando em **Accept Risk** no menu kebab (⋮) de um Achado individual.

![imagem](images/OS_RA_image6.png)

Depois que um Achado tem sua Aceitação de Risco Simples aplicada, ele continua aparecendo na tabela de Achados do Teste, mas o status é alterado para **Inactive, Risk Accepted.** Uma lista completa dos Achados individuais com risco aceito pode ser visualizada no submenu **Risk Accepted Findings** da seção **Findings** na barra lateral.

Se você aplicar a Aceitação de Risco Simples a um Achado e mais tarde quiser adicioná-lo a uma Aceitação de Risco Completa, o Risco precisa ser desfeito (unaccepted) antes de adicioná-lo à Aceitação de Risco Completa.

## Quando a Data de Expiração de uma Aceitação de Risco é Alterada

A data de expiração de uma Aceitação de Risco Completa pode ser editada a qualquer momento após sua criação.  A forma como o DefectDojo responde depende de a Aceitação de Risco estar atualmente ativa ou já ter expirado.

### Editando a data em uma Aceitação de Risco ativa

Se uma Aceitação de Risco ainda não expirou — sua data de expiração está no futuro, ou acabou de passar mas o job periódico de expiração ainda não a processou — editar a data é simples:

- A nova data é salva como está.
- Os Achados vinculados permanecem com o Risco Aceito.
- O objeto de Aceitação de Risco permanece ativo.

### Adiando a data em uma Aceitação de Risco já expirada

Se a Aceitação de Risco **já expirou** — ou seja, o job periódico de expiração já processou sua expiração e os Achados vinculados voltaram para Ativo — editar a data de expiração para um valor futuro dispara um fluxo de **reinstatement (reinstate)**:

- A Aceitação de Risco é reinstaurada e deixa de estar no estado expirado.
- Todo Achado vinculado à Aceitação de Risco que estiver atualmente Ativo tem seu Risco Aceito novamente (volta a Risk Accepted / Inactive).
- Um comentário é publicado em quaisquer issues do Jira vinculadas, registrando o reinstatement.

A data que você informar é a data que será salva.  A configuração do sistema **Risk Acceptance Form Default Days** (padrão: 180) só é usada quando você não pede uma data específica — por exemplo, ao usar a ação **Reinstate**, que reinstaura a Aceitação de Risco sem editar sua data de expiração e, portanto, define a data como hoje + N dias.

### Movendo a data para trás ou para uma data ainda no passado

Mover a data de expiração para uma data anterior, mas ainda no futuro, não tem comportamento especial — a Aceitação de Risco permanece ativa e a nova data é salva.

Mover a data para uma data no passado não expira imediatamente a Aceitação de Risco a partir do formulário de edição; o próximo job periódico de expiração a processará e aplicará o comportamento padrão de expiração.  Isso também vale para uma Aceitação de Risco **já expirada**: uma data no passado ainda é a data que você escolheu, então ela é salva como está e a próxima execução de expiração expira a Aceitação de Risco novamente.

### O que a API expõe

Consumidores da API podem observar o estado de expiração no objeto de Aceitação de Risco por meio dos campos `expiration_date`, `expiration_date_handled` e `expiration_date_warned`.  Uma Aceitação de Risco está "expirada" exatamente quando `expiration_date_handled` é não nulo.  Quando ocorre um reinstatement, tanto `expiration_date_handled` quanto `expiration_date_warned` voltam a ser `null`, e `expiration_date` passa a conter a data enviada — ou hoje + N dias quando nenhuma data foi solicitada.

Expirar e reinstaurar também estão disponíveis diretamente, então você não precisa fazer isso editando `expiration_date`:

- `POST /api/v2/risk_acceptance/{id}/expire/` expira a Aceitação de Risco agora.  Retorna `400` se ela já tiver expirado.
- `POST /api/v2/risk_acceptance/{id}/reinstate/` reinstaura uma Aceitação de Risco expirada, reaceitando o risco dos Achados que ela cobre.  Retorna `400` se ela ainda não tiver expirado.  Envie `expiration_date` para escolher por quanto tempo; omita para usar hoje + N dias.

Ambos aceitam um `reason` opcional, que é registrado como uma nota na Aceitação de Risco, junto com quem executou a ação.  Ambos exigem a mesma permissão necessária para editar a Aceitação de Risco.

## Boas Práticas de Aceitação de Risco

Como prática padrão, geralmente é preferível usar exclusivamente Aceitações de Risco Completas ou Aceitações de Risco Simples, em vez de utilizar as duas abordagens.

Por exemplo, se as Aceitações de Risco Completas forem a abordagem padrão, ter um Achado com Risco Aceito de forma Simples pode causar confusão caso não exista uma Aceitação de Risco Completa associada que contenha o Achado em questão. Da mesma forma, se os Achados costumam ter o Risco Aceito de forma Simples, também pode gerar confusão adicionar alguns Achados a uma Aceitação de Risco Completa quando não existem esses objetos para a maioria dos demais Achados.
