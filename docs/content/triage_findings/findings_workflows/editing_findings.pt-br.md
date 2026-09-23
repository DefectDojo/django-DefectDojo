---
title: Editando Achados
description: Altere o Status de um Achado ou adicione mais metadados ao resolver um
  problema
weight: 2
aliases:
- /pt-br/en/working_with_findings/findings_workflows/editing_findings
---

Se você quiser adicionar notas ou atualizar o texto de um Achado para torná-lo mais relevante para a situação atual, pode fazer isso pelo formulário Editar Achado.

## Abrindo o Formulário Editar Achado

Você pode atualizar um Achado abrindo o **Menu** **⚙️ Engrenagem** na parte superior e clicando em **Editar Achado.**

![imagem](images/Editing_Findings.png)

Isso abrirá o formulário **Editar Achado**, onde você pode editar os metadados, alterar o Status do Achado e adicionar informações adicionais.

![imagem](images/Editing_Findings_2.png)

### Campos do Formulário Editar Achado

* **"Test" não pode ser editado:** os Achados sempre precisam estar associados a um objeto Test e não podem ser movidos para fora desse contexto. No entanto, o Engajamento que contém um Teste pode ser movido para outro Produto.
​
* **Found By** é a ferramenta de scan que descobriu esse Achado. Observe que é possível adicionar ferramentas de scan adicionais além daquela associada ao Teste.
​
* **Title** é criado a partir do relatório de scan, mas você pode editar esse título para torná-lo mais significativo, se necessário. Observe que isso pode afetar a Deduplicação, já que a Deduplicação geralmente usa os títulos dos Achados para identificar duplicatas.
​
* **Date** representa a data em que o Achado foi descoberto pelo scanner \- não necessariamente a data em que o Achado foi importado para o DefectDojo. Essa data é extraída do relatório de scan, mas você pode atualizá-la para torná-la mais precisa, se necessário (por exemplo, ao trabalhar com dados históricos, ou ao usar uma ferramenta de scan que não registra as datas de descoberta).
​
* **Description** é a descrição de um Achado fornecida pela ferramenta de scan. Você pode adicionar ou remover informações da Descrição do Achado, se desejar.
​
* **Severity** é calculada com base em vários fatores. No nível básico, será a Severidade relatada por uma ferramenta, mas a Severidade de um Achado pode ser afetada por mudanças no EPSS. Você também pode ajustar manualmente a Severidade do Achado para um nível apropriado.
​
* **Tags** são rótulos de texto genéricos que você pode usar para organizar seus Achados por meio de Filtros \- ou podem simplesmente ser usadas como forma abreviada de identificar um Achado específico.
​
* **Active / Verified** são os principais status de Achado usados por uma ferramenta. Achados Ativos são Achados que estão atualmente ativos em sua rede e foram relatados por uma ferramenta. Verificado significa que esse Achado foi confirmado como existente por um membro da equipe.
​
* **SAST / DAST** são rótulos usados para organizar seus Achados de acordo com o contexto em que foram descobertos. Geralmente, esse rótulo é preenchido com base na ferramenta de scan usada, mas você pode ajustá-lo para um nível mais preciso (por exemplo, se o Achado foi encontrado tanto por uma ferramenta SAST quanto por uma DAST).

### Editando a Data de Mitigação e Mitigado Por

Por padrão, os valores de **Mitigated Date** e **Mitigated By** de um Achado **não são editáveis**. Esses campos ficam ocultos tanto no formulário Editar Achado quanto na caixa de diálogo de Fechamento do Achado, e a Data de Mitigação é sempre definida automaticamente no momento em que o Achado é fechado. Tentativas de definir ou retroagir esses valores pela API são rejeitadas pelo mesmo motivo.

A edição pode ser habilitada com a configuração de servidor `DD_EDITABLE_MITIGATED_DATA`. Quando habilitada, os campos **Mitigated Date** e **Mitigated By** aparecem no formulário Editar Achado e na caixa de diálogo de Fechamento do Achado, e também podem ser definidos pela API — mas apenas para usuários com status de **superusuário**. Em outras palavras, a edição exige *ao mesmo tempo* que a configuração esteja habilitada *e* que o usuário que realiza a ação seja superusuário.

* **Por que vem desativado por padrão:** permitir que uma mitigação seja retroagida pode distorcer a conformidade com o SLA — um Achado que na verdade foi corrigido *fora* da janela do SLA poderia ser registrado como se tivesse sido mitigado *dentro* do SLA. Habilitar a configuração é apenas prospectivo; ela **não** altera a Data de Mitigação nem a idade de nenhum Achado já existente.
* **Tudo permanece auditável:** toda alteração em um Achado, incluindo edições em Mitigated Date e Mitigated By, é registrada no histórico do Achado — quem fez a alteração, quando, e os valores anterior e novo.
* **Aplicando a configuração:** `DD_EDITABLE_MITIGATED_DATA` é uma variável de ambiente no nível do servidor (veja [Configuração](/get_started/open_source/configuration/)). Alterá-la exige a reinicialização do serviço para ter efeito.
* **DefectDojo Cloud / Pro:** essa configuração não pode ser alterada pela interface. Entre em contato com o Suporte do DefectDojo para que seja habilitada em sua instância.

## Edição em Massa de Achados

Os Achados podem ser editados em massa a partir de uma Lista de Achados, que pode ser encontrada tanto na própria página de Achados quanto dentro de um Teste.

### Selecionando Achados para Edição em Massa

Ao visualizar uma tabela com vários Achados, como a tabela ‘Findings From \[tool]’ em uma Página de Teste ou a lista Todos os Achados, você pode usar as caixas de seleção ao lado dos Achados para marcá-los para Edição em Massa.

Selecionar um ou mais Achados dessa forma abrirá o menu (oculto) de Edição em Massa, que contém as quatro opções a seguir:

* **Ações de Atualização em Massa**: aplica alterações de metadados aos Achados selecionados.
* **Ações de Aceitação de Risco: cria uma Aceitação de Risco Completa para reger os Achados selecionados, ou adiciona os Achados a uma Aceitação de Risco Completa existente**
* **Ações de Grupo de Achados: cria um Grupo de Achados composto pelos Achados selecionados. Observe que Grupos de Achados só podem ser criados dentro de um Teste individual.**
* **Excluir: exclui os Achados selecionados. Será necessário confirmar essa ação em uma nova janela.**

![imagem](images/Bulk_Editing_Findings.png)

### Ações de Atualização em Massa

Por meio do menu Ações de Atualização em Massa, você pode aplicar as seguintes alterações a quaisquer Achados selecionados:

* Atualizar a **Severidade**
* Aplicar um novo **Status do Achado**
* Alterar a Data de Descoberta ou de Correção Planejada dos Achados
* Adicionar uma **Aceitação de Risco Simples,** se a opção estiver habilitada no nível do Produto
* Aplicar **Tags** ou **Notas** a todos os Achados selecionados.

![imagem](images/Bulk_Editing_Findings_2.png)

### Ações de Aceitação de Risco

Esta página permite adicionar uma **Aceitação de Risco Completa** aos Achados selecionados. Você pode criar uma nova **Aceitação de Risco Completa** ou adicionar os Achados a uma que já exista.

![imagem](images/Bulk_Editing_Findings_3.png)

### Ações de Grupo de Achados

Esta página permite criar um novo Grupo de Achados a partir dos Achados Selecionados, ou adicioná-los a um Grupo de Achados existente.

No entanto, Grupos de Achados só podem ser criados dentro de um **Teste** individual \- Achados de Testes, Engajamentos ou Produtos diferentes não podem ser adicionados ao mesmo Grupo de Achados.

![imagem](images/Bulk_Editing_Findings_4.png)

### Exclusão em Massa de Achados

Você também pode Excluir os Achados selecionados clicando no botão vermelho **Excluir**. Uma janela pop-up aparecerá pedindo que você confirme essa decisão.

![imagem](images/Bulk_Editing_Findings_5.png)
