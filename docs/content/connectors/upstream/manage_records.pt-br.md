---
title: Gerenciando Registros
description: Direcione o fluxo de dados da sua ferramenta para o DefectDojo
aliases:
- /pt-br/import_data/pro/connectors/manage_records/
- /pt-br/en/connecting_your_tools/connectors/manage_records
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: os Conectores Upstream são um recurso exclusivo do DefectDojo Pro.</span>

Depois de executar sua primeira operação de Discover, você deverá ver uma lista de Registros Mapeados ou Não Mapeados na página **Manage Records and Operations**.

## O que é um Registro?

Um Registro é uma conexão entre um **Produto** do DefectDojo e um **Produto Equivalente do Fornecedor**. Você pode usar sua lista de Registros para controlar o fluxo de dados entre sua ferramenta e o DefectDojo.

Os Registros são criados e atualizados durante a operação **[Discover](../manage_operations/#discover-operations)**, que o DefectDojo executa diariamente para procurar novos Produtos Equivalentes do Fornecedor.

![image](images/manage_records.png)

Os Registros têm vários atributos, incluindo:

* O **State** (Estado) do Registro
* O **Produto** para o qual o Registro importa dados
* Quando o Registro foi **descoberto pela primeira e pela última vez** (pelo processo de **Discover**)
* Quando o mapeamento do Registro foi **finalizado** por um usuário
* Um link para o **Produto** do DefectDojo

## Como os Registros são mapeados

Cada Registro precisa ter um Mapeamento atribuído. O Mapeamento informa ao DefectDojo onde armazenar os dados de varredura vindos da ferramenta. Um Registro Mapeado associa o Produto Equivalente do Fornecedor a um Produto do DefectDojo e instrui o Conector a começar a importar dados de varredura para esse local (como Engajamentos e Testes).

Você pode atribuir Mapeamentos você mesmo, ou pode deixar que o DefectDojo os atribua automaticamente.

### Auto-Mapping

Se você tiver o **Auto-Mapping** habilitado, os novos Registros serão Mapeados para Produtos automaticamente. Cada vez que o DefectDojo **descobre** (Discover) um novo Registro, um Produto do DefectDojo correspondente será criado automaticamente para cada Registro. Esse Registro será armazenado em **Mapped Records** para indicar que está pronto para importar dados para o DefectDojo.

Se você não tiver o Auto-Mapping habilitado, você pode decidir por conta própria para onde deseja que os dados fluam. Cada vez que o Conector encontrar um novo Produto Equivalente do Fornecedor (via **Discover**), ele adicionará um novo Registro à sua lista de **Unmapped Records**, e você poderá então atribuir manualmente esse Registro a um Produto novo ou existente no DefectDojo.

#### Mapeamento - Exemplo de Fluxo de Trabalho:

David acabou de configurar um conector para sua ferramenta BurpSuite e executa uma operação Discover. David tem o Burp configurado para varrer 4 'Sites' diferentes, e o DefectDojo cria um novo Registro para cada um desses Sites.

* Se David decidir usar o Auto-Mapping, o DefectDojo criará um novo Produto para cada Site. A partir de agora, quando o DefectDojo executar uma operação Synchronize, o Conector importará os dados de varredura diretamente do Site para o Produto (via o mapeamento do Registro)  
​
* Se David deixar o Auto-Mapping desativado, o DefectDojo ainda assim descobrirá esses 4 Sites e criará os Registros, mas não importará nenhum dado até que David crie os Mapeamentos ele mesmo.  
​
* David sempre pode alterar posteriormente a forma como esses mapeamentos estão configurados. Talvez ele queira consolidar a saída de vários Sites diferentes do Burp em um único Produto. Ou talvez ele queira ter um Produto que registre dados de varredura de várias ferramentas diferentes - incluindo o Burp. É fácil para David alterar onde os dados de varredura do Burp são armazenados no DefectDojo, bastando mudar o Mapeamento desses Registros.

## Como os Registros interagem com os Produtos

Uma vez que um Registro é Mapeado, o DefectDojo estará pronto para importar as varreduras da sua ferramenta por meio de uma Operação Sync. Os Conectores podem funcionar em conjunto com outros processos de importação do DefectDojo ou com testes interativos.

* Os Mapeamentos de Registros são projetados para serem não invasivos. Se você mapear um Produto para um Registro que contenha Engajamentos ou Achados existentes, esses Engajamentos e Achados existentes não serão afetados nem sobrescritos pelo processo de sincronização de dados.  
​
* Todos os dados criados por meio de um conector serão armazenados em um único Engajamento chamado **Global Connectors**. Esse Engajamento criará um Teste separado para cada Conector mapeado ao Produto.

![image](images/manage_records_2.jpg)

Isso torna possível enviar dados de varredura de vários Conectores para o mesmo Produto. Todos os dados serão armazenados no mesmo Engajamento, mas cada Conector armazenará dados em um Teste separado.

Para saber mais sobre Produtos, Engajamentos e Testes, consulte nosso [Product Hierarchy Overview](/asset_modelling/os_hierarchy/product_hierarchy/).

## Glossário de Estados de Registro

Cada Registro tem um estado associado para comunicar como o Registro está funcionando.

A lista completa de registros de um conector é acessada abrindo o conector em **Connect \> Upstream** — a página se chama **All \<Connector\> Records**. Apesar do nome, ela lista todos os Registros pertencentes **àquele único conector**, não todos os Registros da instância.

Essa lista pode ser **filtrada por estado** na coluna **State**, e mais de um estado pode ser selecionado ao mesmo tempo. Essa é a forma mais rápida de responder às perguntas que surgem com mais frequência em uma frota grande de conectores — *o que está esperando que eu mapeie?* (**New**) e *o que parou de reportar?* (**Missing** ou **Error**) — sem precisar ler todos os Registros um por um.

Nem todo estado se aplica a todo conector. **Stale** é definido pelo pipeline de importação de achados, portanto só ocorre em conectores que importam achados; os **Asset Connectors** nunca entram nesse estado, e ele não é oferecido como opção de filtro para eles.

### New

Um Registro New é um Registro Não Mapeado que o DefectDojo descobriu. Ele pode ser Mapeado para um Produto ou Ignorado. Para mapear um novo Registro a um Produto, consulte nosso guia sobre [Editing Records]().

### Good

'Good' indica que um Registro está Mapeado e funcionando corretamente. As futuras Operações Discover verificam se o Produto Equivalente do Fornecedor subjacente ainda existe, para garantir que a operação Sync será executada corretamente.

### Ignored

Os Registros 'Ignored' foram descobertos com sucesso, mas um usuário do DefectDojo decidiu não mapear os dados para um Produto.

## Estados de Aviso: Stale ou Missing

Se a conexão entre a ferramenta e o DefectDojo mudar, o estado de um Registro mudará para avisá-lo.

### Stale

Um Mapeamento passa para 'Stale' quando um Produto, Engajamento ou Teste relacionado foi excluído do DefectDojo. O mapeamento ainda existe, mas não há mais nenhum lugar no DefectDojo para onde os dados da Ferramenta possam ser importados.

Registros Stale podem ser remapeados para um Produto existente, ou Ignorados se os dados de varredura não forem mais relevantes.

### Missing

Se um Registro foi Mapeado, mas os dados de origem (ou o Produto Equivalente do Fornecedor) não estão sendo detectados pelo DefectDojo, o Registro será rotulado como **Missing**.

Os Conectores do DefectDojo se adaptam a mudanças de nome, mudanças de diretório e outras alterações de dados, então isso provavelmente ocorre porque o Produto Equivalente do Fornecedor relacionado foi excluído da Ferramenta que você está usando.

Se você pretendia remover o Produto Equivalente do Fornecedor da sua ferramenta, você pode excluir um Registro Missing. Caso contrário, será necessário investigar o problema dentro da Ferramenta para que os dados de origem possam ser descobertos corretamente.

### Error

**Error** indica que o DefectDojo não conseguiu processar o Registro. Está disponível em todos os tipos de conector e pode ser selecionado no filtro **State** junto com os estados acima, o que o torna a forma mais rápida de verificar se algo em um conector precisa de atenção depois de uma execução.

## Editar Registros: Remapear, Ignorar ou Excluir

Os Registros podem ser Editados, Ignorados ou Excluídos na página **Manage Records \& Operations**.

Embora os registros Mapeados e Não Mapeados estejam em tabelas separadas, ambos podem ser editados da mesma forma.

Na tabela de Registros, clique na seta azul ▼ ao lado da coluna State em um determinado Registro. A partir daí, você pode selecionar **Edit Record** ou **Delete Record**.

![image](images/edit_ignore_delete_records.png)

### Alterar o Mapeamento de um Registro

Clicar em **Edit Record** abrirá uma janela que permite alterar o produto de destino no DefectDojo. Você pode selecionar um Produto existente no menu suspenso ou digitar o nome de um novo Produto que deseja criar.

![image](images/edit_ignore_delete_records_2.png)

Os dados de varredura associados a um Registro podem ser direcionados para fluir para um Produto diferente ao alterar o mapeamento.

Selecione, ou digite o nome de um novo Produto no menu suspenso à direita.

#### Editar o Estado de um Registro

O Estado de um Registro também pode ser alterado a partir deste menu. Os Registros podem ser alternados entre Good e Ignored (ou vice-versa) escolhendo uma opção na lista suspensa **State**.

### Ignorando um Registro

Se você quiser 'desligar' um dos registros ou descartar os dados que ele está enviando ao DefectDojo, você pode optar por 'Ignore' o registro. Um registro 'Ignored' será movido para a lista de Unmapped Records e não enviará novos dados ao DefectDojo.

Você pode Ignorar um Registro Mapeado (o que removerá o mapeamento), ou um Registro New (a partir da lista de Registros não mapeados).

#### Restaurando um Registro Ignorado

Se você quiser remover o status Ignored de um registro, você pode alterá-lo de volta para New usando o mesmo menu suspenso State.

* Se o Auto-Map Records estiver habilitado, o Registro retornará ao seu mapeamento original assim que a operação Discover for executada novamente.  
* Se o Auto-Map Records não estiver habilitado, o DefectDojo não restaurará automaticamente um mapeamento anterior, então será necessário configurar o mapeamento deste Registro novamente.

### Excluir um Registro

Você também pode Excluir Registros, o que os removerá da tabela de Registros Não Mapeados ou Mapeados.

Lembre-se de que a função Discover sempre importará todos os registros de uma ferramenta - o que significa que, mesmo que um Registro seja excluído do DefectDojo, ele será redescoberto posteriormente (e voltará à lista de Registros a serem mapeados novamente).

* Se você planeja remover o Produto Equivalente do Fornecedor subjacente da sua ferramenta de varredura, então Excluir o Registro é uma boa opção. Caso contrário, a próxima operação Discover verá que os dados associados estão ausentes, e esse Registro mudará de estado para 'Missing'.  
​
* No entanto, se o Produto Equivalente do Fornecedor subjacente ainda existir, ele será descoberto novamente em uma futura operação Discover. Para evitar esse comportamento, você pode Ignorar o Registro.

#### Isso afeta algum dado importado?

Não. Todos os Achados, Testes e Engajamentos criados por um registro de sincronização permanecerão no DefectDojo mesmo depois que um Registro for excluído. Excluir um registro ou uma configuração removerá apenas o processo de fluxo de dados, e não excluirá nenhum dado de vulnerabilidade do DefectDojo ou da sua ferramenta.
