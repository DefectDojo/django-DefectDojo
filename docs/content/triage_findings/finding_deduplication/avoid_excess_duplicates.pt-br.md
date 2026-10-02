---
title: Evitando Duplicados em Excesso
description: ''
weight: 4
aliases:
- /pt-br/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport
---

Um dos pontos fortes do DefectDojo é que o modelo de dados pode acomodar muitos casos de uso e aplicações diferentes. É provável que você mude sua abordagem à medida que domina o software e descobre formas de otimizar seu fluxo de trabalho.

Por padrão, o DefectDojo não exclui nenhum Achado duplicado criado. Cada Achado é considerado uma instância separada de uma vulnerabilidade. Portanto, nesse caso, **Achados duplicados** podem ser um indicador de que é necessária uma mudança de processo no seu fluxo de trabalho.

## Quando os Achados duplicados são aceitáveis?

Achados duplicados nem sempre indicam um problema. Há muitos casos em que manter os duplicados é a abordagem preferida. Por exemplo:

* Se sua equipe usa e reporta Engajamentos Interativos. Se você quer criar um relatório específico e isolado sobre um único Teste, é útil saber se há uma ocorrência de um Achado que já havia sido descoberto anteriormente.
* Se você tem Engajamentos que são separados contextualmente (por exemplo, porque cobrem repositórios diferentes), é útil poder sinalizar Achados que estão ocorrendo em ambos os lugares.

## Verificando importações redundantes

## Etapa 1: Limpe seus Duplicados em excesso

Felizmente, as configurações de Deduplicação do DefectDojo permitem excluir duplicados em massa quando um determinado limite é ultrapassado. Esse recurso facilita o processo de limpeza. Para saber mais sobre esse processo, consulte nosso artigo sobre **Deduplicação de Achados** \<\-link virá aqui.

### Etapa 2: Avalie seus Engajamentos em busca de redundâncias

Depois de limpar seus Achados duplicados, é uma boa prática observar o Produto que os continha para verificar se há um culpado evidente. Você pode descobrir que há Engajamentos ali contidos com um contexto redundante.

#### Engajamentos duplicados ou reutilizados

Os Engajamentos armazenam um ou mais Testes para um determinado contexto de teste. Esse contexto cabe a você definir, mas se você perceber que alguns Engajamentos dentro do seu Produto deveriam compartilhar o mesmo contexto, considere combiná-los em um único engajamento.
​
### Perguntas a fazer ao definir o contexto de um Engajamento:

* Se eu quisesse fazer um relatório sobre esse trabalho, o Engajamento conteria todas as informações relevantes de que preciso?
* Estamos criando Engajamentos proativamente com antecedência, ou eles estão sendo criados de forma ‘ad\-hoc’ pelo meu processo de importação?
* Estamos usando o tipo certo de Engajamento \- **Interativo** ou **CI/CD**?
* Qual seção da base de código está sendo trabalhada pelos testes: cada repositório é um contexto separado, ou vários repositórios poderiam compor um contexto compartilhado para os testes?
* Quem são as partes interessadas envolvidas com o Produto, e como vou compartilhar os resultados com elas?

### Etapa 3: Verifique se há Testes redundantes

Se você descobrir que Testes separados foram criados capturando o mesmo contexto de teste, isso pode ser um indicador de que esses testes podem ser consolidados em uma única Reimportação.

O DefectDojo tem dois métodos para importar dados de teste e criar Achados: **Importação** e **Reimportação**. Ambos os métodos são muito semelhantes, mas a principal diferença entre eles é que a **Importação** sempre cria um novo Teste, enquanto a **Reimportação** pode adicionar novos dados a um Teste existente. Também vale notar que a **Reimportação** não cria Achados duplicados dentro daquele Teste.

Cada vez que você importa novos relatórios de vulnerabilidade no DefectDojo, esses relatórios são armazenados em um objeto Teste. Um objeto Teste pode ser criado por um usuário com antecedência para receber uma futura **Importação**. Se um usuário quiser importar dados sem especificar um Teste de destino, um novo Teste será criado para armazenar o relatório recebido.

Os Testes são objetos flexíveis e, embora só possam conter um *tipo* de relatório, podem lidar com múltiplas instâncias desse mesmo relatório por meio do método de **Reimportação**. Para saber mais sobre a Reimportação, consulte nosso **[artigo](/import_data/import_intro/reimport/)** sobre o tema.


## Usando a Reimportação para Testes contínuos

Se você tem um pipeline de CI/CD, um processo diário de varredura ou qualquer tipo de relatório recorrente, configurar um processo de Reimportação com antecedência é essencial para evitar duplicados excessivos. A Reimportação consolida o contexto e os Achados associados a um teste recorrente em uma única página de Teste, onde você pode revisar o histórico de importações e acompanhar as mudanças de vulnerabilidades entre as varreduras.

1. Crie um Engajamento para armazenar os resultados de CI/CD do objeto no qual você está executando CI/CD. Isso pode ser um repositório de código onde você tem ações de CI/CD configuradas para rodar. Em geral, você vai querer um Engajamento separado configurado para cada pipeline, para poder entender rapidamente de onde vêm os resultados dos Achados.
​
2. Cada ação de CI/CD importará dados para o DefectDojo em uma etapa separada, então cada uma delas deve ser mapeada para um Teste separado. Por exemplo, se cada execução do pipeline roda um NPM\-audit e também uma varredura de dependências, cada resultado de varredura precisará ser direcionado a um Teste (aninhado sob o Engajamento).
​
3. Você não precisa criar um novo Teste toda vez que a ação de CI/CD é executada. Em vez disso, você pode **Reimportar** os dados para o mesmo local de teste.

### A Reimportação em ação

O DefectDojo comparará os dados de varredura recebidos com os dados de varredura existentes e aplicará mudanças aos Achados contidos no seu Teste da seguinte forma:
​
#### Criar Achados

Quaisquer vulnerabilidades que não estavam contidas na importação anterior serão adicionadas ao Teste automaticamente como novos Achados.
​
#### Ignorar Achados existentes

Se algum Achado recebido corresponder a Achados já existentes, os Achados recebidos serão descartados em vez de registrados como Duplicados. Esses Achados já foram registrados \- não é necessário adicionar um novo objeto de Achado. A página do Teste mostrará esses Achados como **Não Modificados**.
​
#### Fechar Achados

Se houver Achados que já existem no Teste, mas que não estão presentes no relatório recebido, você pode optar por definir automaticamente esses Achados como Inativos e Mitigados (partindo do pressuposto de que essas vulnerabilidades foram resolvidas desde a importação anterior). A página do Teste mostrará esses Achados como **Fechados**.

Se você não quiser que nenhum Achado seja fechado, pode desabilitar esse comportamento na Reimportação:

* Desmarque a caixa de seleção **Fechar Achados Antigos** se estiver usando a interface
* Defina **close\_old\_findings** como **False** se estiver usando a API  ​

#### Reabrir Achados

* Se houver Achados Fechados que apareçam novamente em uma Reimportação, eles serão automaticamente Reabertos. Presume-se que essas vulnerabilidades ocorreram novamente, apesar da mitigação anterior. A página do Teste registrará esses Achados como **Reativados**.

Se você estiver usando um scanner sem triagem, ou não quiser que Achados Fechados sejam reativados, pode desabilitar esse comportamento na Reimportação:

* Defina **do\_not\_reactivate** como **True** se estiver usando a API
* Marque a caixa de seleção **Não Reativar** se estiver usando a interface

### Trabalhando com o Histórico de Importações

O Histórico de Importações de um determinado teste é listado sob o cabeçalho **Test Overview** na página do **Teste**.

Essa tabela mostra cada Importação ou Reimportação como uma única linha com um **Timestamp**, junto com as colunas **Branch Tag, Build ID, Commit Hash** e **Version**, caso tenham sido especificados.

![imagem](images/Avoiding_Duplicates_Reimport_Recurring_Tests.png)

### Ações

Esse cabeçalho indica as ações realizadas por uma Importação/Reimportação.

* **\# created indica o número de novos Achados criados no momento da Importação/Reimportação**
* **\# closed mostra o número de Achados que foram fechados por uma Reimportação (por não existirem no relatório recebido).**
* **\# left untouched mostra a contagem de Achados Abertos que não foram alterados por uma Reimportação (por também existirem no relatório recebido).**
* **\#** **reactivated** mostra quaisquer Achados Fechados que foram reabertos por uma Reimportação recebida.

### Por que não simplesmente usar a Importação?

Embora ambos os métodos sejam possíveis, a Importação deve ser reservada para **novas ocorrências** de Achados e dados, enquanto a Reimportação deve ser aplicada para **iterações adicionais** dos mesmos dados.

Se o seu pipeline de CI/CD executa uma Importação e cria um novo objeto Teste a cada vez, cada Importação vai gerar uma coleção de Achados distintos que você precisará gerenciar como objetos separados. Usar a Reimportação alivia esse problema e elimina a quantidade de ‘limpeza’ que você precisaria fazer quando uma vulnerabilidade é resolvida.

Usar a Reimportação permite armazenar cada relatório recorrente na mesma página e mantém a continuidade de cada momento em que novos dados foram adicionados ao Teste.

No entanto, se você estiver usando a mesma ferramenta de varredura em vários locais ou contextos, pode ser mais apropriado criar um Teste separado para cada local ou contexto. Isso depende do método de organização que você preferir.
