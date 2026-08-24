---
title: Automação do Rules Engine
description: Trabalhando com a automação do Rules Engine
weight: 1
audience: pro
aliases:
- /pt-br/en/customize_dojo/rules_engine
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Observação: o Rules Engine é um recurso exclusivo do DefectDojo Pro.</span>

O Rules Engine do DefectDojo permite construir workflows personalizados e ações em massa para tratar Findings e outros objetos. O Rules Engine permite construir ações automatizadas que são disparadas quando um objeto corresponde a uma Regra.

O Rules Engine só pode ser acessado através da [Pro UI](/get_started/about/ui_pro_vs_os/).

**Procurando o editor de grafos?** O [Rules Engine 2.0](/automation/rules_engine_2/about/) constrói automações como grafos visuais de nós, e adiciona ramificações, ações de saída como tickets e mensagens, rastros por execução e um livro-razão de entregas. Os dois mecanismos funcionam lado a lado, e regras existentes podem ser [convertidas](/automation/rules_engine_2/converting_from_rules_engine/).

## Habilitando o Rules Engine

O Rules Engine está em Beta e vem desativado por padrão. Um superusuário pode ativá-lo em **Settings > Feature Flags**, tanto em instâncias Cloud quanto On-Premise. Veja [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Atualmente, Regras só podem ser criadas para Findings, mas mais tipos de objeto serão suportados no futuro.

As Regras podem ser disparadas manualmente na página **All Rules**, ou agendadas para rodar automaticamente em um cronograma recorrente. Quando uma regra é disparada, ela será aplicada a todos os Findings existentes que correspondam às condições de filtro definidas.

## Ações de Regra possíveis
Cada Regra pode aplicar uma ou mais destas alterações a um Finding quando é disparada com sucesso (ou seja, corresponde às condições de Filtro definidas).

### Modificações de campo
* **Definir um campo** em um Finding, incluindo Title, Description, Severity, CVSSv3 Vector, Active, Verified, Risk Accepted, False Positive, Mitigated
* **Anexar ou prefixar texto** ao Title ou Description de um Finding
* **Set Priority** — sobrescreve o valor de Priority calculado em um Finding (sobrepõe o cálculo automático de prioridade)
* **Set Risk** — sobrescreve o nível de Risk calculado em um Finding (sobrepõe o cálculo automático de risco)
* **Somar, Subtrair, Multiplicar ou Dividir** o valor de Priority em um Finding por um número informado

### Atribuições e propriedade
* **Definir um usuário para revisar** um Finding
* **Atribuir um Grupo como Owners** de um Finding
* **Definir uma Mitigation Policy** em um Finding — atribui uma Mitigation Policy pré-configurada ao Finding
* **Adicionar a Risk Acceptance** — adiciona um Finding a um registro de Risk Acceptance existente (define risk_accepted=True, active=False, e trata a integração com Jira e os status de endpoint)

### Tags, Notas e Alertas
* **Adicionar Tags** a um Finding
* **Adicionar uma Nota** a um Finding
* **Criar um Alerta** no DefectDojo com texto personalizado

### Condições de filtro
As Regras são disparadas automaticamente quando um Finding atende a condições de Filtro específicas. Para mais informações sobre os Filtros que podem ser usados para criar Ações de Regra, veja a página [Filter Index](/navigation/pro__filter_index).

## Criando uma nova Regra
Inicie este processo pela página New Rule. Na [Pro UI](/get_started/about/ui_pro_vs_os/), em **Manage Category**, expanda o menu suspenso **Rules Engine** e clique em **+ New Rule**.

![image](images/rules_engine_1.png)

### Etapa 1: Nomeie sua Regra
Digite um Label como identificador da nova regra e clique em Next.

![image](images/rules_engine_2.png)

### Etapa 2: Defina as condições de disparo com um Filtro
Você verá uma tabela All Findings. Usando essa tabela, defina as condições de Filtro para filtrar o conjunto de Findings ao qual sua regra deve se aplicar. Para mais informações sobre como aplicar Filtros a uma tabela, veja [nosso guia da Pro UI](/get_started/about/ui_pro_vs_os/#navigational-changes).

A tabela mostrará uma prévia da lista de Findings existentes que você filtrou.

Por exemplo, nesta captura de tela estamos filtrando todos os Findings que estão em 'Product One'. Depois de aplicarmos este filtro (clicando fora do menu de Filtros), ele será adicionado à nossa lista de Filtros aplicáveis.

![image](images/rules_engine_3.png)

Na captura de tela acima, todos os Findings que estão no Produto 'Product One' terão ações aplicadas a eles.

Depois de ter o conjunto de Filtros que deseja aplicar, clique no botão Next.

### Etapa 3: Defina as Ações da Regra 
No menu suspenso **Action**, selecione a Ação que deseja aplicar a um Finding que corresponda a todos os filtros da Etapa 2. Várias Ações podem ser aplicadas.

Você pode definir Valores Condicionais adicionais, que permitem executar ações extras caso certos critérios sejam atendidos.  

![image](images/rules_engine_4.png)


Por exemplo, na captura de tela acima temos 4 Ações de Regra definidas. Duas dessas ações são Condicionais.

Todos os Findings que correspondem às condições de filtro disparam estas Ações Não Condicionais:

* O Finding será atribuído ao grupo de usuários 'Group 1'
* O Finding será marcado com a tag `all_group_1`

Quaisquer Findings que correspondam às condições de filtro, mais estas condições **adicionais**, disparam estas Ações Condicionais, além das duas Ações Não Condicionais listadas acima:

* **se o Finding tiver Severidade Crítica**, ele será marcado com a tag `critical_group_1`.
* **se o Finding tiver Severidade Alta**, ele será marcado com a tag `high_group_1`.

### Etapa 4 - Visualize a prévia da sua Regra

O Rule Preview exibe todos os Findings que serão alterados por esta regra quando ela for executada, junto com uma prévia das Ações realizadas. Confirme que está satisfeito com as alterações propostas e clique em Submit para salvar sua regra. 

Se você acredita que esta regra não foi aplicada corretamente, pode clicar no botão Back e voltar a qualquer uma das etapas anteriores. 

![image](images/rules_engine_5.png)

Por exemplo, na captura de tela acima temos uma lista de Findings que serão afetados pela Regra quando ela for executada. Podemos ver que novas Tags e Owners serão aplicados a cada um desses Findings, nas colunas à direita da lista de Findings.

Você será solicitado novamente a confirmar que deseja criar sua Regra. Observe que a **Regra não será aplicada imediatamente**, e deve ser disparada manualmente.

## Executando uma Regra
Na página All Rules, você pode selecionar a Regra que deseja executar. Clique no título da regra para vê-la em mais detalhes.

![image](images/rules_engine_6.png)

Nesta página, você pode ver informações detalhadas sobre esta regra em **Metadata**, incluindo informações sobre quando a regra foi disparada pela última vez. Você também pode ver uma prévia de quaisquer Findings que serão afetados por uma nova execução desta Regra, logo abaixo de **Rule Preview**.

Para executar a Regra, clique no botão verde Run Rule. Depois de confirmar que deseja executar a regra, aparecerá uma mensagem informando que a regra foi enfileirada para execução em segundo plano.

Assim que a Regra terminar de ser executada com sucesso, o número de Items Changed será atualizado na seção Rule Metadata da descrição da Regra.

## Referência de Rule Metadata
* **Rule For**: os objetos governados pela Regra.
* **Rule Name**: o nome da Regra.
* **Filters**: o número de Filtros aplicados por esta Regra.
* **Actions**: o número de Ações realizadas por esta Regra.
* **Owner**: o Usuário que criou esta Regra.
* **Status**: o relatório de Status da última vez que esta Regra foi executada.  
    'E' = 'Error', 'R' = 'Running', 'S' = 'Success'.
* **Last Run**: o timestamp da última vez que esta Regra foi executada.
* **Items Changed:** contagem de objetos que foram alterados na última execução da regra.
* **Items Skipped:** contagem de objetos que foram ignorados na última execução da regra. Se um objeto filtrado já corresponde ao 'resultado' de uma Ação de Regra aplicada a ele (por exemplo, se ele já tem as Tags que seriam aplicadas por uma Ação de Regra), o objeto simplesmente será ignorado.
