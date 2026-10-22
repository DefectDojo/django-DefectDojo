---
title: Definições de Status de Achado
description: 'Uma referência rápida aos status de Achado: Aberto, Verificado, Aceito..'
weight: 2
aliases:
- /pt-br/en/working_with_findings/findings_workflows/finding_status_definitions
---

Cada Achado criado no DefectDojo tem um Status que comunica informações relevantes. Os status ajudam sua equipe a acompanhar o progresso na resolução dos problemas.

Cada status de Achado tem um significado específico de contexto que precisará ser definido pela sua própria equipe. Estas são nossas sugestões, mas o uso da sua equipe pode variar.

Observe que Aberto/Fechado não são tipos de Status **explícitos** para Achados.  Alguns elementos da Classic UI (a tabela "All Open Findings", por exemplo) podem se referir a Achados Abertos ou Fechados: isso funciona como um termo genérico para

* Achados Ativos e/ou Verificados, no caso de "Achados Abertos"
* Achados Inativos e/ou com Risco Aceito, Em Revisão, Fora do Escopo ou Falso Positivo, no caso de "Achados Fechados"

## **Status de Achado Aberto**

Assim que um Achado está **Ativo**, ele é rotulado como um Achado **Aberto**, independentemente de ter sido **Verificado** ou não.

Os Achados Abertos podem ser vistos na visualização **Findings \> Open Findings** do DefectDojo.

### **Achados Ativos**

'Este Achado foi descoberto por uma ferramenta de scan.'

Por padrão, todo novo Achado criado no DefectDojo é rotulado como **Ativo**. Ativo, nesse caso, significa 'este é um novo Achado que o DefectDojo não registrou em uma importação anterior'. Se um Achado foi Mitigado no passado, mas aparece novamente em um scan futuro, o status desse Achado será reaberto para refletir que a vulnerabilidade retornou.

### **Achados Verificados**

'Nossa equipe confirmou que este Achado existe.'

O simples fato de uma ferramenta registrar um problema não significa necessariamente que o Achado exija atenção da engenharia. Por isso, novos Achados também são rotulados como **Não Verificado** por padrão.

Se você conseguir confirmar que o Achado realmente existe, pode marcá-lo como **Verificado**.

Certas funções do DefectDojo exigem que os Achados estejam Ativos e Verificados.  Se você não precisar verificar manualmente cada Achado, pode desativar a exigência de Verificado para qualquer uma ou todas essas funções na página **System Settings** (**Classic UI: Configuration > System Settings**, **Pro UI: Settings > System > System Settings**).

![imagem](images/verified_status_toggle.png)

Esses Status Verificado são exigidos para

* Enviar Issues do Jira
* Aplicar Classificação (Grading) aos Produtos
* Calcular Métricas

## **Status de Achado Fechado**

'A vulnerabilidade registrada aqui não está mais ativa'.

Depois que o trabalho em um Achado é concluído, você pode Fechá-lo manualmente pela opção Close Findings. Alternativamente, se um scan for reimportado no DefectDojo e não contiver um Achado registrado anteriormente, esse Achado será fechado automaticamente.

## **Inativo**

'Este Achado foi descoberto anteriormente, mas foi mitigado ou não exige atenção imediata.'

Se um Achado é marcado como Inativo, isso significa que o problema atualmente não tem impacto no ambiente de software e não precisa ser tratado. Esse status não significa necessariamente que o problema foi resolvido, já que Aceitações de Risco ativas também rotulam os Achados como Inativos.

### **Em Revisão**

'Enviei este Achado para um ou mais membros da equipe analisarem.'

Quando um Achado está Em Revisão, ele precisa ser analisado por um membro da equipe. Você pode colocar um Achado em revisão selecionando **Request Peer Review** no menu suspenso do Achado.

![imagem](images/Finding_Status_Definitions.png)

### **Risco Aceito**

'Nossa equipe avaliou o risco associado a este Achado e concordamos que podemos adiar a correção com segurança.'

Nem sempre é possível corrigir ou tratar os Achados, por vários motivos. Você pode adicionar uma Aceitação de Risco a um Achado usando a opção Add Risk Acceptance. As Aceitações de Risco permitem enviar arquivos e inserir notas para embasar uma decisão de aceitação de risco.

As Aceitações de Risco têm datas de expiração, momento em que você pode reavaliar o impacto do Achado e decidir os próximos passos.

Para mais informações sobre Aceitações de Risco, consulte nosso [Guia](/triage_findings/findings_workflows/os__risk_acceptance/).

### **Fora do Escopo**

'Este Achado foi descoberto por nossa ferramenta de scan, mas detectar esse tipo de vulnerabilidade não era o objetivo direto do nosso teste.'

Ao marcar um Achado como Fora do Escopo, você está indicando que ele não é diretamente relevante para o Engajamento ou Teste em que está contido.

Se você tiver um esforço de teste e correção relacionado a um aspecto específico do seu software, pode usar esse Status para indicar que esse Achado não faz parte do seu esforço.

### **Falso Positivo**

'Este Achado foi descoberto por nossa ferramenta de scan, mas, após revisá-lo, descobrimos que a vulnerabilidade relatada não existe.'

Depois de revisar um Achado, você pode descobrir que a vulnerabilidade relatada não existe de fato. O status Falso Positivo será mantido durante a reimportação e impede que achados correspondentes sejam abertos ou fechados, o que ajuda a reduzir ruído.

Se uma ferramenta de scan diferente encontrar um Achado semelhante, ele não será registrado como Falso Positivo. O DefectDojo só consegue comparar Achados dentro da mesma ferramenta para determinar se um Achado já foi registrado.

## Severidade vs Risco
A Severidade reflete o impacto técnico de um problema caso seja explorado. O Risco reflete a urgência de negócio e a resposta necessária, considerando o contexto, como exposição, explorabilidade, controles compensatórios e impacto operacional.


## Definições de Nível de Risco
### Urgente
Um achado que representa um risco de negócio imediato e inaceitável.

Alta probabilidade de exploração ou exploração ativa observada
Exposição direta de sistemas críticos, dados sensíveis ou ambientes de clientes
Controles compensatórios limitados ou inexistentes
A falha em agir pode resultar em interrupção grave dos negócios, impacto regulatório ou dano à reputação

Ação esperada: Resposta imediata SLA típico: Correção emergencial


### Necessita Ação
Um achado que representa um risco claro e acionável, exigindo correção ou mitigação oportuna.

Existe um caminho de ataque realista
O ativo afetado está exposto, é crítico para o negócio ou voltado ao cliente
Os controles compensatórios são fracos, inexistentes ou não verificados
A exploração resultaria em impacto mensurável para o negócio, a segurança ou a conformidade

Ação esperada: Correção ou mitigação ativa necessária SLA típico: Janela de correção de curto prazo


### Risco Médio
Um achado que apresenta um nível moderado de risco de negócio e deve ser corrigido dentro de um prazo planejado.

Poderia haver impacto relevante se explorado
Existe alguma exposição, mas a exploração exige condições ou privilégios específicos
Pode afetar indiretamente sistemas de produção ou dados de clientes
Frequentemente está alinhado a problemas de severidade média ou alta sem explorabilidade imediata

Ação esperada: Correção priorizada SLA típico: Janela de correção planejada


### Risco Baixo
Um achado que apresenta impacto mínimo para o negócio e não exige ação imediata.

Nenhuma exploração conhecida em ambiente real
Exposição limitada ou inexistente (por exemplo, sistemas internos, não produção, controles compensatórios fortes)
A correção pode ser tratada como parte dos ciclos normais de desenvolvimento ou manutenção
Frequentemente são achados informativos ou de baixa severidade, mas pode incluir problemas de severidade mais alta que estejam bem mitigados

Ação esperada: Acompanhar e tratar de forma oportunista SLA típico: Melhor esforço / backlog
