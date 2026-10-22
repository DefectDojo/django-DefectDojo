---
title: Atribuir Prioridade, Risco e SLAs
description: Como o DefectDojo classifica seus Achados
weight: 1
audience: pro
aliases:
- /pt-br/en/working_with_findings/finding_priority
- /pt-br/en/working_with_findings/priority_adjustments
---

![image](images/pro_finding_priority.png)

Um gerenciamento eficaz de vulnerabilidades baseado em risco requer uma abordagem que considere tanto o contexto de negócio quanto a explorabilidade técnica. Usando o recurso de Prioridade e Risco do DefectDojo Pro, os usuários podem organizar automaticamente os Achados em um contexto significativo, garantindo que as vulnerabilidades de alto impacto sejam tratadas primeiro.

**Prioridade** é uma classificação numérica calculada, aplicada a todos os Achados da sua instância do DefectDojo. Ela permite entender rapidamente as vulnerabilidades em contexto, especialmente em organizações grandes que supervisionam as necessidades de segurança de muitos Achados e/ou Produtos.

**Risco** é um sistema de classificação de 4 níveis que leva em conta a explorabilidade de um Achado em maior grau. Trata-se de uma versão menos granular e mais voltada ao 'nível executivo' da Prioridade.

![image](images/pro_risk_example.png)

Os valores de Prioridade e Risco podem ser usados com outros filtros para comparar Achados em qualquer contexto, como:

* dentro de um único Produto, Engajamento ou Teste
* globalmente em todos os Produtos do DefectDojo
* entre alguns Produtos específicos

Aplicar Prioridade e Risco aos Achados ajuda sua equipe a responder às vulnerabilidades mais relevantes da sua organização, além de fornecer uma estrutura que auxilia na conformidade com padrões regulatórios.


Saiba mais sobre Prioridade e Risco no Office Hours de maio de 2025 da DefectDojo, Inc.:
<iframe width="560" height="315" src="https://www.youtube.com/embed/4SN0BWWsVm4?si=VYUzEGNeijjhoD22" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


## Como a Prioridade e o Risco são calculados
O intervalo de valores de Prioridade vai de 0 a 1150. Quanto maior o número, maior a urgência do Achado para triagem ou remediação.

De forma semelhante à Severidade, o Risco é pontuado de Baixo -> Médio -> Requer Ação -> Urgente.  **Risco** leva em conta os campos de Prioridade e, por isso, pode ser diferente da Severidade reportada por uma ferramenta.

![image](images/priority-overview.png)

## Campos de Prioridade: Nível de Produto

Cada Produto no DefectDojo possui metadados que rastreiam a criticidade de negócio e os fatores de risco. Esses metadados são usados para ajudar a calcular a Prioridade e o Risco de quaisquer Achados associados.

Todos esses campos de metadados podem ser definidos no formulário **Editar Produto** de um determinado Produto.

![image](images/priority_edit_product.png)

* **Criticidade** pode ser definida com qualquer um dos valores Nenhuma, Muito Baixa, Baixa, Média, Alta ou Muito Alta. Criticidade é um campo subjetivo, então, ao atribuí-lo, considere como o Produto se compara a outros Produtos da sua organização.
* **Registros de Usuários** é uma estimativa numérica de registros de usuários em um banco de dados (ou em um sistema que pode acessar esse banco de dados).
* **Receita** é uma estimativa numérica da receita anual do Produto. Para calcular a Prioridade, o DefectDojo calculará uma porcentagem comparando a receita deste Produto com a soma de todos os Produtos dentro do Tipo de Produto.

Não é possível definir um tipo de moeda no DefectDojo, então certifique-se de que todas as suas estimativas de Receita tenham a mesma denominação monetária. ("50000" pode significar 50.000 dólares americanos ou ¥50.000 ienes japoneses - a denominação não importa, desde que todos os seus Produtos tenham a receita calculada na mesma moeda).
* **Público Externo** é um valor verdadeiro/falso - defina como Verdadeiro se este Produto puder ser acessado por um público externo. Por exemplo, clientes, usuários ou qualquer pessoa fora da sua organização.
* **Acessível pela Internet** é um valor verdadeiro/falso. Se este Produto puder se conectar à internet aberta, você deve definir esse valor como Verdadeiro.

A Prioridade é um cálculo "relativo", destinado a comparar diferentes Produtos dentro da sua instância do DefectDojo. No fim das contas, cabe à sua organização decidir como esses filtros são definidos. Esses valores devem ser o mais precisos possível, mas o objetivo principal é destacar seus Produtos-chave para que você possa priorizar vulnerabilidades de acordo com as políticas da sua organização - portanto, esses campos não precisam necessariamente estar definidos com perfeição.

## Campos de Prioridade: Nível de Achado

Os Achados dentro de um Produto podem ter metadados adicionais que ajustam ainda mais o nível de Prioridade e Risco do Achado:

* Se o Achado tem ou não uma **Pontuação EPSS** - isso é adicionado automaticamente aos Achados e mantido atualizado para usuários Pro. A **Pontuação EPSS** é o campo que contribui para a Pontuação de Prioridade — o **Percentil EPSS** é registrado no Achado apenas para referência, mas não alimenta diretamente o cálculo.
* Quantos Endpoints do Produto são afetados por este Achado
* Se um Achado está ou não Em Revisão
* Se o Achado está ou não na base KEV (Known Exploited Vulnerabilities), verificada pelo DefectDojo regularmente
* A Severidade reportada pela ferramenta para um Achado (Informativa, Baixo, Médio, Alto, Crítica)

#### Pontuação EPSS vs. Percentil EPSS

Dois Achados que parecem idênticos nos fatores visíveis (Severidade, Criticidade de Negócio, Acessível pela Internet, Exploit Disponível) ainda podem acabar com Pontuações de Prioridade diferentes se suas **Pontuações EPSS** forem diferentes. Isso é esperado: a Pontuação EPSS é uma entrada contextual do cálculo.

O Percentil EPSS é exibido no Achado para contexto, mas não é utilizado no cálculo da Pontuação de Prioridade. Se você precisar comparar dois Achados para entender uma diferença na Pontuação de Prioridade, observe os valores da Pontuação EPSS, não os valores do Percentil.

O peso exato que a Pontuação EPSS (e os outros fatores) tem no cálculo da Pontuação de Prioridade não é divulgado intencionalmente. Se você precisar influenciar o quanto a Pontuação EPSS afeta a pontuação no seu ambiente, ajuste o controle deslizante de **Explorabilidade** no seu [Mecanismo de Priorização](#prioritization-engines).


## Cálculo de Risco do Achado

![image](images/risk_table.png)

A coluna Risco em uma tabela de Achados é outra forma de priorizar rapidamente os Achados. O Risco é calculado usando o nível de Prioridade de um Achado, mas também leva em conta a explorabilidade do Achado em maior grau. Trata-se de uma versão menos granular e mais voltada ao 'nível executivo' da Prioridade.

Os quatro níveis de Risco atribuíveis são:

![image](images/pro_risk_levels.png)

O EPSS / a explorabilidade de um Achado é muito mais enfatizado no cálculo de Risco. Como resultado, um Achado pode ter tanto uma prioridade alta quanto um valor de risco baixo.

O cálculo de Risco em si atualmente não pode ser ajustado diretamente. No entanto, se a [Inteligência de Ameaças](/asset_modelling/pro_hierarchy/threat_intelligence/) estiver habilitada, o **Piso de Risco de Exploração Ativa** permite controlar o resultado para o caso mais importante: um Achado confirmado como explorado ativamente é elevado a, no mínimo, uma faixa de Risco que você escolher, em vez de permanecer em uma faixa baixa só porque sua severidade base é Baixa. Por padrão, vem definido como **Requer Ação**, e cada Mecanismo de Priorização pode elevá-lo, reduzi-lo ou desativá-lo. Consulte [o Piso de Risco de Exploração Ativa](/asset_modelling/pro_hierarchy/threat_intelligence/#the-actively-exploited-risk-floor).

## Painel de Insights de Prioridade

Os usuários podem ter uma visão de nível executivo da Prioridade e do Risco em seu ambiente usando o Painel de Insights de Prioridade (Metrics > Priority Insights na barra lateral)

![image](images/priority_dashboard.png)

Esse painel pode ser filtrado para incluir Produtos específicos ou intervalos de datas. Como os demais painéis do Pro, este painel pode ser exportado do DefectDojo como PDF para gerar um relatório rapidamente.

## Definindo Prioridade e Risco para Conformidade Regulatória

Esta é uma lista não exaustiva de padrões regulatórios que exigem especificamente métodos de priorização de vulnerabilidades:

* A conformidade com a [SOX (Sarbanes-Oxley Act](https://www.sarbanes-oxley-act.com/)) exige priorização baseada em receita para sistemas que impactam dados financeiros. No DefectDojo, a receita de um sistema pode ser inserida no nível do Produto.
* A conformidade com [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) exige priorização baseada em classificações de risco e criticidade para ambientes de dados de titulares de cartão. A Criticidade de Negócio e o Público Externo podem ser definidos no nível do Produto, enquanto a sincronização de EPSS no nível de Achado do DefectDojo apoia a abordagem baseada em risco do PCI.
* A [NIST SP 800-40](https://csrc.nist.gov/pubs/sp/800/40/r4/final) é um guia de manutenção preventiva que exige especificamente a priorização de vulnerabilidades com base em impacto de negócio, criticidade do produto e fatores de acessibilidade pela internet. Todos esses fatores podem ser definidos no nível de Produto do DefectDojo.
* A conformidade com o Controle A.12.6.1 da [ISO 27001/27002](https://www.iso.org/standard/27001) exige a gestão de vulnerabilidades técnicas com Prioridade baseada em avaliação de risco.
* O [Artigo 32 do GDPR](https://gdpr-info.eu/art-32-gdpr/) exige medidas de segurança baseadas em risco - os registros de usuários e os sinalizadores de público externo no nível do Produto podem ajudar a priorizar sistemas da sua organização que processam dados pessoais.
* A conformidade com [FISMA/FedRAMP](https://help.fedramp.gov/hc/en-us) exige monitoramento contínuo e remediação de vulnerabilidades baseada em risco.

Os cálculos de Prioridade e Risco do DefectDojo Pro podem ser ajustados, permitindo adaptar o DefectDojo Pro aos padrões internos da sua organização para Prioridade e Risco de Achados.

## Mecanismos de Priorização

Assim como as configurações de SLA, os Mecanismos de Priorização permitem definir as regras que determinam como a Prioridade e o Risco são calculados.

![image](images/priority_default.png)

O DefectDojo vem com um Mecanismo de Priorização integrado, aplicado a todos os Produtos. No entanto, você pode editar esse Mecanismo de Priorização para alterar o peso dos multiplicadores de **Achado** e **Produto**, o que ajustará como a Prioridade e o Risco dos Achados são atribuídos.

### Multiplicadores de Achado

Oito fatores contextuais impactam a pontuação de Prioridade de um Achado. Três deles são específicos do Achado, e os outros cinco são atribuídos com base no Produto ao qual o Achado pertence.

Você pode ajustar seu Mecanismo de Priorização controlando como esses fatores são aplicados ao cálculo final.

![image](images/priority_sliders.png)

Selecione um fator clicando no botão; o controle deslizante permite controlar a porcentagem com que um determinado fator é aplicado. Conforme você ajusta o controle deslizante, verá os limiares de Risco mudarem como resultado.

#### Multiplicadores no Nível do Achado

* **Severidade** - o nível de Severidade de um Achado
* **Explorabilidade** - o KEV e/ou a pontuação EPSS de um Achado
* **Endpoints** - a quantidade de Endpoints associados a um Achado

#### Multiplicadores no Nível do Produto

* **Criticidade de Negócio** - a Criticidade de Negócio do Produto relacionado (Nenhuma, Muito Baixa, Baixa, Média, Alta ou Muito Alta)
* **Registros de Usuários** - a contagem de Registros de Usuários do Produto relacionado
* **Receita** - a receita do Produto relacionado, em relação à receita total do Tipo de Produto
* **Público Externo** - se o Produto relacionado tem ou não um público externo
* **Acessível pela Internet** - se o Produto relacionado é ou não acessível pela internet

### Limiares de Risco

Com base no ajuste do Mecanismo de Priorização, o DefectDojo recomendará automaticamente Limiares de Risco. No entanto, esses limiares também podem ser ajustados e definidos com os valores que você considerar apropriados.

![image](images/risk_threshold.png)

## Criando Novos Mecanismos de Priorização

Você pode usar vários Mecanismos de Priorização, cada um podendo ser atribuído a Produtos diferentes.

![image](images/priority_engine_new.png)

Criar um novo Mecanismo de Priorização abrirá o formulário do Mecanismo de Priorização. Depois que esse formulário for enviado, um novo Mecanismo de Priorização será adicionado à tabela.

## Atribuindo Mecanismos de Priorização a Produtos

Cada Produto pode ter um Mecanismo de Priorização em uso, definido no formulário **Editar Produto** de um determinado Produto.

![image](images/priority_chooseengine.png)

Observe que, quando o Mecanismo de Priorização de um Produto é alterado, ou quando um Mecanismo de Priorização é atualizado, o Mecanismo de Priorização do Produto ou o próprio Mecanismo de Priorização ficará "Bloqueado" até que o cálculo de priorização seja concluído.

Cada Produto no DefectDojo pode ter sua própria configuração de Acordo de Nível de Serviço (SLA), que representa os dias que sua organização tem para remediar ou, de alguma forma, gerenciar um Achado.

O SLA pode ser definido com base na **[Severidade do Achado](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** ou no **[Risco do Achado](/asset_modelling/pro_hierarchy/priority_sla/)** (no DefectDojo Pro).

![image](images/sla_multiple.png)

Os SLAs aplicam uma contagem regressiva de dias a um Achado com base no dia em que o Achado foi criado no DefectDojo. Se um Achado não for Fechado dentro da contagem regressiva, ele será rotulado como em violação de SLA.

## Trabalhando com SLAs

Você pode usar os SLAs como uma forma de representar as políticas de remediação da sua organização. Também pode usá-los para priorizar os Achados mais críticos e ativos há mais tempo na sua instância do DefectDojo.

* Você pode ordenar ou filtrar tabelas de Achados por dias de SLA.
* As violações de SLA podem ser configuradas para disparar [Notificações](/admin/notifications/about_notifications/) para os usuários do DefectDojo atribuídos ao Produto relacionado.
* No **DefectDojo Pro**, o desempenho do SLA também é acompanhado nos Painéis de Métricas de [Insights Executivos e Remediação](/metrics_reports/pro_metrics/pro__overview/).
* A conformidade com o SLA também pode ser exibida em um [painel personalizado](/metrics_reports/dashboards/custom-dashboards/) no **DefectDojo Pro** - por exemplo, com um widget de SLA Burndown ou de Contagem filtrada.

### Status Mitigado Dentro do SLA

Se um Achado for Mitigado com sucesso até o prazo do SLA, o Achado registrará uma marca de verificação verde ✅ na coluna Mitigado Dentro do SLA.

![image](images/sla_mitigated_within.png)

Se um Achado foi Mitigado, mas não antes da violação do SLA, o Achado registrará um X vermelho ❌ na coluna Mitigado Dentro do SLA.

### Violação de SLAs

Quando o SLA de um determinado Achado é violado (o Achado não é Fechado dentro do prazo do SLA), a marca de verificação verde ✅ muda para um X vermelho ❌. O SLA continuará sendo acompanhado com um número negativo, representando por quantos dias o SLA foi violado.

![image](images/sla_breached.png)

## Gerenciando Configurações de SLA (Pro)

No DefectDojo Pro, uma ou mais Configurações de SLA são gerenciadas na seção **Configuration > Service Level Agreements** da barra lateral. Você pode criar um **Novo Acordo de Nível de Serviço** ou trabalhar com configurações de SLA existentes na página **Todos os Acordos de Nível de Serviço**.

![image](images/pro_sla_risk.png)

As Configurações de SLA só podem ser editadas por Superusuários ou por um usuário com a [Permissão de Configuração](/admin/user_management/user_permission_chart/#configuration-permission-chart) correspondente.

### Configurando o SLA

As configurações de SLA contêm os dias atribuídos a cada valor de **Severidade** ou **Risco** do DefectDojo.

![image](images/pro_new_sla.png)

Cada Acordo de Nível de Serviço pode ter um nome exclusivo, além de uma descrição opcional.

**Reiniciar SLA na Reativação do Achado**: se habilitada, essa opção reiniciará o SLA do zero quando um Achado for Reaberto. Caso contrário, o SLA será baseado na data em que o Achado foi criado.

Ao editar um SLA, você pode escolher se esse SLA usará **Severidade** ou **Risco** como referência para atribuir os Dias para Remediação. Isso é feito selecionando a opção correspondente na seção **Tipo de Configuração de Nível de Serviço** do formulário.

A partir daí, você pode definir o número de dias permitido para cada nível de **Severidade** ou **Risco**. Você também pode aplicar os SLAs seletivamente; desmarcando a opção **Enforce ___ Finding Days**, você pode ignorar o cálculo de SLA para esses níveis de Severidade ou Risco.

## Aplicar uma Configuração de SLA a um Produto (Pro)

Produtos recém-criados no DefectDojo sempre aplicarão a **Configuração de SLA Padrão**, que pode ser definida com valores diferentes, se desejado.

Se você tiver configurações de SLA, poderá escolher qual delas será aplicada ao seu Produto no formulário **Editar Produto**.

![image](images/pro_sla_product.png)

### Recálculo de SLA

Depois que um novo SLA for selecionado para um Produto, todos os SLAs dos Achados associados precisarão ser recalculados pelo DefectDojo. Enquanto esse processo estiver em execução, o SLA de um Produto não poderá ser alterado.

## Notas sobre SLAs

* Os SLAs podem, opcionalmente, ser reiniciados quando um Achado com [Risco aceito](/triage_findings/findings_workflows/pro__risk_acceptance/) é reativado. Isso é definido ao criar a Aceitação de risco, configurando o campo **Reiniciar SLA Expirado**.
* Reimportar um Achado não reinicia o SLA - os SLAs são sempre calculados a partir do momento em que um Achado foi detectado pela primeira vez, a menos que a opção **Reiniciar SLA na Reativação do Achado** esteja habilitada.
* A expiração da Aceitação de risco ou a reativação de um Achado Fechado são as únicas formas de redefinir ou recalcular um SLA de um Achado depois de criado (sem alterar a configuração de SLA do Produto).
