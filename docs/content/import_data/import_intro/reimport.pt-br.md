---
title: Reimportação
description: Aprenda a importar dados manualmente, pela API, ou via um connector
weight: 2
aliases:
- /pt-br/en/connecting_your_tools/import_scan_files/using_reimport
---

Quando um Teste é criado no DefectDojo (seja com antecedência ou pela importação de um arquivo de scan), o Teste pode ser estendido com novos dados de Achados.

Por exemplo, digamos que você tenha um pipeline de CI/CD projetado para enviar um novo relatório ao DefectDojo todos os dias. Em vez de criar um novo Teste ou Engajamento para cada 'execução' do pipeline, você pode fazer com que cada relatório flua para o mesmo Teste usando o **Reimport**.

## Reimport: Resumo do Processo

Reimportar dados não substitui nenhum dado antigo no Teste; em vez disso, compara o arquivo de scan recebido com os dados de scan existentes em um teste para tomar decisões informadas:

* Com base no arquivo mais recente, quais vulnerabilidades ainda estão presentes?
* Quais vulnerabilidades não estão mais presentes?
* Quais vulnerabilidades foram previamente resolvidas, mas foram reintroduzidas desde então?

O Teste rastreará e separará cada versão de scan por meio do **Import History,** para que você possa verificar as mudanças nos Achados do seu Teste ao longo do tempo.

![image](images/using_reimport.png)

## Lógica do Reimport: Criar, Ignorar, Fechar ou Reabrir

Ao usar o Reimport, o DefectDojo compara os dados de scan recebidos com os dados de scan existentes, e então aplica alterações aos Achados contidos no seu Teste da seguinte forma:

### Criar Achados

Quaisquer vulnerabilidades que não estavam contidas na importação anterior serão adicionadas automaticamente ao Teste como novos Achados.

### Ignorar Achados existentes

Se algum Achado recebido corresponder a Achados que já existem, os Achados recebidos serão descartados em vez de registrados como Duplicados. Esses Achados já foram registrados \- não há necessidade de adicionar um novo objeto de Achado. A página do Teste mostrará esses Achados como **Left Untouched**.

### Campos fix_available e fix_version

Se algum Achado recebido corresponder a Achados que já existem, o Achado recebido é verificado para saber se os campos `fix_available` e `fix_version` diferem, sendo atualizados em caso afirmativo. Esses Achados já foram registrados \- não há necessidade de adicionar um novo objeto de Achado. A página do Teste mostrará esses Achados como **Left Untouched**.

### Fechar Achados

Se houver Achados que já existem no Teste mas que não estão presentes no relatório recebido, você pode optar por definir automaticamente esses Achados como Inativos e Mitigados (sob a premissa de que essas vulnerabilidades foram resolvidas desde a importação anterior). A página do Teste mostrará esses Achados como **Closed**.

Se você **não** quiser que nenhum Achado antigo seja fechado, pode desabilitar esse comportamento no Reimport:

* Desmarque a caixa de seleção **Close Old Findings** se estiver usando a UI
* Defina `close_old_findings` como `False` se estiver usando a API (neste endpoint, `close_old_findings` é `True` por padrão)

**Nota sobre escopo:** Diferente do Import, o Reimport nunca pode olhar para outros Testes no Engajamento ao considerar Achados para fechar. O escopo do fechamento de Achados é sempre limitado ao Teste alvo.

O recurso `close_old_findings` também respeitará o campo `service`: apenas Achados com um valor de `service` idêntico (ou sem valor de `service`, caso nenhum tenha sido especificado) serão considerados para fechamento.

### Reabrir Achados

* Se houver Achados Fechados que apareçam novamente em um Reimport, eles serão automaticamente Reabertos. A premissa é que essas vulnerabilidades ocorreram novamente, apesar da mitigação anterior. A página do Teste rastreará esses Achados como **Reactivated**.

Se você estiver usando um scanner sem triagem, ou não quiser que Achados Fechados sejam reativados por qualquer outro motivo, pode desabilitar esse comportamento no Reimport:

* Defina **do_not_reactivate** como **True** se estiver usando a API
* Marque a caixa de seleção **Do Not Reactivate** se estiver usando a UI

### Comportamento do Force Active e Force Verified

Definir `active=true` (UI: **Force Active**) ou `verified=true` (UI: **Force Verified**) em um Reimport definirá o status correspondente em cada Achado correspondente, **incluindo achados que, de outra forma, estariam Inativos por terem sido Mitigados**. Esse é o mesmo comportamento de reativação descrito acima, apenas tornado explícito em cada Achado recebido.

Force Active e Force Verified **não** sobrescrevem status que representam uma decisão explícita de usuário ou sistema sobre por que um Achado não deveria estar Ativo:

| Status | O Force Active reativa? | Por quê |
|---|---|---|
| Mitigado / Fechado | Sim | Igual ao comportamento de reativação padrão |
| Risco aceito | Não | O Achado está Inativo porque um usuário aceitou explicitamente o risco; o reimport não deve revogar silenciosamente essa decisão |
| Duplicado | Não | O Achado está Inativo porque a deduplicação o marcou como duplicado de outro Achado; o Achado original (não o duplicado) é o que deve estar ativo |
| Falso positivo | Não | Mesmo raciocínio do Risco aceito — uma decisão explícita de triagem |
| Fora do escopo | Não | Mesmo raciocínio do Risco aceito — uma decisão explícita de triagem |

Se você quiser que um Achado com Risco aceito ou Duplicado volte a ficar Ativo, é necessário remover primeiro a Aceitação de risco ou o marcador de Duplicado. O Force Active sozinho não faz isso.

## Abrindo o formulário de Reimport

O formulário **Re\-Import Findings** pode ser acessado em qualquer página de Teste, no menu suspenso **⚙️Gear**.

![image](images/using_reimport_2.png) 

O **Formulário** **Re\-import Findings** **não** permitirá que você importe um tipo de scan diferente, ou altere o destino dos Achados que está tentando enviar. Se você estiver tentando fazer uma dessas coisas, precisará usar o **Formulário de Importação de Scan**.

## Trabalhando com o Import History

O Import History de um determinado teste é listado sob o cabeçalho **Test Overview** na página do **Teste**.

Essa tabela mostra cada Import ou Reimport como uma única linha com um **Timestamp**, além das colunas **Branch Tag, Build ID, Commit Hash** e **Version**, se estas tiverem sido especificadas.

![image](images/using_reimport_3.png)

### Ações

Esse cabeçalho indica as ações realizadas por um Import/Reimport.

* **\# created indica o número de novos Achados criados no momento do Import/Reimport**
* **\# closed mostra o número de Achados que foram fechados por um Reimport (por não existirem no relatório recebido).**
* **\# left untouched mostra a contagem de Achados Abertos que não foram alterados por um Reimport (porque também existiam no relatório recebido).**
* **\#** **reactivated** mostra quaisquer Achados Fechados que foram reabertos por um Reimport recebido.

## Deduplicação do Reimport

O Reimport decide se um item recebido corresponde a um Achado existente usando as configurações de **[Reimport Deduplication](/triage_findings/finding_deduplication/about_deduplication/)**. Isso é separado da "Same Tool Deduplication" e da "Cross Tool Deduplication," que operam depois que os Achados já existem.

Se você perceber que o Reimport está fechando Achados antigos e criando novos Achados quando apenas um atributo secundário muda (por exemplo, um deslocamento de número de linha), ajuste o **Reimport Deduplication** para essa ferramenta de modo a usar identificadores estáveis que ignorem esses atributos (como o Unique ID From Tool).

**DefectDojo Pro** pode resolver isso diretamente para ferramentas sem IDs únicos confiáveis: habilitar o **[Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/)** faz com que o Reimport reconheça um Achado cuja localização mudou — um deslocamento de linha, renomeação de arquivo, mudança de URL ou atualização de versão de dependência — como o *mesmo* Achado, atualizando-o no local e preservando seu histórico de localização.

## Reimport via API - nota especial

Observe que o endpoint de API /reimport pode tanto **estender um Teste existente** (aplicando o método deste artigo) **quanto criar um novo Teste** com novos dados \- uma chamada inicial a `/import`, ou a configuração prévia de um Teste, não é necessária.

Para saber mais sobre como criar um pipeline de CI/CD automatizado usando o DefectDojo, veja nosso guia [aqui](/automation/api/api-v2-docs/).
