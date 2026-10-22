---
title: Configuração de SLA
description: Configure Acordos de Nível de Serviço para diferentes Produtos
weight: 2
audience: opensource
aliases:
- /pt-br/en/working_with_findings/sla_configuration
---

Cada Produto no DefectDojo pode ter sua própria configuração de Acordo de Nível de Serviço (SLA), que representa os dias que sua organização tem para remediar ou, de outra forma, gerenciar um Achado.

O SLA pode ser definido com base na **[Severidade do Achado](/asset_modelling/os_hierarchy/product_hierarchy/#findings)** ou no **[Risco do Achado](/asset_modelling/pro_hierarchy/priority_sla/)** (no DefectDojo Pro).

![image](images/sla_multiple.png)

Os SLAs aplicam uma contagem regressiva de dias a um Achado com base no dia em que o Achado foi criado no DefectDojo.  Se um Achado não for Fechado dentro da contagem regressiva, ele será rotulado como em violação do SLA.

## Trabalhando com SLAs

Você pode usar os SLAs como uma forma de representar as políticas de remediação da sua organização.  Você também pode usá-los como uma forma de priorizar os Achados mais críticos e ativos há mais tempo na sua instância do DefectDojo.

* Você pode ordenar ou filtrar tabelas de Achados por dias de SLA.
* As violações de SLA podem ser configuradas para disparar [Notificações](/admin/notifications/about_notifications/) para usuários do DefectDojo atribuídos ao Produto relacionado.
* No **DefectDojo Pro**, o desempenho do SLA também é acompanhado nos Painéis de Métricas de [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/).
* A conformidade com o SLA também pode ser exibida em um [painel](/metrics_reports/dashboards/custom-dashboards/) personalizado no **DefectDojo Pro** — por exemplo, com um SLA Burndown ou um widget de Contagem filtrado.

### O status Mitigated Within SLA

Se um Achado for Mitigado com sucesso até o prazo do SLA, ele registrará uma marca de verificação verde ✅ na coluna Mitigated Within SLA.

![image](images/sla_mitigated_within.png)

Se um Achado foi Mitigado, mas não antes de o SLA ser violado, ele registrará um X vermelho ❌ na coluna Mitigated Within SLA.

### Violação de SLAs

Quando o SLA de um determinado Achado é violado (o Achado não é Fechado dentro do prazo do SLA) a marca de verificação verde ✅ muda para um X vermelho ❌.  O SLA continuará sendo acompanhado com um número negativo, para representar há quantos dias o SLA foi violado.

![image](images/sla_breached.png)

## Gerenciando Configurações de SLA (Pro)

No DefectDojo Pro, uma ou mais Configurações de SLA são gerenciadas na seção **Configuration > Service Level Agreements** da barra lateral.  Você pode criar um **New Service Level Agreement** ou trabalhar com configurações de SLA existentes na página **All Service Level Agreements**.

![image](images/pro_sla_risk.png)

As Configurações de SLA só podem ser editadas por Superusuários ou por um usuário com a [Permissão de Configuração](/admin/user_management/user_permission_chart/#configuration-permission-chart) correspondente.

### Configurando o SLA

As configurações de SLA contêm os dias atribuídos a cada valor de **Severidade** ou **Risco** do DefectDojo.

![image](images/pro_new_sla.png)

Cada Acordo de Nível de Serviço pode ter um nome único, junto com uma descrição opcional.

**Restart SLA on Finding Reactivation**: se habilitada, essa opção reiniciará o SLA quando um Achado for Reaberto.  Caso contrário, o SLA será baseado em quando o Achado foi criado.

Ao editar um SLA, você pode escolher se esse SLA usará **Severidade** ou **Risco** como referência para atribuir os Days To Remediate.  Isso é feito selecionando a opção correspondente na seção **Service Level configuration Type** do formulário.

A partir daqui, você pode definir o número de dias permitido para cada nível de **Severidade** ou **Risco**.  Você também pode aplicar os SLAs seletivamente; desmarcando **Enforce ___ Finding Days**, você pode ignorar o cálculo do SLA para esses níveis de Severidade ou Risco.

## Aplicar uma Configuração de SLA a um Produto (Pro)

Produtos recém-criados no DefectDojo sempre aplicarão a **Default SLA Configuration**, que pode ser definida com valores diferentes, se desejado.

Se você tiver configurações de SLA, pode escolher qual delas será aplicada ao seu Produto no formulário **Edit Product**.

![image](images/pro_sla_product.png)

### Recálculo de SLA

Depois que um novo SLA for selecionado para um Produto, os SLAs de todos os Achados associados precisarão ser recalculados pelo DefectDojo.  Enquanto esse processo estiver em execução, o SLA do Produto não pode ser alterado.

## Observações sobre SLAs

* Os SLAs podem, opcionalmente, ser reiniciados quando um Achado com [Risco aceito](/triage_findings/findings_workflows/os__risk_acceptance/) é reativado.  Isso é definido ao criar a Aceitação de Risco, configurando o campo **Restart SLA Expired**.
* Reimportar um Achado não reinicia o SLA - os SLAs são sempre calculados a partir do momento em que um Achado foi detectado pela primeira vez, a menos que **Restart SLA on Finding Reactivation** esteja habilitado.
* A expiração da Aceitação de Risco ou a reativação de um Achado Fechado são as únicas formas de redefinir ou recalcular um SLA para um Achado depois de criado (sem alterar a configuração de SLA do Produto).
