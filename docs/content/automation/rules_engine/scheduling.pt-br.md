---
title: Agendamento de regras
description: Execute regras do Rules Engine automaticamente em um agendamento recorrente
  ou único
weight: 2
audience: pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Observação: o Agendamento do Rules Engine é um recurso exclusivo do DefectDojo Pro.</span>

As Regras podem ser agendadas para rodar automaticamente, em vez de serem disparadas manualmente todas as vezes. Uma regra agendada será executada contra todos os Findings que correspondam às suas condições de filtro no horário configurado.

O agendamento vem desativado por padrão e é habilitado por instância pelo DefectDojo, em vez de pela página Feature Flags. Entre em contato com o [Suporte DefectDojo](mailto:support@defectdojo.com) para que o **Scheduling Service** seja ativado; a opção **Schedule Rule** aparece assim que ele estiver ativo. Veja [Feature Flags](/admin/feature_flags/pro__feature_flags/) para saber como são exibidos os recursos que o DefectDojo gerencia de forma centralizada.

O usuário que configurar o agendamento precisa ter a permissão de configuração **Change Scheduling Service Schedule**.

## Tipos de agendamento

### Single Run

Um agendamento Single Run executa a regra uma única vez, em uma data e hora específicas. Depois que a execução é concluída, o agendamento não se repete.

### Repeated Run

Um agendamento Repeated Run permite disparar uma regra de forma recorrente — por exemplo, todo dia às 9:00, ou toda segunda-feira às 15:00.

**Observação:** os agendamentos do Rules Engine são limitados a marcas de quinze em quinze minutos. O campo de minuto de um agendamento cron deve ser um dos seguintes: **0, 15, 30 ou 45**. Outros valores de minuto não são permitidos.

Exemplos de agendamentos válidos:
- Toda hora, na hora cheia: `0 * * * *`
- Todo dia às 9:15: `15 9 * * *`
- Toda segunda-feira às 15:00: `0 15 * * 1`
- A cada 15 minutos: `0,15,30,45 * * * *`

## Criando um agendamento para uma Regra

1. Navegue até a página **All Rules** pelo menu **Rules Engine** na barra lateral.
2. Encontre a regra que deseja agendar e abra seu menu de ações (**⋮**).
3. Clique em **Schedule Rule**. Esta opção só fica visível se o Scheduling Service estiver habilitado e você tiver a permissão necessária.
4. No modal **Schedule Rule**, preencha os seguintes campos:

| Campo | Descrição |
|---|---|
| **Name** | Um nome único para este agendamento (obrigatório, máximo de 100 caracteres). |
| **Description** | Descrição opcional da finalidade do agendamento. |
| **Trigger Type** | Escolha **Single Run** para uma execução única, ou **Repeated Run** para um agendamento cron recorrente. |
| **Frequency** | Para Repeated Run: use o construtor de cron para selecionar o período (por hora, diário, semanal etc.) e os valores específicos de minuto, hora e dia. Para Single Run: selecione uma data e hora usando o seletor de data. |
| **Enable Schedule** | Alterna para habilitar ou desabilitar o agendamento. Um agendamento desabilitado não será executado até ser reabilitado. |

5. Clique em **Submit** para salvar o agendamento. A regra será executada automaticamente no próximo horário agendado.


## Permissões

O acesso ao agendamento dentro do Rules Engine requer permissões de Superusuário ou a Permissão de Configuração apropriada. Veja [User Permission Chart](/admin/user_management/user_permission_chart) para mais detalhes.  
