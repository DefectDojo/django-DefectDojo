---
title: Sobre Notificações e 🔔 Alertas
description: Saiba mais sobre notificações e alertas no aplicativo
aliases:
- /pt-br/en/customize_dojo/notifications/about_notifications
---

DefectDojo mantém você atualizado de diversas formas. Notificações podem ser enviadas para Engajamentos futuros, [Menções a usuários](/triage_findings/findings_workflows/intro_to_findings/#notes-and-mentions), expiração de SLA e outros eventos no sistema.

Este artigo apresenta uma visão geral das notificações, tanto no nível de Sistema quanto no nível Pessoal.

## Tipos de Notificação

O DefectDojo trata as notificações de duas formas diferentes::

* **Notificações do Sistema** são enviadas a todos os usuários.
* **As Notificações Pessoais são definidas por usuários individuais e são recebidas além de quaisquer Notificações do Sistema.**

Em ambos os casos, as regras de [Controle de Acesso Baseado em Função](../../user_management/about_perms_and_roles/) se aplicam, portanto os usuários não receberão notificações de atividade de Produtos ou Tipos de Produto (ou seus objetos relacionados) aos quais não têm acesso.

## Métodos de Entrega de Notificação

Existem quatro métodos de entrega para as notificações do DefectDojo:

* O DefectDojo pode compartilhar **🔔 Alertas,** armazenados como uma lista na interface do DefectDojo
* O DefectDojo pode enviar notificações para um endereço de **E-mail**
* O DefectDojo pode enviar notificações para o **Slack,** em um canal compartilhado ou individual
* O DefectDojo também pode enviar notificações para o **Microsoft Teams** em um canal compartilhado

As notificações podem ser enviadas para vários destinos simultaneamente.

Para receber notificações do Slack e do Teams, é necessário ter uma integração funcionando. Para mais informações sobre como configurar essa integração, consulte nosso [Guia](../email_slack_teams).

## Alertas no Aplicativo

O sistema de Alertas do DefectDojo mantém você atualizado sobre toda a atividade de Produto ou do sistema.

### A Lista de Alertas

A Lista de Alertas fica sempre visível no canto superior direito do DefectDojo e contém uma lista compacta de notificações. Clicar em cada Alerta o levará diretamente à página relevante no DefectDojo.

Você pode abrir sua Lista de Alertas clicando no **ícone 🔔▼** no canto superior direito:

![image](images/About_In-App_Alerts.png)

Para ver todas as suas notificações, com detalhes adicionais, você pode clicar no botão **See All Alerts \>**, que abrirá a **Alerts Page**.

Você também pode **Clear All Alerts \>** a partir da Lista de Alertas.

### A Página de Alertas

A Página de Alertas armazena todos os seus Alertas no DefectDojo com detalhes adicionais. Nesta página, você pode ler as descrições de cada Alerta no DefectDojo e removê-los da fila de Alertas quando não precisar mais deles.

![image](images/About_In-App_Alerts_2.png)

Para remover um ou mais Alertas da Página de Alertas, marque a caixa vazia ao lado dele e clique no botão **Remove selected** no canto inferior direito da Página.

### Observações Sobre Alertas

* Ler um Alerta, ou abrir a Página de Alertas, não removerá nenhum Alerta da contagem ao lado do ícone de sino. Isso permite que você acesse facilmente alertas anteriores para usá-los como lembretes ou como um registro de atividade pessoal.
* Usar a função **Clear All Alerts \>** no Menu de Alertas também limpará completamente a **Alerts Page**, portanto use esse recurso com cuidado.
* Remover um Alerta afeta apenas a sua própria Lista de Alertas \- isso não afetará os Alertas de nenhum outro usuário.
* Remover um Alerta não remove nenhum histórico de importação ou registro de atividade do DefectDojo.

## Restringindo Notificações de Solicitação de Revisão (Pro)

Se uma revisão for solicitada a todos os revisores elegíveis, todos os elegíveis para esse ativo são notificados. Isso representa muito e-mail para um revisor que cuida apenas de parte do seu ambiente.

Na interface do DefectDojo Pro, você pode restringir suas próprias notificações de solicitação de revisão. Na sua página de configurações de notificação, em **Review Requests**:

* **Review Request Scope** — *All* (o padrão) notifica você sobre tudo o que você pode visualizar. *Selected* restringe você aos ativos e tipos de ativo que você escolher.
* **Review Request Assets** / **Review Request Asset Types** — a parte do ambiente sobre a qual você quer ser avisado. Uma solicitação corresponde se estiver em um dos seus ativos selecionados *ou* em um dos seus tipos de ativo selecionados.

Duas coisas devem ficar claras:

* Escolher *Selected* e não selecionar nada significa **nenhum**, não todos.
* Restringir suprime a notificação, **não a solicitação**. Você continua sendo um revisor solicitado, e a solicitação ainda aparece na sua fila [My Work](/metrics_reports/dashboards/pro__my_work/), em **Awaiting My Review** — você simplesmente não é avisado por mensagem. Isso é proposital: a fila é o registro duradouro, as notificações são apenas o lembrete.

Essa restrição também tem precedência sobre a substituição em nível de sistema descrita abaixo, portanto um revisor que se excluiu do escopo não é notificado mesmo quando `review_requested` está configurado para prevalecer sobre as preferências pessoais.

A restrição também pode ser definida pela API, no endpoint de notificações, o que é a forma mais prática se você estiver configurando muitos revisores de uma vez.

## Notificações de Atribuição de Trabalho (Pro)

Quando Achados são atribuídos a você, a notificação **Work Assigned** informa quantos foram atribuídos e traz um link para sua fila My Work.

Ela é agregada por pessoa, e não por Achado: atribuir cem Achados envia uma única mensagem, não cem. Assim como nas solicitações de revisão, a atribuição fica visível na sua fila independentemente de a notificação chegar até você.

## Considerações sobre Código Aberto

### Substituições específicas

As configurações de notificação do sistema (scope: system) descrevem o envio de notificações a superadmins. As configurações de notificação do usuário (scope: personal) descrevem o envio de notificações ao usuário específico.

No entanto, há um caso de uso específico em que o usuário decide desativar as notificações (para reduzir o ruído), mas a configuração do sistema é usada para substituir esse comportamento. Por padrão, essas substituições se aplicam apenas a `user_mentioned` e `review_requested`.

O escopo dessa configuração é personalizável (veja a variável de ambiente `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP`).

Para mais informações sobre esse comportamento, consulte o [pull request relacionado #9699](https://github.com/DefectDojo/django-DefectDojo/pull/9699/)

### Webhooks (experimental)

O DefectDojo também suporta webhooks que seguem os mesmos eventos que as demais notificações (você pode ser notificado nas mesmas situações). Detalhes sobre a configuração são descritos na [página relacionada](/automation/api/notification_webhooks/).
