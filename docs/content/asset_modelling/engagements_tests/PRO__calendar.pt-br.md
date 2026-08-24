---
title: Calendário
description: Como usar o Calendário no DefectDojo Pro
audience: pro
weight: 9
---

O DefectDojo conta com um Calendário integrado para que você possa acompanhar todos os Engajamentos e Testes anteriores e ativos em sua organização. Sempre que um Usuário cria um novo Engajamento ou Teste e define as datas de início e término, uma entrada correspondente é adicionada automaticamente ao Calendário. 

### Página Inicial 

A página do Calendário inclui filtros na parte superior e um calendário mensal abaixo. Os filtros podem ajustar quais resultados aparecem no calendário com base em:
- Engajamento e/ou Teste 
- Data de início e término 
- Status do Engajamento (por exemplo, Concluído, Em andamento, Em espera, etc.) 
- Responsável pelo Engajamento/Teste (ou seja, a quem o Engajamento/Teste está atribuído?) 
- Tipo de Engajamento (por exemplo, Interativo ou CI/CD)
- Tipo de Teste (por exemplo, Pen Test, Acunetix Scan, Tenable Scan, etc.) 

![image](images/calendar1.png)
 
Depois de filtrados, os resultados podem ser exportados e compartilhados como um arquivo ICS. 

É importante notar que o Calendário exibirá apenas os Engajamentos e Testes aos quais o Usuário que está visualizando o calendário tem acesso. Ele não exibirá Engajamentos e Testes que o Usuário não tem permissão para visualizar. 

## Recursos 

### Visualização Mensal

O calendário mensal exibe uma prévia de cinco entradas por dia. Entradas adicionais que ocorram naquele dia ficarão ocultas, a menos que **"+ [X] events"** seja clicado dentro da célula de uma determinada data. Uma vez clicado, o calendário mudará da visualização mensal para a visualização diária.

Clicar em uma entrada de Teste ou Engajamento abrirá uma janela modal com informações adicionais sobre essa entrada, incluindo: 
- Data de início e término 
- Tipo de Teste ou Engajamento 
- Responsável 
- Status 
- Asset 
- Engajamento 
- Teste 

A partir daí, o Asset, Engajamento ou Teste pode ser acessado por meio de um hyperlink.

### Visualização Diária 

Na visualização diária, todos os Engajamentos e Testes atualmente ativos aparecem em ordem cronológica decrescente (ou seja, um Engajamento ou Teste recém-criado aparecerá na parte inferior das entradas daquele dia). Os Engajamentos aparecem em azul, enquanto os Testes aparecem em laranja.

Se definido dentro do Engajamento/Teste aplicável, o título de cada entrada no calendário diário incluirá o seguinte:
- Status 
- Produto
- Engajamento
- Teste
- Responsável 

#### Setas

As setas nos lados esquerdo e direito de cada entrada indicam se aquele Teste ou Engajamento específico está presente no dia anterior e/ou no dia seguinte. 

Por exemplo, um Teste criado no mesmo dia em que está sendo visualizado não terá setas à esquerda, pois esse Teste não existia no dia anterior. Por outro lado, um Teste que termina no mesmo dia em que está sendo visualizado não terá setas à direita, pois a entrada não existirá no dia seguinte.

Por exemplo, como o último Engajamento na captura de tela abaixo (**In Progress** Example Product A ▶ **Sample Engagement** (Unassigned)) está sendo visualizado no dia em que foi criado, e a Data de Término Alvo foi definida para o dia seguinte, não há setas presentes em nenhum dos lados.

![image](images/calendar2.png)
