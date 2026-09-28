---
title: Logs de Auditoria
description: Acesse os logs de auditoria de objetos do DefectDojo
weight: 1
audience: pro
---

**Logs de Auditoria** fornecem um registro cronológico das ações realizadas no DefectDojo. Eles garantem responsabilização e conformidade ao registrar qual usuário realizou qual ação e quando.

Os logs de auditoria são valiosos para:
- **Investigações de segurança**: Determinar quem realizou ações sensíveis.
- **Conformidade**: Demonstrar um histórico auditável para padrões como SOC 2, ISO 27001, ou requisitos internos de governança.
- **Solução de problemas**: Identificar quando uma configuração ou objeto foi alterado.
- **Responsabilização**: Rastrear a atividade administrativa e de usuários em toda a plataforma.

Em resumo, os Logs de Auditoria fornecem um registro centralizado de eventos importantes que ajuda os administradores a entender o histórico de atividades de sua instância além do histórico de qualquer objeto individual. 

### Acessando os Logs de Auditoria

Os Logs de Auditoria são acessíveis pela barra lateral, dentro do submenu Configurations. 

![image](images/auditlogs_ss2.png)

### Permissões 

O acesso aos Logs de Auditoria é determinado pela função global de um Usuário.

As funções globais de API Importer, Reader e Writer não permitem acesso aos Logs de Auditoria, enquanto as funções Maintainer e Owner permitem. Superusuários também têm acesso aos Logs de Auditoria independentemente de sua função global. 

Mais informações sobre permissões e funções globais podem ser encontradas [aqui](/admin/user_management/pro_permissions_overhaul/).

## Conteúdo dos Logs de Auditoria 

Os Logs de Auditoria rastreiam uma variedade de ações, incluindo, mas não se limitando a:
- Interações com objetos (por exemplo, criar, atualizar ou excluir objetos).
- Atualizações na prioridade e no risk score de um Achado.
- Criação e edição de perfis de Usuário.
- Atualizações de percentil EPSS. 

A lista completa de alterações e ações capturadas nos Logs de Auditoria pode ser encontrada [aqui](../pro__audit_log_index/).

## Tabela de Logs de Auditoria 

Os Logs de Auditoria incluem várias colunas com diferentes dados para melhorar a rastreabilidade, incluindo:
- **Timestamp**: O momento em que a alteração ocorreu.
- **User**: O usuário que realizou a ação.
- **Action**: Qual ação foi realizada (por exemplo, criar, atualizar, excluir). 
- **Model**: Qual aspecto foi modificado (por exemplo, Asset, User, Finding, Location, Firewall, URL, etc.). 
- **Object ID**: O ID exclusivo do DefectDojo para o objeto que foi modificado. 
- **Object Name**: O nome do objeto afetado. 
- **Changes**: Campos específicos modificados pela ação, incluindo seus valores anteriores e atualizados.
- **Data**: Um snapshot exato do registro no momento em que a ação foi realizada, incluindo todos os campos, não apenas os que foram alterados. 
- **Context**: Detalhes sobre como a alteração aconteceu, quem a fez, de onde no aplicativo ela veio, e um rótulo indicando qual job realizou a alteração (se foi um job automatizado). 
- **URL**: A URL usada para executar a operação em questão. Esses caminhos podem se referir à Vue UI do DefectDojo, ou à API REST. O campo URL não será preenchido para processos de back-end. 
- **IP Address**: O endereço de rede do dispositivo que fez a alteração. Isso não será preenchido para processos de back-end.

### Linha do Tempo dos Logs de Auditoria

Por padrão, os Logs de Auditoria exibem entradas dos últimos 31 dias. Entradas mais antigas permanecem disponíveis e podem ser visualizadas ajustando o filtro Timestamp. 

![image](images/auditlogs_ss3.gif)

### Filtrando os Logs de Auditoria

A tabela de Logs de Auditoria inclui filtros para ajudar a restringir os resultados exibidos. Por exemplo, se você quisesse ver apenas ações referentes a Assets, poderia filtrar por Assets dentro da tabela. 

![image](images/auditlogs_ss1.png)

As colunas dentro dos Logs de Auditoria também podem ser organizadas em ordem alfabética, crescente/decrescente, ou cronológica, dependendo do conteúdo da coluna em questão. As colunas também podem ser arrastadas para a esquerda ou para a direita, conforme o arranjo preferido.

![image](images/auditlogs_ss4.gif)

## Histórico do Objeto 

O **Histórico do Objeto** fornece um registro cronológico das alterações feitas em um objeto individual do DefectDojo (por exemplo, Organization, Asset, Engagement, Test, Findings, Endpoints e Risk Acceptances). Cada entrada inclui detalhes como o timestamp, o usuário, a ação realizada e as alterações associadas.

Diferente dos Logs de Auditoria, que registram eventos em toda a instância, o Histórico do Objeto diz respeito estritamente à atividade de um único objeto, facilitando o entendimento do histórico de um objeto sem precisar filtrar eventos de sistema não relacionados.

O Histórico do Objeto é útil para:
- Revisar a progressão de um objeto ao longo do tempo.
- Determinar quando uma alteração foi feita.
- Identificar qual usuário fez uma modificação.
- Solucionar alterações inesperadas.

### Acessando o Histórico do Objeto 

O Histórico do Objeto pode ser acessado pelo menu de engrenagem no canto superior direito da visualização de qualquer objeto. Somente Usuários com acesso ao objeto em questão podem visualizar o Histórico do Objeto correspondente. 

### Logs de Auditoria e Histórico do Objeto 

Embora a função dos Logs de Auditoria e do Histórico do Objeto se sobreponha, eles operam em escopos diferentes. O Histórico do Objeto foca nas alterações feitas em objetos individuais, enquanto os Logs de Auditoria fornecem um registro de eventos significativos em toda a sua instância do DefectDojo, oferecendo uma visão mais ampla, de "visão de pássaro", da atividade.

## Endpoints 

### Endpoint de Histórico do Objeto (Somente Pro)

Usuários do <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> têm acesso a um caminho de API `/history` para esses objetos, a fim de visualizar dados semelhantes.  Por exemplo: `/api/v2/findings/{id}/history/`.

### Endpoint de Log de Auditoria (Somente Pro)

Usuários do <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> também têm acesso a um endpoint dedicado `/audit_log` para toda a sua instância.  Este log só pode ser acessado por usuários ou tokens de API com permissões de superusuário.

Esta API retorna 31 dias de logs de auditoria.

* Enviar parâmetros padrão ou vazios retornará os últimos 31 dias de logs de auditoria.

* O parâmetro `window_month` recebe um mês e ano no formato MM-YYYY e fornece os logs de auditoria daquele mês.
* Você pode definir o parâmetro `window_start` para limitar esses logs a uma janela mais curta, em vez de retornar o mês inteiro.

Para mais informações, consulte a documentação da API, localizada em sua instância: `your-instance.cloud.defectdojo.com/api/v2/oa3/swagger-ui/`
