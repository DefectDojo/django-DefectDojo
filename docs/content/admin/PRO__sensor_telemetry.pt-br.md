---
title: "Compartilhamento de telemetria de sensores"
description: "Opte por compartilhar com a DefectDojo eventos anonimizados de detecções de sensores e veja o que seus sensores contribuíram"
weight: 11
audience: pro
draft: false
---

> **Ainda não disponível:** o Compartilhamento de telemetria de sensores ainda não pode ser ativado, nem no DefectDojo Cloud nem em uma instância self-hosted, qualquer que seja a configuração. Esta página descreve como ele vai funcionar depois de lançado.

O Compartilhamento de telemetria de sensores permite que uma instância envie **eventos de detecção de sensores** anonimizados ao serviço de inteligência de ameaças da DefectDojo. Uma detecção é um único disparo de um sensor nos seus hosts que está vinculado a um CVE. As detecções compartilhadas mostram ao serviço de inteligência quais vulnerabilidades estão sendo exploradas em ambiente real, e essa evidência chega a todas as instâncias pelo feed de Inteligência de Ameaças.

O compartilhamento é um recurso do **DefectDojo Pro**. Ele fica **desativado por padrão**, e nada é enviado até que um superusuário o ative.

## O que é compartilhado e o que não é

Cada evento contém quatro valores e nada mais:

| Campo | O que é |
| --- | --- |
| CVE | O CVE com que está marcada a regra de detecção que correspondeu |
| Hora | A hora em que a detecção foi vista, em UTC. Minutos e segundos não são enviados |
| Origem | No máximo o país e a rede (ASN) de onde veio a detecção. Muitas vezes vazio |
| ID de contribuidor | Um identificador aleatório que muda a cada mês do calendário |

Um evento nunca contém um payload ou corpo de requisição, um nome de host, um endereço IP, um nome de usuário, uma linha de comando, um nome de ativo, um nome de empresa, o nome ou o identificador da regra de detecção, nem o nome ou a URL da sua instância. A origem só é preenchida quando a sua instância está configurada para consultá-la, e apenas para um endereço público. Nesse caso, a DefectDojo determina o país e a rede na sua instância e descarta o endereço ali mesmo, antes de enviar qualquer coisa.

Os identificadores de regras são omitidos de propósito: uma regra escrita por você pode ter qualquer nome, inclusive o da sua empresa, de um host ou de uma pessoa.

Os eventos são entregues à DefectDojo com a chave de licença da sua instância, que é como o serviço de inteligência os aceita. A chave acompanha a entrega, e não fica dentro dos eventos.

O ID de contribuidor permite que o serviço de inteligência conte quantas instâncias diferentes viram um CVE dentro de um mês. Ele é sorteado aleatoriamente, substituído por um novo a cada mês, e o antigo não pode ser deduzido a partir do novo.

Só são enviadas as detecções posteriores à ativação do compartilhamento e das últimas 24 horas. Desativar o compartilhamento exclui todos os eventos que ainda aguardavam envio e descarta o ID de contribuidor, e o mesmo acontece com uma mudança da cláusula contratual. Ativar o compartilhamento de novo começa com um novo ID de contribuidor.

## Antes de poder ativá-lo

O compartilhamento é coberto por uma cláusula do seu contrato com a DefectDojo. O card informa a **versão da cláusula contratual** que você aceita ao ativar o compartilhamento, e ele não pode ser ativado até que essa versão esteja disponível na sua instância.

A cláusula contratual será publicada antes que o compartilhamento fique disponível.

Se a DefectDojo publicar mais tarde uma nova versão da cláusula, o compartilhamento é pausado automaticamente. O card avisa, os eventos que aguardavam sob a versão anterior são excluídos, e nada é enviado até que um superusuário ative o compartilhamento de novo sob a nova versão. Enquanto o compartilhamento está pausado, a caixa de seleção aparece desmarcada, então a nova versão só é aceita ao marcá-la novamente. O compartilhamento então recomeça do zero, com um novo ID de contribuidor.

O compartilhamento nunca está disponível em uma instância air-gapped, na demo pública ou no sandbox.

## Ativar ou desativar o compartilhamento

1. Entre como superusuário e abra **Settings > System Settings**.
2. Role até o card **Sensor Telemetry**, no fim da página.
3. Leia o que é compartilhado e a versão da cláusula contratual que o card informa. Quando a sua instância tem o endereço da cláusula, o card mostra um link para ela ao lado da versão (**Read the contract term**).
4. Marque **Share Sensor Hit Events** e selecione **Submit**. Para parar, desmarque a caixa de seleção e selecione **Submit**.

Toda alteração é registrada no log de auditoria com o usuário que a fez.

## O que o card mostra

* **Sharing**: Off, On, Paused (a cláusula contratual mudou), On, Not Sending (não há endpoint de inteligência ou chave de licença configurados; o card diz qual falta) ou Not Available.
* **Events Shared**, **Events Waiting** e **Events Dropped**: quantos eventos foram entregues, estão na fila ou foram descartados. Um evento que não pode ser entregue é tentado novamente por até um dia e depois descartado.
* **Last Shared**: quando eventos foram entregues pela última vez.
* **A lista de CVEs**: os CVEs que seus sensores observaram, até os 200 vistos mais recentemente, com o número de detecções, quantas foram compartilhadas e quando cada um foi visto pela primeira e pela última vez. O título do card mostra quantos CVEs foram observados no total. Essa lista é mantida na sua instância, com o compartilhamento ativado ou não.
* **Seen Elsewhere**: se outras instâncias que compartilham viram o mesmo CVE. Só é preenchido enquanto o compartilhamento está ativado e o serviço de inteligência responde, e apenas para os CVEs que a sua instância já compartilhou: a consulta nomeia o CVE, então um CVE visto apenas antes da ativação do compartilhamento nunca é consultado. Caso contrário, a linha abaixo da tabela explica por que está vazio, por exemplo, que não há endpoint de inteligência ou chave de licença configurados na instância.

O card aparece quando a sua instância tem sensores, observou um CVE ou foi configurada para compartilhamento.

## Configuração self-hosted

Em uma instância self-hosted, o operador define estas variáveis de ambiente. Todas ficam vazias por padrão, e vazio significa desativado.

| Variável | Finalidade |
| --- | --- |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_VERSION` | A versão da cláusula contratual. Sem ela, o compartilhamento não pode ser ativado |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_URL` | Opcional. O endereço HTTPS onde a cláusula contratual pode ser lida. O card mostra um link para ele ao lado da versão |
| `DD_SENSOR_TELEMETRY_ENDPOINT` | A URL base HTTPS do serviço de inteligência. Sem ela, nenhuma chamada de rede é feita |
| `DD_THREAT_INTEL_LICENSE_KEY` | A chave de licença enviada com cada entrega. Sem ela, nenhuma chamada de rede é feita |
| `DD_SENSOR_TELEMETRY_SOURCE_RESOLVER` | Opcional. O caminho Python com pontos de uma função que converte um endereço de origem público em um país e um ASN. A DefectDojo não inclui nenhum banco de dados de países ou de ASN, então sem ela os eventos não trazem origem |
