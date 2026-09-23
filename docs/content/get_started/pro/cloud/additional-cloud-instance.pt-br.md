---
title: Configure uma instância Cloud adicional
description: Adicione uma instância de teste, desenvolvimento ou outra instância do
  DefectDojo à sua conta
weight: 3
audience: pro
aliases:
- /pt-br/en/cloud_management/additional-cloud-instance
---

O processo para adicionar uma segunda instância Cloud é basicamente o mesmo processo de adicionar sua primeira instância. Este guia pressupõe que você já configurou seu servidor DefectDojo inicial e tem um acordo com nossa equipe de Vendas para adicionar outra instância.

Se você ainda não solicitou uma instância Cloud adicional, entre em contato com [info@defectdojo.com](mailto:info@defectdojo.com) antes de prosseguir.

## Etapa 1: Abra o processo de Nova Assinatura

Você pode iniciar esse processo a partir do seguinte link: <https://cloud.defectdojo.com/accounts/onboarding/step_1>, ou clicando em 🛒 **New Subscription** na página do Cloud Manager (cloud.defectdojo.com).

![imagem](images/request_a_trial.png)

## Etapa 2: Defina seu Server Label

Insira o **Nome** da sua empresa e o **Server Label** que você deseja usar com o DefectDojo. Em seguida, será criado um domínio personalizado para a sua instância do DefectDojo em nossos servidores.

Mantenha o nome da sua empresa como estava antes, mas crie um novo Server Label e marque o botão "**Use Server Label in Domain**", para que você consiga diferenciar facilmente entre seus servidores.

![imagem](images/request_a_trial_2.png)

## Etapa 3: Selecione uma Localização de Servidor

Selecione uma Localização de Servidor no menu suspenso. Como antes, recomendamos selecionar um servidor que fique geograficamente mais próximo dos seus usuários para reduzir a latência do servidor.

![imagem](images/request_a_trial_3.png)

## Etapa 4: Configure suas Regras de Firewall

Insira os intervalos de endereços IP, a máscara de sub-rede e os rótulos que você deseja permitir para acessar o DefectDojo. Endereços IP e regras adicionais podem ser adicionados ou alterados pela sua equipe depois que sua instância estiver em operação.

Se desejar, essas regras de firewall podem ser diferentes das regras da sua instância principal do DefectDojo.

![imagem](images/request_a_trial_4.png)

Se você quiser usar serviços externos com esta instância (GitHub ou JIRA), marque as caixas apropriadas listadas em **Select External Services.**

Você também pode prosseguir sem um firewall selecionando **Proceed Without Firewall**.  Seu firewall pode ser reativado mais tarde.

## Etapa 5: Confirme o tipo de Plano e a Frequência de Cobrança

Ao final do nosso processo, você será colocado em contato com nossa equipe de vendas, que poderá cotar sua nova instância com precisão. Recomendamos que você selecione o Tipo de Plano que tenha as especificações de servidor necessárias para a nova instância.

![imagem](images/request_a_trial_5.png)

Uma segunda instância pode não exigir os mesmos requisitos de armazenamento, CPU e RAM que sua instância 'principal', mas isso dependerá dos requisitos técnicos da sua equipe.

## Etapa 6: Revise e Envie sua Solicitação

Vamos pedir que você revise sua solicitação mais uma vez. Depois de enviada, apenas as regras de Firewall podem ser alteradas pela sua equipe sem a assistência do Suporte.

![imagem](images/request_a_trial_6.png)

Depois de revisar e aceitar o Contrato de Licença e Suporte do DefectDojo, você pode prosseguir para **Checkout With Stripe**, ou, se já tiver um acordo de cobrança existente, pode clicar em **Contact Sales**.

Nossa equipe de Suporte entrará em contato com você com as credenciais de login assim que sua instância for aprovada e provisionada.
