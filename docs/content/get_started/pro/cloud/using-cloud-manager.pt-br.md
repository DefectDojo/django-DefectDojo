---
title: Usando o Cloud Manager
description: Gerencie sua assinatura e as configurações da sua conta
weight: 1
collapsed: true
audience: pro
aliases:
- /pt-br/en/cloud_management/using-cloud-manager
---

Fazer login no Cloud Manager do DefectDojo permite configurar as definições da sua conta e gerenciar sua assinatura do DefectDojo Cloud.

## **New Subscription**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

Esta página permite solicitar uma nova instância do Cloud do DefectDojo, [ou uma adicional](../additional-cloud-instance/).

## **Manage Subscriptions**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

A página de Gerenciamento de Assinaturas mostra todas as suas instâncias do Cloud atualmente ativas, e permite configurar as definições de Firewall para cada instância.

### Alterando suas Configurações de Firewall
![image](images/using_the_cloud_manager.png)

Na página **Edit Subscription**, insira o Endereço IP, a Máscara e o Rótulo para a regra que deseja adicionar. Se for necessária mais de uma regra de firewall, clique em **Add New Range** para criar uma nova regra vazia.

![image](images/using_the_cloud_manager_2.png)

Aqui, você também pode abrir seu firewall para serviços externos (GitHub e Jira Cloud).  Também é possível desabilitar completamente seu firewall, se desejar, selecionando **Proceed Without Firewall** no menu.

## Adicionando usuários adicionais ao Cloud Portal

Se você tiver vários usuários aos quais deseja dar controle sobre o seu Cloud Portal / assinatura do DefectDojo, você pode adicioná-los usando este formulário.  Os usuários que você deseja adicionar precisam ter criado sua própria conta no Cloud Portal em cloud.defectdojo.com; ter uma conta na sua instância do DefectDojo não é suficiente.

![image](images/using_the_cloud_manager_5.png)

Insira o e-mail associado à conta do Cloud Portal do usuário, e clique em Submit para adicioná-lo à sua lista de usuários vinculados.  O usuário poderá então gerenciar o Cloud Portal e sua assinatura do DefectDojo.

## Resources
<https://cloud.defectdojo.com/resources/>

A página Resources contém um formulário Contact Us, que você pode usar para entrar em contato com nossa equipe de Suporte.

![image](images/using_the_cloud_manager_3.png)

## Tools
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

A página Tools é um dos locais onde você pode baixar ferramentas Pro externas, como o Universal Importer ou o DefectDojo CLI.  Essas ferramentas são complementos externos que podem ser usados para construir rapidamente um pipeline de importação via linha de comando na sua rede. Para mais informações sobre essas ferramentas, consulte a documentação de [External Tools](/import_data/pro/specialized_import/external_tools/).

![image](images/using_the_cloud_manager_6.png)


## Account Settings
<https://cloud.defectdojo.com/accounts/settings>

A página de configurações da conta tem quatro seções:

* **User Contact** permite definir seu Username, Email Address, First Name e Last Name.
* **Email Accounts** permite adicionar endereços de e-mail adicionais à sua conta. Adicionar uma conta de e-mail adicional enviará um e-mail de verificação para o novo endereço.
* **Manage Social Accounts** permite conectar o DefectDojo Cloud às suas credenciais do GitHub ou Google, que podem ser usadas para fazer login em vez de um nome de usuário e senha.
* **MFA Settings** permite adicionar um código de MFA ao Google Authenticator, 1Password ou aplicativos similares. Adicionar uma etapa extra ao seu processo de login é uma boa medida proativa para evitar acessos não autorizados.

### Adicionando MFA ao login do seu Cloud Portal
<https://cloud.defectdojo.com/settings/mfa/configure/>

Observe que isso adicionará MFA apenas ao seu login no DefectDojo Cloud, não ao login do seu aplicativo DefectDojo.

![image](images/using_the_cloud_manager_4.png)

1. Comece instalando um aplicativo Authenticator que suporte autenticação por QR code no seu smartphone ou computador.
2. Depois de fazer isso, clique em **Generate QR Code**.
3. Escaneie o QR code exibido no DefectDojo usando seu aplicativo Authenticator, e então insira o código de seis\-dígitos fornecido pelo seu aplicativo.
4. Clique em **Enable Multi\-Factor Authentication**.
