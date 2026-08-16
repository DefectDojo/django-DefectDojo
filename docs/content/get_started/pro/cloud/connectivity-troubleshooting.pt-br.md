---
title: Solução de Problemas de Conectividade
description: Reconecte-se à sua instância do DefectDojo
weight: 2
audience: pro
aliases:
- /pt-br/en/cloud_management/connectivity-troubleshooting
---

Se você tiver dificuldade para acessar sua instância do DefectDojo, aqui estão algumas etapas que você pode seguir para se reconectar:

## Consigo acessar o site, mas não consigo fazer login

1. Você pode redefinir a senha da sua conta a partir da página de login: **yourcompanyinstance.cloud.defectdojo.com/login**. Clique em 'I forgot my password' para iniciar o processo.
​

![imagem](images/Connectivity_Troubleshooting.png)

2. Insira seu endereço de e-mail e clique em "Reset my password".
​
3. Você deve receber um e-mail com o assunto "`Password reset on yourcompanyinstance.cloud.defectdojo.com`". Esse e-mail contém um link no qual você pode clicar para definir uma nova senha.


![imagem](images/Connectivity_Troubleshooting_2.png)

Se você não receber um e-mail, verifique sua pasta de Spam. Se ainda assim não encontrar, peça para o administrador DefectDojo da sua equipe confirmar que você tem uma conta registrada na instância.



## Não consigo acessar o site cloud.defectdojo da minha empresa

Se o site cloud.defectdojo da sua empresa não carregar no seu navegador, ou expirar por timeout, pode ser necessário que sua empresa altere as regras de firewall para aceitar sua conexão.

As regras de firewall podem ser alteradas no seu Cloud Manager em <https://cloud.defectdojo.com/accounts/manage_subscriptions>.

Se sua empresa usa uma VPN compartilhada, servidor proxy ou ferramenta similar, certifique-se de que ela esteja autorizada a se conectar ao DefectDojo e que o endereço IP esteja incluído nas regras de Firewall do DefectDojo.

Se o problema persistir, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com) .



## Não consigo fazer login no Cloud Manager

Se você não conseguir acessar o Cloud Manager, navegue até a página de Login em <https://cloud.defectdojo.com/accounts/login/> e clique em **"Forgot your password?"**


![imagem](images/Connectivity_Troubleshooting_3.png)
Você será solicitado a inserir seu endereço de e-mail, e nossa equipe enviará um e-mail com um link para redefinir sua senha e inserir uma nova.

Observe que esse método de login funciona somente para o **Cloud Manager**, um site administrativo ao qual nem todos os membros da sua equipe podem ter acesso. Fazer login diretamente na sua instância para usar o DefectDojo só é possível conectando-se diretamente a **yourcompanyinstance.cloud.defectdojo.com/login**.



## Perdi o acesso aos meus códigos de MFA

* **Para o Cloud Manager:** Se você perder o acesso aos seus códigos de MFA, ou ao Authenticator App, entre em contato com o Suporte do DefectDojo em [support@defectdojo.com](mailto:support@defectdojo.com).
* **Para uma Instância do DefectDojo:** Primeiro tente um dos **códigos de recuperação** emitidos quando o MFA foi configurado — inseridos no lugar do código de seis dígitos no login. Se eles não estiverem disponíveis, um administrador com acesso ao servidor pode limpar o MFA da conta usando `python manage.py remove_mfa --username <username>`; o usuário então faz login com sua senha e se registra novamente, mantendo todas as permissões e o histórico existentes. No DefectDojo Cloud, entre em contato com o Suporte para que esse comando seja executado. Veja [Autenticação Multifator](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) para ver todas as opções.
