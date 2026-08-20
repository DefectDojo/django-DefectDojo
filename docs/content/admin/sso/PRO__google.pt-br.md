---
title: Google Auth
description: Configure o OAuth do Google no DefectDojo Pro
weight: 11
audience: pro
---

O DefectDojo Pro oferece suporte a login via contas do Google. Novos usuários são criados
automaticamente no primeiro login, caso ainda não existam. Usuários já existentes no DefectDojo são
correspondidos a contas do Google pelo nome de usuário (a parte antes do `@` no e-mail do Google). O
DefectDojo open-source não inclui SSO — consulte
[Usuários Autorizados](/admin/user_management/os__authorized_users/) para controle de acesso no open-source.

## Pré-requisitos

Conclua as etapas a seguir no Google Cloud Console antes de configurar o DefectDojo:

1. Faça login no [Google Developers Console](https://console.developers.google.com).

2. Acesse **Credentials > Create Credentials > OAuth Client ID**.

   ![image](images/google_1.png)

3. Selecione **Web Application** e dê a ela um nome descritivo (por exemplo, `DefectDojo`).

4. Em **Authorized Redirect URIs**, adicione:
   `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/`

5. Anote o **Client ID** e a **Client Secret Key**.

## Configuração

No DefectDojo, acesse **Enterprise Settings > OAuth Settings**, selecione **Google** e preencha o
formulário:

- **Google OAuth Key** — insira seu **Client ID**
- **Google OAuth Secret** — insira sua **Client Secret Key**
- **Whitelisted Domains** — insira o domínio da sua organização (por exemplo, `yourcompany.com`) para
  permitir que qualquer usuário com esse domínio faça login
- **Whitelisted E-mail Addresses** — alternativamente, insira endereços de e-mail específicos para permitir
  (por exemplo, `user1@yourcompany.com, user2@yourcompany.com`)

É necessário definir pelo menos um domínio ou endereço de e-mail na lista de permissões, caso contrário
nenhum usuário conseguirá fazer login via Google.

Marque **Enable Google OAuth** e envie o formulário. Um botão **Login With Google** aparecerá na página de
login.
