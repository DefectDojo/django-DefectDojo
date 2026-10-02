---
title: Auth0
description: Configure o SSO do Auth0 no DefectDojo Pro
weight: 3
audience: pro
---

O DefectDojo Pro oferece suporte a login via Auth0. O DefectDojo open-source não inclui SSO — consulte
[Usuários Autorizados](/admin/user_management/os__authorized_users/) para controle de acesso no open-source.

## Pré-requisitos

Conclua as etapas a seguir no seu painel do Auth0 antes de configurar o DefectDojo:

1. Crie uma nova aplicação: **Applications > Create Application > Single Page Web Application**.

2. Configure a aplicação:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. Anote os seguintes valores — você vai precisar deles no DefectDojo:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configuração

No DefectDojo, acesse **Enterprise Settings > OAuth Settings**, selecione **Auth0** e preencha o formulário:

- **Auth0 OAuth Key** — insira seu **Client ID**
- **Auth0 OAuth Secret** — insira seu **Client Secret**
- **Auth0 Domain** — insira seu **Domain**

Marque **Enable Auth0 OAuth** para adicionar um botão **Login With Auth0** à página de login do DefectDojo.
