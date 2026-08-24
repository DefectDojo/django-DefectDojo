---
title: GitHub Enterprise
description: Configure o SSO do GitHub Enterprise no DefectDojo Pro
weight: 7
audience: pro
---

O DefectDojo Pro oferece suporte a login via GitHub Enterprise. O DefectDojo open-source não inclui
SSO — consulte [Usuários Autorizados](/admin/user_management/os__authorized_users/) para controle de acesso
no open-source.

## Pré-requisitos

Conclua as etapas a seguir no GitHub Enterprise antes de configurar o DefectDojo:

1. [Crie um novo OAuth App](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app)
   no seu GitHub Enterprise Server.

2. Escolha um nome para a aplicação, por exemplo `DefectDojo`.

3. Defina a **Redirect URI**:
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. Anote o **Client ID** e o **Client Secret** da aplicação.

## Configuração

No DefectDojo, acesse **Enterprise Settings > OAuth Settings**, selecione **GitHub Enterprise** e preencha o
formulário:

- **GitHub Enterprise OAuth Key** — insira seu **Client ID**
- **GitHub Enterprise OAuth Secret** — insira seu **Client Secret**
- **GitHub Enterprise URL** — insira a URL do GitHub da sua organização, por exemplo
  `https://github.yourcompany.com/`
- **GitHub Enterprise API URL** — insira a URL da API do GitHub da sua organização, por exemplo
  `https://github.yourcompany.com/api/v3/`

Marque **Enable GitHub Enterprise OAuth** e envie o formulário. Um botão **Login With GitHub** aparecerá na
página de login.
