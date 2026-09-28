---
title: Okta
description: Configure o SSO do Okta no DefectDojo Pro
weight: 15
audience: pro
---

O DefectDojo Pro oferece suporte a login via Okta. O DefectDojo open-source não inclui SSO — consulte [Usuários Autorizados](/admin/user_management/os__authorized_users/) para o controle de acesso no open-source.

## Pré-requisitos

Conclua as etapas a seguir no Okta antes de configurar o DefectDojo:

1. Faça login ou crie uma conta em [Okta](https://www.okta.com/developer/signup/).

2. Acesse **Applications** e clique em **Add Application**.

   ![image](images/okta_1.png)

3. Selecione **Web Applications**.

   ![image](images/okta_2.png)

4. Em **Login Redirect URLs**, adicione a URL de callback do seu DefectDojo. Marque também a caixa **Implicit**.

   ![image](images/okta_3.png)

5. Clique em **Done**.

6. No **Dashboard**, anote a **Org-URL**.

   ![image](images/okta_4.png)

7. Abra o aplicativo recém-criado e anote o **Client ID** e o **Client Secret**.

   ![image](images/okta_5.png)

## Configuração

No DefectDojo, acesse **Enterprise Settings > OAuth Settings**, selecione **Okta** e preencha o formulário:

- **Okta OAuth Key** — insira seu **Client ID**
- **Okta OAuth Secret** — insira seu **Client Secret**
- **Okta Tenant ID** — insira sua Org-URL no formato `https://your-org-url/oauth2`

Marque **Enable Okta OAuth** e envie o formulário. Um botão **Login With Okta** aparecerá na página de login.
