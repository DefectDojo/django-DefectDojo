---
title: KeyCloak
description: Configure o SSO do KeyCloak no DefectDojo Pro
weight: 13
audience: pro
---

O DefectDojo Pro oferece suporte a login via KeyCloak. O DefectDojo open-source não inclui SSO —
consulte [Usuários Autorizados](/admin/user_management/os__authorized_users/) para controle de acesso no
open-source.

Este guia pressupõe que você já tenha um Realm do KeyCloak configurado. Caso contrário, consulte a
[documentação do KeyCloak](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

## Pré-requisitos

Conclua as etapas a seguir no seu realm do KeyCloak antes de configurar o DefectDojo:

1. Adicione um novo client com o tipo `openid-connect`. Anote o client ID.

2. Nas configurações do client:
   - Defina **Access Type** como `confidential`
   - Em **Valid Redirect URIs**, adicione a URL do seu DefectDojo, por exemplo
     `https://yourorganization.cloud.defectdojo.com` ou `https://your-dojo-host/*`
   - Em **Web Origins**, adicione a mesma URL (ou `+`)
   - Em **Fine Grained OpenID Connect Configuration**:
     - Defina **User Info Signed Response Algorithm** como `RS256`
     - Defina **Request Object Signature Algorithm** como `RS256`
   - Salve as configurações.

3. Em **Scope**, defina **Full Scope Allowed** como `off`.

4. Em **Mappers**, adicione um mapper personalizado:
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** selecione o seu client ID
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. Em **Credentials**, copie o **Secret**.

6. Em **Realm Settings > Keys**, copie a **Public Key** (chave de assinatura).

7. Em **Realm Settings > General > Endpoints**, abra a configuração de endpoint do OpenID e copie as URLs
   de endpoint **Authorization** e **Token**.

## Configuração

No DefectDojo, acesse **Enterprise Settings > OAuth Settings**, selecione **KeyCloak** e preencha o
formulário:

- **KeyCloak OAuth Key** — insira o nome do seu client (da etapa 1)
- **KeyCloak OAuth Secret** — insira o secret de credenciais do seu client (da etapa 5)
- **KeyCloak Public Key** — insira a Public Key das configurações do seu realm (da etapa 6)
- **KeyCloak Resource** — insira a URL do Authorization Endpoint (da etapa 7)
- **KeyCloak Group Limiter** — insira a URL do Token Endpoint (da etapa 7)
- **KeyCloak OAuth Login Button Text** — escolha o texto do botão de login do DefectDojo

Marque **Enable KeyCloak OAuth** e envie o formulário. Um botão de login aparecerá na página de login com o
texto que você configurou.
