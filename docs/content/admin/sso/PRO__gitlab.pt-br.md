---
title: GitLab
description: Configure o SSO do GitLab no DefectDojo Pro
weight: 9
audience: pro
---

O DefectDojo Pro oferece suporte a login via GitLab. O DefectDojo open-source não inclui SSO — consulte
[Usuários Autorizados](/admin/user_management/os__authorized_users/) para controle de acesso no open-source.

## Pré-requisitos

Conclua as etapas a seguir no GitLab antes de configurar o DefectDojo:

1. Acesse a página Applications do seu perfil do GitLab:
   - GitLab.com: `https://gitlab.com/profile/applications`
   - Self-hosted: `https://your-gitlab-host/profile/applications`

2. Crie uma nova aplicação:
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. Anote o **Application ID** e o **Secret** da aplicação.

## Configuração

No DefectDojo, acesse **Enterprise Settings > OAuth Settings**, selecione **GitLab** e preencha o formulário:

- **GitLab OAuth Key** — insira seu **Application ID**
- **GitLab OAuth Secret** — insira seu **Secret**
- **GitLab API URL** — insira a URL base da sua instância do GitLab, por exemplo `https://gitlab.com`

Marque **Enable GitLab OAuth** e envie o formulário. Um botão **Login With GitLab** aparecerá na página de
login.
