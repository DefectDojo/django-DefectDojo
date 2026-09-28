---
title: Single Sign-On
description: O DefectDojo Pro oferece suporte a SAML e a uma variedade de provedores
  OAuth para Single Sign-On
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2026-04-30 00:00:00+00:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
pro-feature: true
aliases:
- /pt-br/admin/user_management/configure_sso/
- /pt-br/admin/sso/os__saml/
- /pt-br/admin/sso/os__auth0/
- /pt-br/admin/sso/os__azure_ad/
- /pt-br/admin/sso/os__github_enterprise/
- /pt-br/admin/sso/os__gitlab/
- /pt-br/admin/sso/os__google/
- /pt-br/admin/sso/os__keycloak/
- /pt-br/admin/sso/os__oidc/
- /pt-br/admin/sso/os__okta/
- /pt-br/admin/sso/os__remote_user/
---

Single Sign-On é um recurso do **DefectDojo Pro**. A partir do DefectDojo 3.0, a superfície de SSO — SAML, OIDC e os provedores OAuth integrados — está disponível somente no DefectDojo Pro. O DefectDojo open-source usa login local por nome de usuário/senha e o fluxo de redefinição de senha.

Se você estiver usando o DefectDojo open-source e quiser SSO, será necessário migrar para o [DefectDojo Pro](https://defectdojo.com); a migração está descrita nas [notas de atualização do 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only). As contas de usuário e associações de grupo existentes são preservadas na atualização. Para controle de acesso no DefectDojo open-source, veja a página [Usuários Autorizados](/admin/user_management/os__authorized_users/).

## Vendo o que está configurado

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** lista todos os provedores suportados em uma única página — quais estão configurados, quais estão habilitados e qual protocolo cada um utiliza — e leva você diretamente ao formulário de configurações de qualquer um deles. Comece por ali se quiser saber o estado desta instância, em vez de configurar um provedor específico.

## Provedores de SSO suportados (DefectDojo Pro)

O DefectDojo Pro oferece suporte a SAML e aos seguintes provedores OAuth. Cada guia percorre a configuração no lado do provedor e a configuração correspondente na interface **Enterprise Settings** do Pro.

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**
* **[LDAP](/admin/sso/pro__ldap/)**

## Provisionando usuários a partir do seu diretório (DefectDojo Pro)

Os provedores acima decidem quem pode fazer login. **[SCIM Provisioning](/admin/sso/pro__scim/)** mantém a própria lista de contas sincronizada com o seu diretório, de modo que os usuários sejam criados quando entram, atualizados quando seus dados mudam e desativados (junto com seus tokens de API) quando saem.

A configuração de SSO no DefectDojo Pro só pode ser feita por um **Superuser**.

**Usuários do DefectDojo Pro:** adicione os endereços IP dos seus serviços SAML ou SSO à whitelist do Firewall antes de configurar o SSO. Veja [Firewall Rules](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) para mais informações.

## Desabilitando o login por Nome de usuário / Senha

Depois que o SSO estiver configurado no DefectDojo Pro, você pode querer desabilitar o formulário tradicional de login por nome de usuário/senha. Desmarque **Allow Login via Username and Password** em **Enterprise Settings > Login Settings**.

![image](images/pro_login_settings.png)

### Fallback de login

Se a sua integração de SSO parar de funcionar, você sempre pode voltar ao formulário de login padrão adicionando o seguinte à URL do seu DefectDojo:

`/login?force_login_form`

Recomendamos manter pelo menos uma conta de administrador com nome de usuário e senha configurados como fallback.
