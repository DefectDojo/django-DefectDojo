---
title: Autenticação LDAP
description: Configure a autenticação LDAP no DefectDojo Pro
weight: 20
audience: pro
aliases:
- /pt-br/en/open_source/ldap-authentication
---

O DefectDojo Pro oferece suporte a autenticação LDAP diretamente pela interface **Enterprise
Settings** — não são necessárias imagens Docker personalizadas nem arquivos de configuração.

Diferentemente dos outros provedores nesta página, o LDAP não é um fluxo baseado em redirecionamento. Os
usuários fazem login com o formulário padrão de nome de usuário e senha do DefectDojo, e suas credenciais
são verificadas no seu diretório. Não há um botão de login extra.

## Configuração

Abra **Enterprise Settings > LDAP Settings**.

![image](images/sso_ldap_settings.png)

1. **Server URI** — o diretório ao qual se conectar, por exemplo `ldaps://ldap.example.com:636`.
   Prefira `ldaps://`. Se for necessário usar `ldap://` simples, habilite **Use StartTLS** abaixo para que
   a conexão seja atualizada antes do envio das credenciais.
2. **Bind DN** — o distinguished name da conta de serviço usada para pesquisar usuários.
   Deixe em branco para um bind anônimo.
3. **Bind Password** — a senha dessa conta de serviço. O valor armazenado nunca é
   retornado ao navegador; deixe o campo em branco para manter a senha que você já salvou.
4. **User Search Base** — o DN sob o qual pesquisar as entradas de usuário, por exemplo
   `ou=people,dc=example,dc=com`.
5. **User Search Filter** — o filtro usado para localizar o usuário. Ele **deve** conter o
   placeholder literal `%(user)s`, que é substituído pelo nome de usuário enviado. Valores
   comuns são `(uid=%(user)s)` para OpenLDAP e `(sAMAccountName=%(user)s)` para Active
   Directory.
6. **User Attribute Mapping** — veja abaixo.
7. Marque **Enable LDAP** para ativá-lo.

Use **Validate Config** para verificar as configurações sem salvá-las. Ele reporta a integridade das
configurações, se o servidor está acessível, se o bind é bem-sucedido, se as bases de pesquisa são
resolvidas, e se o mapeamento de atributos parece utilizável.

## User Attribute Mapping

Cada linha mapeia um **LDAP Attribute** para o **DefectDojo Field** que ele deve preencher. Use
**Add Attribute Mapping** para adicionar linhas e o ícone de lixeira para remover uma.

![image](images/sso_ldap_attribute_mapping.png)

- **LDAP Attribute** é texto livre e deve corresponder ao atributo que o seu diretório realmente
  retorna — por exemplo `uid`, `givenName`, `sn`, `mail` no OpenLDAP, ou `sAMAccountName`,
  `givenName`, `sn`, `mail` no Active Directory.
- **DefectDojo Field** é escolhido a partir de uma lista: **Username**, **First Name**, **Last Name** e
  **Email**.
- Mapear um atributo para **Email** é fortemente recomendado: o DefectDojo usa o endereço de e-mail para
  notificações.
- O mesmo atributo pode alimentar mais de um campo. Cada campo do DefectDojo pode ser mapeado a partir de
  apenas um atributo.
- Sem nenhum mapeamento, as contas são criadas sem nome ou endereço de e-mail.

**Always Update User** controla quando o mapeamento é aplicado. Quando habilitado (o padrão), os atributos
mapeados são atualizados a partir do diretório a cada login, de modo que uma alteração de nome ou e-mail no
LDAP chega ao DefectDojo. Quando desabilitado, eles só são aplicados quando a conta é criada pela primeira
vez.

## Group Mapping

O DefectDojo pode espelhar os grupos LDAP de um usuário em grupos do DefectDojo no login. Marque
**Enable Group Mapping** para revelar as configurações.

![image](images/sso_ldap_group_mapping.png)

- **Group Search Base** — o DN sob o qual pesquisar as entradas de grupo, por exemplo
  `ou=groups,dc=example,dc=com`. Obrigatório quando o group mapping está habilitado.
- **Group Type** — como o seu diretório modela a associação. Escolha **groupOfNames** para OpenLDAP e
  Active Directory, **groupOfUniqueNames**, ou **posixGroup**.
- **Group Limiter Regex Expression** — apenas os grupos cujo nome corresponde a esta expressão são
  espelhados. Use `.*` para permitir todos, ou um prefixo como `^dd-` para espelhar apenas os grupos que
  você pretende que o DefectDojo gerencie.

Os grupos são criados no primeiro uso, caso ainda não existam. Um grupo recém-criado não tem permissões até
que um Superuser as configure — veja [User Groups](../../user_management/create_user_group/).

## Opções adicionais

* **Use StartTLS** — atualiza uma conexão `ldap://` simples para TLS antes do bind. Não é necessário quando
  a URI já é `ldaps://`.
* **Always Update User** — atualiza os atributos mapeados a partir do diretório a cada login.

## Solução de problemas

Execute **Validate Config** primeiro — geralmente ele indica o problema diretamente. Além disso:

**Todo login falha, mas o diretório está acessível.** Verifique se o **User Search Filter** contém
`%(user)s` e se o atributo nele corresponde ao que os usuários realmente digitam. Um filtro
`(uid=%(user)s)` nunca vai corresponder se os seus usuários fizerem login com um `sAMAccountName` do Active
Directory.

**Os logins são bem-sucedidos, mas as contas não têm nome ou e-mail.** O **User Attribute Mapping** está
vazio, ou os nomes de atributo LDAP à esquerda não correspondem ao que o seu diretório retorna.

**Um nome mudou no LDAP, mas não no DefectDojo.** **Always Update User** está desabilitado, portanto o
mapeamento só foi aplicado quando a conta foi criada.

**As tentativas de login travam ou ficam lentas.** As conexões e pesquisas são limitadas por um timeout, de
modo que um diretório inacessível falha em vez de bloquear indefinidamente. Verifique **Server
Reachability** em **Validate Config** e confirme se a porta está aberta a partir do host do DefectDojo.
