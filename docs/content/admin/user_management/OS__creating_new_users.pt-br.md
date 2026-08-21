---
title: Criando um novo usuário
description: Como integrar um novo usuário à sua instância do DefectDojo
audience: opensource
weight: 1
---

Esta página descreve o fluxo de integração recomendado para adicionar novos usuários a uma instância do DefectDojo.  Usuários do DefectDojo podem ser usados tanto como contas padrão, operadas por humanos, quanto como contas de serviço.

O administrador que cria a conta é responsável por entregar as credenciais iniciais (usuário e senha) ao novo usuário.

## Fluxo de trabalho recomendado

1. **Crie a conta de usuário** no DefectDojo (somente Superusuário):
   * Navegue até **👤 Users → Users** para abrir a tabela All Users.
   * Clique no ícone 🛠️ (chave inglesa e chave de fenda cruzadas).
   * Digite o nome e o endereço de e-mail do novo usuário.
   * Defina uma senha temporária.
   * Envie o formulário.

2. **Atribua as permissões** conforme apropriado — associação a Produto/Tipo de Produto, Permissões de Configuração, Papel Global ou status de Superusuário. Veja [Definir as permissões de um usuário](../set_user_permissions/) para mais detalhes. Um novo usuário sem nenhuma atribuição não conseguirá ver nenhum Produto ou Achado.

3. **Envie as credenciais ao novo usuário por um canal separado** (por e-mail, pela ferramenta de chat da sua equipe, ou da forma como você costuma compartilhar segredos). Inclua:
   * A URL da instância do DefectDojo.
   * O nome de usuário (normalmente o e-mail dele).
   * A senha temporária que você acabou de definir.
   * Uma observação de que ele deve trocar a senha e ativar o MFA (se a sua instância usar MFA) no primeiro login.

4. **O novo usuário faz login e troca a credencial.** Ele pode:
   * Fazer login com a senha temporária e depois trocá-la pelo menu de perfil, ou
   * Usar o link **Esqueci minha senha** na página de login para definir uma senha diretamente, sem usar a temporária. A senha temporária ainda é necessária para que o registro inicial da conta exista, mas o usuário não precisa memorizá-la se usar o fluxo de redefinição de senha.

5. **O novo usuário configura o MFA** pelo menu de perfil. Recomendamos fortemente exigir MFA para todos os usuários em instâncias que não estejam atrás de um SSO.

## Usuários de SSO

Se a sua instância estiver configurada com [SSO](../configure_sso/), o fluxo é diferente — os usuários normalmente são criados no primeiro login a partir do Provedor de Identidade, e você só precisa conceder a eles associação a grupos ou papéis depois.

Se você migrou para o DefectDojo open source (onde o SSO é exclusivo do Pro) e os usuários de SSO existentes não conseguem mais fazer login, veja [Reativando o login para usuários de SSO](../os__sso_user_local_login_fallback/).

## Recuperando-se de um token de MFA perdido

Se um usuário perder o acesso ao dispositivo de MFA, veja a [seção de recuperação de MFA](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes) do guia de solução de problemas de conectividade. Atualmente não há como remover o MFA de uma conta sem um código de MFA — a solução alternativa é criar uma nova conta para o usuário e conceder novamente as mesmas permissões.
