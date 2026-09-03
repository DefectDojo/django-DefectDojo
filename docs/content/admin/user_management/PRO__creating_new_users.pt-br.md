---
title: Criando um novo usuário
description: Como integrar um novo usuário à sua instância do DefectDojo
audience: pro
weight: 1
---

Esta página descreve o fluxo de integração recomendado para adicionar novos usuários a uma instância do DefectDojo.  Usuários do DefectDojo podem ser usados tanto como contas padrão, operadas por humanos, quanto como contas de serviço.

O administrador que cria a conta é responsável por entregar as credenciais iniciais (nome de usuário e senha) ao novo usuário.

## Fluxo recomendado

1. **Crie a conta de usuário** no DefectDojo (somente Superusuário):
   * Navegue até **👤 Users → ➕ New User**.
   * Insira o nome e o endereço de e-mail do novo usuário.
   * Defina uma senha temporária.
   * Envie o formulário.

2. **Atribua as permissões** conforme apropriado — associação a Produto/Tipo de Produto, Permissões de Configuração, Função Global, ou status de Superusuário. Consulte [Definir as permissões de um Usuário](../set_user_permissions/) para mais detalhes. Um novo usuário sem nenhuma atribuição não conseguirá ver nenhum Produto ou Achado.

3. **Envie as credenciais ao novo usuário por um canal separado** (por e-mail, pela ferramenta de chat da sua equipe, ou da forma como você normalmente compartilha segredos). Inclua:
   * A URL da instância do DefectDojo.
   * O nome de usuário (geralmente o endereço de e-mail).
   * A senha temporária que você acabou de definir.
   * Uma observação de que o usuário deve trocar a senha e ativar o MFA (se sua instância usar MFA) no primeiro login.

4. **O novo usuário faz login e rotaciona a credencial.** Ele pode:
   * Fazer login com a senha temporária e depois alterá-la pelo menu de perfil, ou
   * Usar o link **I forgot my password** na página de login para definir uma senha diretamente, sem usar a temporária. A senha temporária ainda é necessária para que o registro inicial da conta exista, mas o usuário não precisa memorizá-la se usar o fluxo de redefinição de senha.

5. **O novo usuário configura o MFA** pelo menu de perfil. Recomendamos fortemente exigir MFA para todos os usuários em instâncias que não estejam atrás de SSO.

## Usuários SSO

Se sua instância estiver configurada com [SSO](../configure_sso/), o fluxo é diferente — os usuários normalmente são criados no primeiro login a partir do Provedor de Identidade, e você só precisa conceder a eles associação a grupos ou funções posteriormente.

## Recuperando-se da perda de um token MFA

Se um usuário perder o acesso ao seu dispositivo MFA, ele pode fazer login com um dos códigos de recuperação emitidos no momento do cadastro. Se esses também tiverem sido perdidos, um administrador com acesso ao servidor pode limpar o MFA da conta com `python manage.py remove_mfa --username <username>`, após o que o usuário faz login com sua senha e se cadastra novamente — suas permissões e seu histórico são preservados, portanto não é necessário criar uma conta substituta.

Consulte [Autenticação Multifator](../pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) para conhecer todas as opções de recuperação, e observe que o acesso ao **Cloud Manager** em si é uma questão separada — consulte o [guia de solução de problemas de conectividade](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes).
