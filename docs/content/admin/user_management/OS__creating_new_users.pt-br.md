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

2. **Conceda acesso** conforme apropriado. Adicione o usuário à lista de Usuários Autorizados de cada Ativo ou Organização de que ele precisa, ou marque-o como membro da equipe (staff) ou superusuário. Veja [Permissões do Open Source](../os__authorized_users/) para mais detalhes. Um novo usuário sem nenhuma atribuição não conseguirá ver nenhum Ativo ou Achado.

3. **Envie as credenciais ao novo usuário por um canal separado** (por e-mail, pela ferramenta de chat da sua equipe, ou da forma como você costuma compartilhar segredos). Inclua:
   * A URL da instância do DefectDojo.
   * O nome de usuário (normalmente o e-mail dele).
   * A senha temporária que você acabou de definir.
   * Uma observação de que ele deve trocar a senha no primeiro login.

4. **O novo usuário faz login e troca a credencial.** Ele pode:
   * Fazer login com a senha temporária e depois trocá-la pelo menu de perfil, ou
   * Usar o link **Esqueci minha senha** na página de login para definir uma senha diretamente, sem usar a temporária. A senha temporária ainda é necessária para que o registro inicial da conta exista, mas o usuário não precisa memorizá-la se usar o fluxo de redefinição de senha.

## Usuários que entraram com SSO

O DefectDojo open source oferece suporte apenas a contas locais. SSO (SAML, OIDC, OAuth), LDAP e MFA estão disponíveis no [DefectDojo Pro](/admin/sso/).

Se você atualizou para o DefectDojo open source 3.x e os usuários de SSO existentes não conseguem mais fazer login, veja [Reativando o login para usuários de SSO](../os__sso_user_local_login_fallback/).
