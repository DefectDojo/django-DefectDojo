---
title: Redefinindo credenciais de usuários em massa
description: Rotacione tokens de API e force a redefinição de senha para vários usuários
  de uma vez a partir da lista de Usuários
audience: pro
weight: 2
---

A lista de **Usuários** do DefectDojo Pro permite rotacionar tokens de API e forçar a redefinição de senha para vários usuários de uma vez — útil para higiene periódica de credenciais ou para responder a uma suspeita de exposição de credenciais.

Essas ações em massa estão disponíveis apenas para **Superusuários** e usuários com o papel **Global Owner**. Se você não tiver uma dessas permissões, as caixas de seleção e os botões de ação em massa não aparecem.

## Selecionando usuários

Na lista de **Usuários**, use as caixas de seleção para selecionar um ou mais usuários. Uma barra de ações em massa aparece com os botões de redefinição. Cada ação pede confirmação em uma caixa de diálogo antes de ser executada.

A ação se aplica aos usuários que você marcou explicitamente. Você **não pode incluir sua própria conta** em uma redefinição em massa: se sua conta estiver entre as linhas selecionadas, os botões de ação em massa ficam desabilitados e um aviso é exibido.

## Reset API Tokens

**Reset API Tokens** rotaciona o token de API de cada usuário selecionado: o DefectDojo exclui o token existente do usuário e emite um novo. **O token atual do usuário para de funcionar imediatamente**, portanto qualquer script ou integração que use o token antigo precisa ser atualizado com o novo.

* Os novos valores de token **não** são exibidos para você como administrador. Cada usuário afetado recebe uma notificação de **"API Token Reset"** informando que deve obter o novo token na interface (entregue de acordo com as configurações de notificação desse usuário).

## Force Password Reset

**Force Password Reset** define o sinalizador *force-password-reset-on-next-login* em cada usuário selecionado. Na próxima vez que esse usuário fizer uma requisição, o DefectDojo o redireciona para a página **Change Password** e não permite que ele continue até definir uma nova senha. O sinalizador é removido automaticamente assim que isso acontece.

Tenha em mente o que essa ação **não** faz:

* Ela **não** define nem randomiza uma senha temporária, e **não** retorna nenhuma credencial para você.
* Ela **não** envia um e-mail ou notificação aos usuários afetados. Como não há aviso automático, informe os usuários afetados por outro canal de que serão solicitados a alterar a senha no próximo login.

> **Usuários SSO:** Diferente do formulário de edição de usuário único (que desabilita o sinalizador de redefinição forçada para contas autorizadas via SSO), a ação em massa aplica o sinalizador a **todos** os usuários selecionados, independentemente de como eles se autenticam. Como os usuários SSO fazem login através do seu Provedor de Identidade em vez de uma senha do DefectDojo, forçar uma redefinição de senha para eles geralmente não faz sentido — evite incluir usuários somente-SSO na seleção.
