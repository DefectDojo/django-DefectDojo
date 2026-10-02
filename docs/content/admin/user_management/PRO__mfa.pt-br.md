---
title: Autenticação Multifator (MFA)
description: Configure o MFA em sua própria conta, exija-o em toda a sua instância
  e recupere um usuário que perdeu o dispositivo
audience: pro
weight: 3
---

A autenticação multifator adiciona uma segunda etapa ao login: depois da sua senha, o DefectDojo solicita um código de seis dígitos de um aplicativo autenticador. Recomendamos fortemente exigi-la para todos os usuários em instâncias que não estejam atrás de SSO.

O MFA do DefectDojo Pro usa um **aplicativo autenticador TOTP** — Google Authenticator, 1Password, Authy, ou qualquer outro aplicativo que leia um QR code padrão. Não há opção de e-mail ou SMS.

## Configurando o MFA na sua conta

1. Vá até **Connect \> Authorization \> MFA Settings**.
2. Em **Personal Multi-Factor Authentication Settings**, clique em **Set Up MFA**.
3. Leia o QR code com seu aplicativo autenticador. Se você não conseguir ler o código, a tela de configuração também mostra a chave em formato de texto, que você pode digitar manualmente no seu aplicativo.
4. Digite o código de seis dígitos exibido pelo seu aplicativo, e clique em **Verify & enable**.
5. O DefectDojo mostra seus **códigos de recuperação**. Salve-os em um local seguro antes de continuar — veja abaixo. Clique em **Copy codes**, guarde-os, depois clique em **I've saved them. Continue**.

O MFA fica ativo a partir desse momento. Na próxima vez que você fizer login, o DefectDojo pedirá um código depois da sua senha.

### Códigos de recuperação

Você recebe **dez códigos de recuperação de uso único** ao ativar o MFA. Cada um pode ser usado uma vez, no lugar de um código do seu aplicativo autenticador, e é consumido ao ser usado.

Eles são exibidos **uma única vez**, na tela final de configuração. Depois disso, a página MFA Settings mostra apenas quantos códigos ainda restam, não os códigos em si.

Se você perder seus códigos de recuperação — ou quiser um novo conjunto depois de usar vários — clique em **Regenerate Recovery Codes** na página MFA Settings. Isso **substitui todos os seus códigos existentes**: qualquer código salvo anteriormente para de funcionar imediatamente, então salve o novo conjunto assim que possível.

Os códigos de recuperação são o que permite que você volte a acessar a conta quando perde o celular, então guarde-os em um local separado do dispositivo que executa seu aplicativo autenticador.

### Desativando o MFA

**Disable MFA** na página MFA Settings o desativa para sua própria conta. Você só precisa estar logado — não é solicitado nenhum código para confirmar.

Se o seu administrador tiver tornado o MFA obrigatório, você será solicitado a configurá-lo novamente no próximo login.

## Fazendo login com MFA

Depois de digitar seu nome de usuário e senha, o DefectDojo solicita seu código de seis dígitos. Se você não tiver seu aplicativo autenticador, digite um dos seus **códigos de recuperação** no mesmo campo — esse código é então consumido.

## Exigindo MFA para todos

Superusuários podem tornar o MFA obrigatório em toda a instância:

1. Vá até **Connect \> Authorization \> MFA Settings**.
2. No card **MFA Settings** — visível apenas para Superusuários — marque **Require Multi-Factor Authentication Globally**.
3. Envie o formulário.

Isso vem **desativado por padrão**.

Uma vez ativado, qualquer usuário que ainda não tenha se cadastrado é enviado para a tela de configuração de MFA no próximo login, e **não pode pular essa etapa**. O usuário conclui o cadastro, salva seus códigos de recuperação, e chega ao destino original.

### Usuários SSO

O MFA é aplicado pelo DefectDojo, e não delegado ao seu provedor de identidade. Com o MFA global exigido, os usuários que fazem login via SSO também são enviados para configurar o MFA depois que o provedor os retorna ao DefectDojo, e são solicitados a fornecer um código nos logins seguintes.

Não há uma configuração para isentar usuários de SSO. Se o seu provedor de identidade já aplica seu próprio MFA, decida deliberadamente se você quer os dois — ativar o MFA global significa duas solicitações para usuários de SSO.

## Recuperando um usuário que perdeu o dispositivo de MFA

Siga estas etapas em ordem:

1. **Use um código de recuperação.** Se o usuário ainda tiver seus códigos de recuperação, ele digita um deles em vez de um código do aplicativo no login, e depois configura o MFA novamente do zero.
2. **Se ele ainda estiver logado em algum lugar,** pode ir até **MFA Settings** e clicar em **Disable MFA** sem precisar de um código, depois se cadastrar novamente.
3. **Peça a um administrador para limpar o MFA dele.** Com acesso ao servidor, um administrador pode remover o MFA de uma conta:

   ```
   python manage.py remove_mfa --username <username>
   ```

   O comando também aceita `--user-id` ou `--email` em vez de `--username` (exatamente um é obrigatório; `--email` não diferencia maiúsculas de minúsculas). Ele pede confirmação antes de fazer a alteração. O usuário pode então fazer login apenas com a senha e se cadastrar novamente.

   Este é um comando de shell, portanto requer acesso ao container ou host do DefectDojo. Não há um botão equivalente na interface, nem um endpoint na API. No **DefectDojo Cloud**, entre em contato com o [Suporte do DefectDojo](mailto:support@defectdojo.com) para que ele seja executado.

Criar uma conta substituta **não** é necessário — limpar o MFA preserva as permissões, o histórico e as atribuições existentes do usuário.

## MFA e a API

Quando um usuário tem o MFA ativado, as requisições para `/api/v2/api-token-auth/` — o endpoint que troca um nome de usuário e senha por um token de API — também devem incluir um código de MFA, em um campo `mfa_code` junto com as credenciais. Tanto um código TOTP atual quanto um código de recuperação não utilizado são aceitos; usar um código de recuperação aqui o **consome**.

Um código ausente ou incorreto retorna o mesmo erro genérico *"Unable to log in with provided credentials"* de uma senha incorreta, então, se as requisições de token começarem a falhar depois que um usuário ativar o MFA, esse é o primeiro ponto a verificar.

**Os tokens de API existentes continuam funcionando.** Ativar ou desativar o MFA não revoga nem rotaciona tokens já emitidos — a verificação de MFA se aplica no momento em que um token é emitido, não em cada requisição feita com ele. Uma automação de longa duração que já possui um token não é afetada quando um usuário se cadastra no MFA.
