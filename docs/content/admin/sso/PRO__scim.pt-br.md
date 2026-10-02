---
title: Provisionamento SCIM
description: Provisione e desprovisione usuários do DefectDojo Pro a partir do seu
  identity provider
weight: 19
audience: pro
---

O DefectDojo Pro oferece suporte ao SCIM 2.0, que permite que seu identity provider crie, atualize e desative usuários do DefectDojo diretamente. Sem ele, o DefectDojo só toma conhecimento de um usuário quando esse usuário faz login, então remover alguém do seu identity provider impede logins futuros, mas deixa a conta do DefectDojo ativa.

O SCIM é independente do single sign-on e o complementa. O SSO decide quem pode fazer login; o SCIM mantém a própria lista de contas sincronizada com o seu diretório. A maioria dos clientes configura os dois: SAML ou OIDC para autenticação, SCIM para provisionamento.

A configuração do SCIM só pode ser feita por um **Superuser**.

## O que o SCIM faz no DefectDojo

Ao conectar um identity provider via SCIM, ele pode:

* criar usuários do DefectDojo quando alguém é atribuído ao aplicativo
* atualizar nomes e endereços de e-mail quando eles mudam no diretório
* desativar usuários quando eles são desatribuídos ou saem da organização
* criar grupos e adicionar e remover seus membros

Desativar um usuário via SCIM faz duas coisas ao mesmo tempo. A conta é marcada como inativa, para que o usuário não possa mais fazer login, e os tokens de API do DefectDojo desse usuário são excluídos. O offboarding, portanto, fecha as duas portas em uma única etapa, que é o principal motivo para usar o SCIM em vez de depender apenas do seu identity provider.

O registro do usuário em si é mantido. Achados, notas e o histórico fazem referência às pessoas que os criaram, então o DefectDojo desativa a conta em vez de excluí-la. Se a mesma pessoa retornar, reativá-la pelo seu identity provider restaura o acesso sem afetar esse histórico.

## Configuração

1. Acesse **Connect > Authorization** e selecione **SCIM Provisioning**. O SCIM aparece listado junto com seus provedores de login porque se conecta ao mesmo identity provider, e é marcado como **Provisioning** para diferenciá-lo dos provedores que colocam um botão na página de login.

2. Marque **Enable SCIM Provisioning** e envie. Enquanto isso estiver desativado, os endpoints do SCIM se comportam como se não existissem, de modo que um teste de conexão do seu identity provider reporta o endereço como não encontrado.

3. Copie a **Tenant URL** exibida na página. Ela se parece com isto:

   ```
   https://<your-instance>.cloud.defectdojo.com/scim/v2
   ```

4. No painel **SCIM Tokens**, dê ao token um nome que indique onde ele será usado, por exemplo "Okta production", e depois selecione **Generate Token**.

5. Copie o token da caixa de diálogo e cole-o no seu identity provider. O DefectDojo armazena apenas um hash do token, então ele não pode ser exibido novamente. Se você o perder, gere outro e revogue o antigo.

Você pode manter mais de um token ativo ao mesmo tempo. Para fazer o rodízio, gere um novo token, atualize seu identity provider e depois revogue o antigo. Não há nenhuma janela em que o provisionamento pare de funcionar.

O painel de tokens registra quando cada token foi usado pela última vez, o que é uma forma rápida de confirmar que seu identity provider está realmente alcançando o DefectDojo.

## Okta

1. No Okta Admin Console, acesse **Applications > Browse App Catalog** e adicione **SCIM 2.0 Test App (Header Auth)**. Se você já tiver um aplicativo SAML para o DefectDojo, pode habilitar o provisionamento nesse aplicativo em vez disso.

2. Abra a aba **Provisioning** e selecione **Configure API Integration**.

3. Defina **SCIM 2.0 Base Url** com a Tenant URL que você copiou acima.

4. Defina **API Token** como `Bearer <your token>`, incluindo a palavra `Bearer` e um único espaço. Esse tipo de aplicativo envia o valor literalmente como o cabeçalho Authorization.

5. Selecione **Test API Credentials** e depois salve.

6. Em **Provisioning > To App**, habilite **Create Users**, **Update User Attributes** e **Deactivate Users**.

7. Atribua pessoas ou grupos ao aplicativo. O Okta primeiro procura cada pessoa no DefectDojo pelo nome de usuário e só cria uma conta quando não encontra nenhuma, então qualquer pessoa que já tenha uma conta do DefectDojo é vinculada em vez de duplicada.

Para enviar grupos também, abra a aba **Push Groups** e adicione os grupos que você quer que o DefectDojo espelhe. Veja [Grupos](#groups) abaixo para saber o que o DefectDojo faz com eles.

## Microsoft Entra ID

1. No Entra admin center, acesse **Enterprise applications > New application > Create your own application** e escolha a opção non-gallery. Se você já tiver um aplicativo para o DefectDojo, use-o.

2. Abra **Provisioning** e defina **Provisioning Mode** como **Automatic**.

3. Defina **Tenant URL** com a Tenant URL que você copiou acima.

4. Defina **Secret Token** com o seu token SCIM. O Entra o envia como um bearer token, então não adicione a palavra `Bearer` aqui.

5. Selecione **Test Connection** e depois salve.

6. Atribua usuários e grupos em **Users and groups** e inicie o provisionamento.

O Entra provisiona em um ciclo de aproximadamente 40 minutos. Enquanto você estiver configurando, **Provision on demand** aplica um único usuário ou grupo imediatamente, o que torna muito mais rápido confirmar que a configuração funciona.

## O que o DefectDojo armazena

O DefectDojo mapeia um pequeno conjunto de atributos SCIM e ignora o restante.

| Atributo SCIM | Campo do DefectDojo |
|---|---|
| `userName` | Username |
| `name.givenName` | First name |
| `name.familyName` | Last name |
| `emails` | Email address |
| `active` | Se a conta está habilitada |
| `externalId` | Mantido para que seu identity provider possa corresponder o registro posteriormente |

Atributos que o DefectDojo não modela, incluindo números de telefone, cargos e a extensão enterprise do SCIM, são aceitos e ignorados em vez de rejeitados. Mapear atributos extras no seu identity provider é inofensivo.

Dois atributos merecem atenção especial:

**Username.** O DefectDojo permite letras, dígitos e os caracteres `@ . + - _` em um nome de usuário. Se o seu identity provider enviar um nome de usuário contendo qualquer outra coisa, o DefectDojo rejeita esse usuário com um erro indicando o problema, em vez de silenciosamente armazenar um nome de usuário diferente. Armazenar um nome de usuário alterado impediria que seu provedor conseguisse localizar a conta posteriormente.

**Email address.** O SCIM não exige um, e o DefectDojo criará o usuário sem ele. Tenha em mente que as notificações do DefectDojo, incluindo relatórios agendados e alertas, não têm para onde ir para um usuário sem endereço de e-mail. Mapeie o atributo `emails`, a menos que você tenha um motivo para não fazê-lo.

O SCIM nunca define senhas e nunca concede status de superuser ou staff. Se o seu identity provider estiver configurado para enviar senhas, o DefectDojo as ignora. Usuários provisionados dessa forma fazem login pelo SSO.

## Grupos

O SCIM gerencia apenas os grupos que ele criou. Grupos criados por você na interface do DefectDojo, ou que chegaram por meio do mapeamento de grupos do SAML ou do Azure AD, são invisíveis para o SCIM e não podem ser renomeados, esvaziados ou excluídos pelo seu identity provider.

Isso importa porque o push de grupo é, por natureza, uma substituição completa. Se um identity provider pudesse adotar um grupo existente, sua próxima sincronização substituiria a associação cuidadosamente escolhida desse grupo pelo que quer que o diretório contenha. Por isso, enviar um grupo cujo nome já está em uso falha com uma mensagem explicando o conflito. Para transferir um grupo existente para o seu identity provider, renomeie um dos dois, ou exclua o grupo do DefectDojo e deixe o provedor recriá-lo.

Dentro de um grupo gerenciado pelo SCIM, a associação pertence ao seu identity provider e as roles pertencem ao DefectDojo:

* Um membro recém-adicionado recebe a role **Reader**.
* Se você promover alguém a uma role superior no DefectDojo, sincronizações posteriores não alteram essa role.
* Qualquer pessoa adicionada manualmente a um grupo gerenciado pelo SCIM é removida na próxima sincronização, porque o identity provider é a fonte da verdade sobre quem pertence ao grupo.

Excluir um grupo via SCIM remove o grupo e suas associações. Isso nunca exclui as pessoas que faziam parte dele.

## Protegendo o acesso de administrador

Por padrão, o SCIM não desativa uma conta de superuser. A falha comum em qualquer configuração de provisionamento é um identity provider com escopo mais amplo do que o pretendido, e os superusers são a forma de você voltar a acessar o DefectDojo quando algo dá errado.

Se você quiser que seu identity provider também gerencie superusers, habilite **Allow SCIM to deactivate superusers** na página de configurações do SCIM. Mesmo assim, o DefectDojo se recusa a desativar o último superuser ativo restante, de modo que o provisionamento não pode deixar a instância sem um administrador.

## Limitações

* Um identity provider por instância do DefectDojo.
* A filtragem é suportada em `userName`, `displayName`, `externalId` e `id`, usando uma única comparação de igualdade. Isso cobre o que o Okta e o Entra enviam ao corresponder registros. Filtros mais complexos são rejeitados com um erro informando isso.
* Operações em massa, ordenação e o endpoint `/Me` não estão implementados.
* As associações a grupos são gerenciadas por meio do endpoint Groups. Enviar a associação a grupo em um registro de usuário não tem efeito, o que corresponde ao comportamento dos dois provedores.

## Solução de problemas

**O teste de conexão reporta "not found".** O SCIM está desativado, ou a instância não tem licença para ele. Verifique se **Enable SCIM Provisioning** está ativado e se a sua assinatura inclui SSO. Todo o endereço do SCIM se comporta como se não existisse até que ambas as condições sejam verdadeiras.

**O teste de conexão reporta uma falha de autenticação.** O token está errado ou foi revogado. Gere um novo e atualize seu identity provider. No Okta, verifique se o valor começa com `Bearer ` e um espaço; no Entra, verifique se não começa.

**Um usuário falha ao ser provisionado com um erro sobre o nome de usuário.** O nome de usuário contém caracteres que o DefectDojo não permite. Altere o atributo que seu identity provider mapeia para `userName`, geralmente para o endereço de e-mail do usuário ou o user principal name.

**Um grupo falha ao ser enviado, informando que já existe um grupo com esse nome.** Um grupo do DefectDojo com esse nome foi criado em outro lugar. Veja [Grupos](#groups) acima.

**Um membro de grupo falha ao ser provisionado.** A pessoa ainda não foi provisionada no DefectDojo. Atribua-a ao aplicativo, e a associação terá sucesso no próximo ciclo.

**Comece pelo Diagnostics.** As requisições SCIM recusadas são registradas em **Connect > Diagnostics**, com o endpoint, o status e a mensagem que o DefectDojo enviou de volta. Isso geralmente é mais rápido do que ler o log do seu identity provider, e é o único lugar que mostra os dois lados da troca. O provisionamento bem-sucedido não é registrado ali; as alterações em usuários e grupos aparecem no histórico de auditoria.

**Tudo reporta sucesso, mas nada aparece no DefectDojo.** Verifique se a Tenant URL termina em `/scim/v2` sem barra final, e se o seu identity provider está realmente alcançando sua instância. A coluna **Last Used** no painel SCIM Tokens mostra se alguma requisição chegou.

**Usuários do DefectDojo Pro:** se a sua instância restringe o acesso por endereço IP, adicione os endereços do seu identity provider à allowlist do firewall antes de configurar o SCIM. Veja [Firewall Rules](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings).
