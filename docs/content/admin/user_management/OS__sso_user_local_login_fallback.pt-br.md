---
title: Reativando o login para usuários de SSO
description: Defina uma senha local para usuários provisionados via SSO após migrar
  para o Open Source, onde o SSO é um recurso exclusivo do Pro
audience: opensource
weight: 2
---

## Quando isso se aplica

O SSO (SAML, OIDC, OAuth) é um recurso do [DefectDojo Pro](https://defectdojo.com). Se você atualizar para o DefectDojo open source 3.x (ou de alguma outra forma deixar de usar o Pro), as opções de login via SSO são removidas, e os usuários que foram provisionados por SSO não conseguem mais fazer login. As contas deles nunca receberam uma senha local, e a interface e a API não permitem definir uma para eles: o DefectDojo os detecta como contas de SSO e bloqueia a alteração.

Você **não** precisa excluir e recriar esses usuários (o que faria você perder o histórico, as permissões e a propriedade dos objetos deles). Em vez disso, defina uma senha local para cada conta no backend e force uma redefinição de senha no próximo login.

Veja a [seção de SSO](/admin/sso/) e as [notas de atualização da versão 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only) para entender o contexto de o SSO ser exclusivo do Pro.

## Por que isso acontece

O DefectDojo open source autentica apenas contra o banco de dados local de usuários do Django. Ele decide se uma conta é uma "usuária de SSO" unicamente pelo fato de a conta ter ou não uma senha utilizável. As contas provisionadas via SSO foram criadas com uma senha *inutilizável*, então:

* o login local falha (não há senha para verificar), e
* o controle **Forçar redefinição de senha** na interface e na API fica bloqueado, com uma mensagem informando que o usuário está autorizado via SSO.

Definir uma senha real resolve as duas condições de uma vez: a conta passa a conseguir fazer login localmente, e a flag de redefinição forçada passa a poder ser definida.

## A solução alternativa

Execute estes passos a partir do shell do Django dentro do container `uwsgi`:

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### Exemplo para um único usuário

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

## O que o usuário faz em seguida

Entregue a senha temporária a cada usuário por um canal separado (e-mail, o chat da sua equipe, ou da forma como você costuma compartilhar segredos). No próximo login, o DefectDojo os redireciona para a página **Alterar senha** e não permite que eles vão a nenhum outro lugar até definirem sua própria senha. A flag de redefinição forçada é limpa automaticamente assim que isso acontece.

Se a sua instância tiver o fluxo "Esqueci minha senha" habilitado (`DD_FORGOT_PASSWORD`, ativado por padrão) e o e-mail configurado, os usuários podem, em vez disso, usar o link **Esqueci minha senha** na página de login depois que a conta tiver uma senha utilizável, e definir uma senha sem precisar da temporária.

## Observações

* **Kubernetes:** execute o shell no pod do Django, por exemplo `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell` (ajuste os nomes do deployment e do container para a sua versão).
* Escolha uma senha temporária forte. Com `force_password_reset = True` o usuário não pode mantê-la, então ela só precisa sobreviver a um login.
* Mantenha pelo menos uma conta de administrador local funcionando para que você nunca fique bloqueado.
