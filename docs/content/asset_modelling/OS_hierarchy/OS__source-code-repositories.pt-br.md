---
title: Vincular Achados ao código-fonte
description: Integração de repositórios para navegar até a localização dos achados
  no código-fonte.
draft: false
weight: 5
audience: opensource
aliases:
- /pt-br/en/working_with_findings/organizing_engagements_tests/source-code-repositories
---

Algumas ferramentas (particularmente ferramentas SAST) incluem o nome do arquivo associado e o número da linha nos dados de vulnerabilidade. Se o repositório do código-fonte for especificado no Engajamento, o DefectDojo apresentará o caminho do arquivo como um link, e o usuário poderá navegar diretamente até a localização da vulnerabilidade.

## Definindo o repositório no Engajamento e no Teste

### Engajamento

Ao editar o Engajamento, os usuários podem definir a URL do repositório específico de Gerenciamento de Código-Fonte (SCM).  **(Na UI do Pro, esse campo pode ser definido em Editar Engajamento > Campos Opcionais > Repositório)**.

Para um Engajamento Interativo, é necessário informar uma URL que especifique a branch:
- para o GitHub - como https://github.com/DefectDojo/django-DefectDojo/tree/dev
![Editar Engajamento (GitHub)](images/source-code-repositories_1.png)
- para o GitLab - como https://gitlab.com/gitlab-org/gitlab/-/tree/master
![Editar Engajamento (Gitlab)](images/source-code-repositories-gitlab_1.png)
- para o BitBucket público - como    (como uma URL de git clone)
![Editar Engajamento (Bitbucket público)](images/source-code-repositories-bitbucket_1.png)
- para o BitBucket standalone/on-premise https://bb.example.com/scm/some-project/some-repo.git ou https://bb.example.com/scm/some-user-name/some-repo.git para o repositório público do usuário (como uma URL de git clone)
![Editar Engajamento (Bitbucket standalone)](images/source-code-repositories-bitbucket-onpremise_1.png)

Para Engajamentos de CI/CD, o hash do commit, a branch/tag e a linha de código podem variar, então você só precisa incluir a URL do repositório.
- para o GitHub - como `https://github.com/DefectDojo/django-DefectDojo`
- para o GitLab - como `https://gitlab.com/gitlab-org/gitlab`
- para o BitBucket público, Gitea e Codeberg - como `https://bitbucket.org/some-user/some-project.git` (como uma URL de git clone)
- para o BitBucket standalone/on-premise `https://bb.example.com/scm/some-project.git` ou `https://bb.example.com/scm/some-user-name/some-repo.git` para o repositório público do usuário (como uma URL de git clone)

Em um Engajamento de CI/CD, você pode especificar um hash de commit ou uma branch/tag no formulário **Editar Engajamento**, que será anexado a todos os links renderizados pelo DefectDojo.  Se esses valores não forem definidos, a URL do SCM precisará conter um link completo que inclua a branch de código.

A URL de navegação do SCM é composta a partir da URL do Repo usando o Tipo de SCM. Um tipo de SCM específico pode ser definido no campo personalizado do Ativo "scm-type". Se nenhum "scm-type" for definido e a URL contiver "https://github.com", será assumido o tipo de SCM "github".

Campos personalizados do Ativo:

![Campos personalizados do Ativo](images/asset-custom-fields_1.png)

Adição do tipo de SCM do Ativo:

![Tipo de SCM do Ativo](images/asset-scm-type_1.png)

Os possíveis tipos de SCM podem ser 'github', 'gitlab', 'bitbucket', 'bitbucket-standalone', 'gitea', 'codeberg' ou nenhum (para o padrão github).


## Links para o código-fonte nos Achados

Ao visualizar um achado, a localização será apresentada como um link, caso o repositório do código-fonte tenha sido definido no Engajamento:

![Link para a localização](images/source-code-repositories_2.png)

Clicar nesse link abrirá uma nova aba no navegador, com o arquivo de origem da vulnerabilidade na linha correspondente:

![Ver no repositório](images/source-code-repositories_3.png)
