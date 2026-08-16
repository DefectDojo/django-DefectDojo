---
title: Implantando o DefectDojo Pro no OpenShift
description: 'O que é específico do OpenShift ao implantar o DefectDojo Pro autogerenciado:
  security context constraints, Routes e armazenamento ReadWriteMany'
draft: false
weight: 8
audience: pro
---

O DefectDojo Pro roda no OpenShift 4.x, incluindo OpenShift Container Platform, ROSA e OKD.

Esta página é um complemento ao guia de instalação fornecido com sua licença do DefectDojo Pro. Esse guia contém o procedimento completo, incluindo uma seção dedicada ao OpenShift. Esta página aborda o que é diferente no OpenShift, para que você saiba o que precisa ter preparado antes de começar e o que esperar das configurações específicas da plataforma.

Um script de bootstrap para o OpenShift é fornecido junto com os materiais da sua licença. Ele instala em um cluster existente e cuida da maior parte do que esta página descreve, incluindo o armazenamento, o valor de `fsGroup`, a Route e a própria instalação. Ele é idempotente, então executá-lo novamente reaproveita o que já foi criado, e ele oferece um modo de ensaio (dry run) que exibe o que seria feito sem alterar nada. O restante desta página se aplica tanto se você usar esse script quanto se você fizer a instalação manualmente.

## Security context constraints

O DefectDojo Pro roda sob a SCC padrão `restricted-v2`. Não é necessário conceder `anyuid`, `privileged`, ou qualquer outra SCC elevada, à conta de serviço.

Quando configurado para o OpenShift, o DefectDojo Pro roda inteiramente com security contexts não privilegiados. Os containers rodam sem privilégios, não podem escalar privilégios e descartam todas as capabilities. O ID de usuário é deixado para o OpenShift atribuir a partir do intervalo alocado ao seu namespace, em vez de ser fixado em um UID fixo que a SCC rejeitaria.

Se os pods forem rejeitados por falha na validação da SCC, a causa mais comum é que a implantação não foi configurada para o OpenShift, e não que seja necessário conceder alguma constraint.

## O armazenamento precisa ser ReadWriteMany

Os pods do Django e do worker do Celery leem e gravam os mesmos arquivos de mídia, que são os scans enviados, capturas de tela e relatórios gerados. Eles precisam de um volume compartilhado, então o armazenamento ReadWriteOnce não é suficiente para uma implantação multi-node.

No OpenShift, o padrão é um PersistentVolumeClaim contra a StorageClass padrão do cluster. Isso funciona quando a classe padrão provisiona ReadWriteMany, o que é típico em clusters sustentados por OpenShift Data Foundation ou NFS. Para implantações multi-node em que a classe padrão é ReadWriteOnce, configure armazenamento baseado em NFS.

### fsGroup em armazenamento baseado em NFS

O OpenShift restringe o `fsGroup` ao intervalo alocado ao namespace. Quando você usa armazenamento NFS ou EFS, é preciso fornecer um valor dentro desse intervalo, ou a montagem do volume falha com um erro de permissão.

Leia o início do intervalo a partir da anotação do namespace e use-o como o seu `fsGroup`:

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

A anotação contém um intervalo escrito como um valor inicial e um comprimento. Use o valor inicial. Isso só é necessário para armazenamento NFS e EFS, não para o caminho padrão de PersistentVolumeClaim.

## Routes, TLS e cookies

No OpenShift, o DefectDojo Pro é exposto através de uma Route em vez de um Ingress, com terminação de TLS na borda (edge) e redirecionamento a partir de HTTP.

No ROSA, os hostnames das Routes são gerados como `<release-name>-<namespace>.apps.<cluster-domain>`, então um release `dojopro` no namespace `dojopro` recebe `dojopro-dojopro.apps.<cluster-domain>`. Obtenha o domínio de apps do cluster com:

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

Um hostname sob o domínio de apps do cluster é coberto pelo certificado wildcard padrão e não precisa de nenhuma configuração de certificado. Para qualquer outro hostname, forneça seu próprio certificado e adicione um CNAME apontando para o hostname da Route.

Defina `dojo.secureCookies` como `false` no OpenShift. Com uma Route com terminação de TLS na borda, o TLS termina no roteador e a conexão do roteador até o pod é HTTP simples, então cookies marcados como secure nunca são enviados de volta e o login falha. Isso é obrigatório, não opcional, sempre que a Route terminar o TLS na borda.

## Perfis de recursos

Três perfis de recursos estão disponíveis, e você seleciona um no momento da instalação. `minimal` é para desenvolvimento, CI e testes. `standard` é para produção sob carga moderada. `performance` é para produção com alta carga e habilita o autoscaling.

Defina o dimensionamento por meio do perfil, em vez de sobrescrever valores individuais, para que seu próprio arquivo de configuração não entre em conflito com ele.

## Antes de começar

Um cluster OpenShift 4.x no qual você esteja autenticado, com `oc`, `helm`, `openssl` e `jq` disponíveis localmente.

Um namespace, e o valor da sua anotação supplemental-groups caso você esteja usando armazenamento NFS ou EFS.

Uma StorageClass padrão que provisiona ReadWriteMany, ou os detalhes de um servidor NFS.

PostgreSQL 16 para qualquer uso além de avaliação. Um PostgreSQL embutido está disponível para desenvolvimento, mas migre para um banco de dados gerenciado externo antes de rodar em produção.

Seu arquivo de licença do DefectDojo Pro.

O hostname de Route pretendido.

## Acesso de rede de saída

Em um cluster com restrições de egress, permita HTTPS de saída na porta 443 para o registro de containers que hospeda as imagens do DefectDojo Pro. O hostname do registro está no guia de instalação fornecido com sua licença. Os endpoints do registro ficam atrás de load balancers e seus endereços mudam, então libere o hostname, e não um endereço fixo.

O cluster também precisa conseguir alcançar o seu banco de dados na porta do PostgreSQL.

O enriquecimento de exploitability é opcional e precisa de mais dois destinos via HTTPS na porta 443. As pontuações EPSS vêm de `api.first.org`, e os dados do CISA KEV vêm de `www.cisa.gov`. Ambos são servidos por content delivery networks cujos endereços mudam, então libere os hostnames. Sem eles, o DefectDojo funciona normalmente e os achados não são enriquecidos com dados de EPSS ou KEV.

Quando o tráfego de saída passa por um proxy em vez de ser direto, consulte [Executando o DefectDojo Atrás de um Forward HTTPS Proxy](/onprem_deployment/forward_proxy/).

## O job initializer precisa terminar primeiro

A instalação executa um job do Kubernetes que aplica as migrações, cria o usuário admin e carrega os dados iniciais. Isso leva cerca de quinze minutos. Até que termine, o usuário admin não existe e você não consegue fazer login, mesmo que a Route já esteja respondendo.

Acompanhe-o:

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

O job está concluído quando `oc get job` reporta `1/1` completions.

Os outros pods aguardam o initializer por meio de um init container. Depois que o banco de dados tiver sido inicializado, você pode definir `dojo.skipInitContainer` como `true` para pular essa espera em upgrades subsequentes.

## Verificando

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

Em seguida, abra o hostname da Route e faça login.

## Solução de problemas

### Pods rejeitados por security context constraints

É provável que a implantação não tenha sido configurada para o OpenShift, então ela caiu de volta para padrões que fixam um ID de usuário que a SCC não permite. Conceder `anyuid` ou `privileged` não é a solução e não é necessário.

### O login redireciona de volta para a página de login

`dojo.secureCookies` está como `true` atrás de uma Route com terminação de TLS na borda. Defina-o como `false` e faça o upgrade.

### Erros de permissão na montagem de volume em NFS

O `fsGroup` está fora do intervalo permitido pelo namespace. Leia a anotação supplemental-groups e use o início do intervalo.

### Erros Multi-Attach, ou pods travados em ContainerCreating

O volume é ReadWriteOnce e mais de um pod está tentando montá-lo. Verifique o claim e a classe por trás dele:

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

Migre para uma classe ReadWriteMany, ou para armazenamento baseado em NFS.

### Avisos de certificado no navegador

O TLS padrão da Route usa o certificado wildcard do cluster, que cobre apenas nomes sob o domínio de apps do cluster. Para qualquer outro hostname, forneça seu próprio certificado.

### Lendo logs

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

Para uma saída mais detalhada, tanto `config.logLevel` quanto `celery.logLevel` aceitam `DEBUG`.

## Fazendo upgrade

Os upgrades seguem o procedimento padrão. Consulte [Atualizando o DefectDojo Pro (on-premise)](/get_started/pro/onprem/upgrading/).

## Dúvidas ou suporte

Para obter ajuda com uma implantação no OpenShift, entre em contato com o seu representante de conta ou com [support@defectdojo.com](mailto:support@defectdojo.com).
