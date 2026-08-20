---
title: Modo FIPS 140-3
date: 2026-07-27 00:00:00+00:00
weight: 6
audience: pro
---

O DefectDojo Pro pode ser implantado com criptografia validada FIPS 140-3, para ambientes sujeitos ao controle FedRAMP **SC-13** ou requisitos similares.

O modo FIPS é distribuído como um **conjunto separado de imagens de contêiner**, identificado por um sufixo de tag `-fips`. As imagens padrão permanecem inalteradas: habilitar o FIPS é uma escolha explícita, nunca um padrão silencioso.

Para obter acesso às imagens FIPS, entre em contato conosco em [hello@defectdojo.com](mailto:hello@defectdojo.com).

## O que as imagens FIPS oferecem

Todas as operações criptográficas são realizadas pelo **OpenSSL FIPS Provider 3.1.2**, que possui o certificado NIST CMVP **[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)** sob o FIPS 140-3. Os serviços em Go usam o **Go Cryptographic Module v1.0.0**, certificado CMVP **[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**.

Como a aplicação ocorre **dentro do contêiner**, o modo FIPS não exige que o host execute um kernel habilitado para FIPS. É isso que o torna viável em runtimes de contêiner gerenciados, como o **Amazon ECS com o tipo de execução Fargate**, onde o sistema operacional do host não está sob seu controle.

> **FIPS 140-3, não 140-2.** O FIPS 140-3 substitui o 140-2 e satisfaz um requisito escrito com base nele. Todos os certificados FIPS 140-2 passam para a CMVP Historical List em **21 de setembro de 2026** e deixam de suportar novas implantações após essa data, portanto novos sistemas devem ser validados em relação a um módulo 140-3.

### Cobertura

| Componente | Coberto | Módulo |
|---|:---:|---|
| Aplicação Django (`dojo`) | sim | OpenSSL FIPS Provider 3.1.2 |
| Importação assíncrona (`dojo-import-scan`) | sim | OpenSSL FIPS Provider 3.1.2 |
| Celery worker e beat | sim | OpenSSL FIPS Provider 3.1.2 |
| Inicializador (`init`) | sim | OpenSSL FIPS Provider 3.1.2 |
| Workers de orquestração (`ddorch-workers`) | sim | OpenSSL FIPS Provider 3.1.2 |
| nginx | sim | OpenSSL FIPS Provider 3.1.2 |
| Mecanismo de advisories PSIRT | sim | OpenSSL FIPS Provider 3.1.2 |
| Connectors, Integrators, ddorch, servidor MCP | sim | Go Cryptographic Module v1.0.0 |
| **Sensei** | **parcial** | binários do serviço: Go Cryptographic Module v1.0.0. Toolchain de scanners empacotado: **não coberto** |
| **PostgreSQL / Redis (incorporado)** | **não** | use serviços externos compatíveis com FIPS |

**O Sensei é um caso parcial que vale a pena entender.** Seus próprios binários são compilados com base no módulo Go validado, portanto o TLS e os tokens da API de jobs estão cobertos. A imagem também empacota um toolchain de scanners de terceiros poliglota — Node (que traz seu próprio OpenSSL), Rust (rustls), Python, Ruby e binários Go de terceiros que não compilamos — e vários deles buscam bancos de dados de advisories via TLS usando sua própria criptografia. Esse toolchain não pode ser reunido sob um único módulo validado, portanto não está coberto e não deve ser apresentado como tal a um avaliador.

O PostgreSQL/Redis incorporados não possuem nenhuma variante FIPS. No Kubernetes, o chart se recusa a renderizar se você habilitar o FIPS junto com o Sensei ou os datastores incorporados, de modo que essa contrapartida é uma decisão explícita, e não uma suposição (veja [Guard rails](#guard-rails)).

## Habilitando o modo FIPS — Docker Compose

Duas mudanças: use as imagens `-fips` e defina `DD_FIPS_MODE`.

**1. Aponte as tags de imagem para as variantes FIPS.** No seu `.env` ou override do compose:

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. Defina `DD_FIPS_MODE` nas âncoras de ambiente compartilhadas.** O arquivo compose define blocos compartilhados que cada serviço relevante mescla, portanto são três edições em vez de uma por serviço:

```yaml
x-dojo-vars: &dojoenv
  DD_FIPS_MODE: "1"        # dojo, dojo-import-scan, celerybeat, celeryworker, init, ddorch-workers
  # ... existing settings

x-nginx-vars: &nginxenv
  DD_FIPS_MODE: "1"        # nginx
  # ... existing settings

x-psirt-vars: &psirtenv
  DD_FIPS_MODE: "1"        # psirt
  # ... existing settings
```

Em seguida, recrie o stack:

```bash
docker compose up -d --force-recreate
```

## Habilitando o modo FIPS — Kubernetes (Helm)

Defina um único valor. O chart seleciona as variantes de imagem `-fips` e define `DD_FIPS_MODE` para todos os pods:

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

Como os datastores incorporados não possuem variante FIPS e o Sensei está apenas parcialmente coberto, uma instalação FIPS deve usar PostgreSQL e Redis externos, e deixar o Sensei desabilitado, a menos que você aceite a ressalva acima:

```yaml
fips:
  enabled: true
sensei:
  enabled: false          # partial coverage — see the table above
postgresql:
  enabled: false          # use an external FIPS-compliant database
redis:
  enabled: false          # use an external FIPS-compliant cache
```

Se você precisar do Sensei em um ambiente FIPS, habilite-o deliberadamente com
`fips.validate: false` e documente o toolchain de scanners empacotado como
não validado em seu plano de segurança do sistema.

### Guard rails

Se `fips.enabled` for verdadeiro enquanto um componente sem variante FIPS também estiver habilitado, **o chart se recusa a renderizar** e identifica os componentes responsáveis:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

Isso é proposital. Uma implantação em que a maioria dos serviços usa criptografia validada e um ou dois não usam silenciosamente é pior do que uma falha óbvia: parece estar em conformidade, sobrevive a uma inspeção casual e só é percebida durante uma avaliação. Se você aceitou esse risco por escrito, sobrescreva com `fips.validate: false`.

## Habilitando o modo FIPS — Amazon ECS / Fargate

O Fargate é um tipo de execução (launch type) do ECS, não um serviço separado: você registra definições de tarefa do ECS com `requiresCompatibilities: ["FARGATE"]` e `networkMode: awsvpc`.

Se você já executa o DefectDojo Pro no ECS, apenas duas coisas mudam:

**1. As tags de imagem** ganham o sufixo `-fips`:

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2. `DD_FIPS_MODE=1`** no bloco `environment` de todos os contêineres que executam
código de aplicação — uwsgi, celery worker, celery beat, o inicializador, os
workers de orquestração, nginx e psirt.

O restante desta seção é uma implantação completa no ECS com FIPS habilitado, para leitores
que estão começando do zero.

### O que provisionar primeiro

| Recurso | Observações |
|---|---|
| VPC com duas subnets | Subnets privadas mais um NAT gateway, ou subnets públicas com `assignPublicIp: ENABLED` |
| RDS for PostgreSQL | Use um endpoint compatível com FIPS e documente-o como um componente herdado |
| ElastiCache for Redis | São usados dois bancos de dados lógicos: `/0` para o broker do Celery, `/1` para o cache |
| Sistema de arquivos EFS | Dois diretórios: um para `/app/media`, outro contendo os certificados TLS do nginx |
| Entradas do Secrets Manager | URL do banco de dados, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY` e sua licença Pro |
| Application Load Balancer | Listener HTTPS, encaminhando para um target group **HTTPS** na porta **8443** |
| Repositórios ECR | Contendo as duas imagens `-fips` |
| Funções (roles) IAM | Uma execution role que possa fazer pull do ECR, gravar logs e ler esses secrets, além de uma task role |
| Grupo de logs do CloudWatch | Referenciado pela configuração `awslogs` de cada contêiner |

Coloque o certificado e a chave TLS no EFS como `dojo.crt` / `dojo.key`, além de
`nginx_int.crt` / `nginx_int.key`. Os dois pares precisam existir — veja
[Três coisas que o ECS precisa](#three-things-ecs-needs-that-compose-provides-for-free)
abaixo para entender o motivo.

### 1. A tarefa do inicializador (executada uma vez por upgrade)

Aplica as migrations e popula os dados de primeira inicialização, depois encerra. É uma tarefa (task), não um
serviço.

```json
{
  "family": "defectdojo-pro-init",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "init",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-initializer.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_INITIALIZE", "value": "true" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" },
        { "name": "DD_ADMIN_USER", "value": "admin" },
        { "name": "DD_ADMIN_MAIL", "value": "admin@example.com" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_ADMIN_PASSWORD", "valueFrom": "<SECRET_ARN_ADMIN_PASSWORD>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "init"
        }
      }
    }
  ]
}
```

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-init.json
aws ecs run-task --cluster <CLUSTER> --launch-type FARGATE \
  --task-definition defectdojo-pro-init \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}"
```

Aguarde até que ela alcance o status `STOPPED` com código de saída 0 antes de iniciar os serviços.

### 2. O serviço web (nginx + uwsgi)

Os dois contêineres residem em uma única tarefa, de modo que o nginx alcança o uwsgi em `127.0.0.1`.

```json
{
  "family": "defectdojo-pro-web",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "volumes": [
    {
      "name": "media",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/media"
      }
    },
    {
      "name": "certs",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/nginx-certs"
      }
    }
  ],
  "containerDefinitions": [
    {
      "name": "uwsgi",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_UWSGI_ENDPOINT", "value": "0.0.0.0:3031" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "mountPoints": [{ "sourceVolume": "media", "containerPath": "/app/media" }],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "uwsgi"
        }
      }
    },
    {
      "name": "nginx",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips",
      "essential": true,
      "dependsOn": [{ "containerName": "uwsgi", "condition": "START" }],
      "portMappings": [{ "containerPort": 8443, "protocol": "tcp" }],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "USE_TLS", "value": "false" },
        { "name": "GENERATE_TLS_CERTIFICATE", "value": "false" },
        { "name": "DD_UWSGI_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_PORT", "value": "3031" },
        { "name": "DD_UWSGI_IMPORT_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_IMPORT_PORT", "value": "3031" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
        { "name": "DD_MCP_PORT", "value": "9142" },
        { "name": "PSIRT_ENABLED", "value": "false" },
        { "name": "NGINX_METRICS_ENABLED", "value": "false" }
      ],
      "mountPoints": [
        { "sourceVolume": "certs", "containerPath": "/etc/nginx/certs", "readOnly": true }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "nginx"
        }
      }
    }
  ]
}
```

`USE_TLS=false` seleciona a configuração on-prem, que termina o TLS internamente na
porta 8443 usando os certificados montados. Registre-a e crie um serviço vinculado ao
load balancer:

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. O serviço de workers (Celery worker e beat)

Mesma imagem e mesmos secrets do uwsgi; o entry point seleciona o processo. Execute
exatamente **uma** réplica de beat.

```json
{
  "family": "defectdojo-pro-worker",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "celeryworker",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-worker.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celeryworker"
        }
      }
    },
    {
      "name": "celerybeat",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-beat.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celerybeat"
        }
      }
    }
  ]
}
```

### 4. Confirme que a implantação está usando criptografia validada

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

Todo contêiner deve reportar o módulo antes de atender a qualquer requisição:

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

Se um contêiner estiver ausente nessa saída, ele nunca chegou a iniciar, pois a verificação
falha de forma fechada (fail closed) — consulte o log stream desse contêiner para saber o motivo.

### Three things ECS needs that Compose provides for free

O Docker Compose oferece um sistema de arquivos do host para fazer bind-mount e DNS para
nomes de contêiner. O Fargate não oferece nenhum dos dois, e cada lacuna impede o nginx de
iniciar, em vez de degradar silenciosamente.

**1. Os certificados TLS precisam existir antes de o nginx iniciar.** O nginx valida cada
`ssl_certificate` no carregamento da configuração, e a configuração on-prem não tem
nenhum caminho sem certificado: a porta 8080 apenas emite um `301` para HTTPS, portanto o listener
TLS 8443 é o funcional. Monte um volume **EFS** em `/etc/nginx/certs`
contendo `dojo.crt` / `dojo.key` e `nginx_int.crt` / `nginx_int.key`. Os dois
pares precisam estar presentes mesmo que você use apenas um listener.

Como alternativa, defina `USE_TLS=true`, que serve o `nginx_TLS.conf` upstream e
permite que `GENERATE_TLS_CERTIFICATE=true` faça o entrypoint gerar seu próprio
certificado. Essa configuração encaminha (proxy) todos os caminhos para o Django e não serve
a UI em Vue a partir de `/ui`, portanto é adequada para uma implantação somente de API ou estritamente atrás de um ALB.

**2. `DD_MCP_HOST` precisa ser resolvível.** O nginx resolve os hostnames de `proxy_pass` no
carregamento da configuração. O valor padrão `mcp-server` é resolvido sob o Compose (nome do contêiner) e
o Helm (nome do Service), mas o `awsvpc` não dá aos contêineres nomes DNS próprios e
rejeita tanto `extraHosts` quanto `dnsSearchDomains`:

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

Apontá-lo para loopback quando o servidor MCP não está implantado faz com que `/mcp` responda
`502` em vez de impedir que toda a camada web seja iniciada.

**3. Os arquivos de configuração do nginx vêm da imagem.** A imagem `-fips` do nginx
já traz embutido o conjunto de configuração on-prem, portanto nenhum mount é necessário. O Compose sobrepõe
seus próprios bind mounts, portanto o comportamento do Compose permanece inalterado.

### Outras particularidades do Fargate

- **O armazenamento persistente precisa ser EFS.** O Fargate não pode anexar EBS, portanto o diretório
  de mídia (`/app/media`) precisa de um volume EFS se você mantiver os arquivos de scan enviados.
- **Não são necessários contêineres privilegiados nem host networking.** As imagens são executadas
  como um usuário não root, e o `awsvpc` dá a cada tarefa sua própria interface de rede.
- **nginx → uwsgi.** Contêineres na *mesma* tarefa compartilham um namespace de rede, portanto
  colocar o nginx junto com o uwsgi permite que o nginx o alcance em `127.0.0.1` — a opção mais simples
  e correta. Se você os separar em serviços ECS distintos, aponte
  `DD_UWSGI_HOST` para um nome de service discovery do Cloud Map e abra o security
  group na porta do uwsgi.
- **Não sobrescreva o entrypoint do uwsgi.** Defina
  `DD_UWSGI_ENDPOINT=0.0.0.0:3031` e deixe o ENTRYPOINT da imagem como está;
  o uwsgi fala o protocolo uwsgi, que é o que o nginx espera. Substituir o
  entrypoint por `uwsgi --http` pula também a verificação de inicialização do FIPS.
- **O inicializador é uma tarefa única (one-shot)**, não um serviço. Execute-o com
  `aws ecs run-task` (ou como uma etapa pré-deploy) e deixe-o encerrar; não atribua a ele um
  desired count.
- **`healthCheck.retries` não pode exceder 10.** Valores mais altos são rejeitados quando
  a task definition é registrada.
- **Aponte o load balancer para a porta 8443** com um target group HTTPS. O listener 8080
  da configuração on-prem apenas redireciona para HTTPS, portanto apontar para 8080 gera um loop.
  Um certificado autoassinado no target é aceitável para um ALB.
- **Terminação de TLS.** Se o ALB terminar o TLS para os clientes, documente a postura FIPS
  do próprio load balancer separadamente no seu SSP.
- **Secrets** devem ficar no Secrets Manager ou no SSM Parameter Store, por meio do
  bloco `secrets`, nunca em `environment`. Isso inclui `DD_LICENSE`.

### Coletando evidências no ECS

O bloco de evidência de inicialização é enviado ao log group nomeado pela configuração
`awslogs` do contêiner:

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

Sob demanda, dentro de uma tarefa em execução (requer `enableExecuteCommand` habilitado no serviço):

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## Inicialização fail-closed

Com `DD_FIPS_MODE` definido, cada contêiner verifica na inicialização se o provedor validado está carregado e se os algoritmos não aprovados são de fato recusados. **Se essa verificação falhar, o contêiner encerra em vez de iniciar.**

Mesmo raciocínio do guard rail do chart: um contêiner que silenciosamente recorresse a criptografia não validada continuaria atendendo tráfego enquanto comprometia sua postura de conformidade, e isso só seria descoberto em uma avaliação.

## Verificando o modo FIPS

Cada contêiner imprime um bloco de evidência na inicialização, que costuma ser a forma mais conveniente para um avaliador. Em runtimes gerenciados, ele chega ao seu agregador de logs:

```
================================================================
[FIPS] DefectDojo Pro FIPS mode verification
Providers:
  fips
    name: OpenSSL FIPS Provider
    version: 3.1.2
    status: active
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
================================================================
```

Recupere-o com:

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

Você também pode verificar sob demanda dentro de um contêiner em execução:

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

Para os serviços em Go, o modo FIPS é compilado no binário e reportado pelo runtime do Go:

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## Diferenças de comportamento no modo FIPS

Alguns algoritmos não aprovados ficam indisponíveis, portanto alguns comportamentos mudam. Estes são os que vale a pena planejar.

### Hashing de senhas

As builds FIPS usam **PBKDF2-SHA256** como hasher de senha padrão. Argon2, bcrypt e scrypt não são funções de derivação de chave aprovadas pelo FIPS e ficam desabilitadas.

Os usuários existentes não ficam bloqueados. O Django faz o rehash de cada senha para PBKDF2 no próximo login bem-sucedido do usuário, e os hashes PBKDF2-SHA1 continuam verificáveis durante a transição. Se preferir uma transição abrupta, force uma redefinição de senha em vez de depender da migração gradual.

### Conjuntos de cifras TLS

O ChaCha20-Poly1305 não é aprovado pelo FIPS e é removido de toda configuração do nginx que termina TLS, e o TLS 1.3 fica fixado em `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`. O TLS 1.2 e o TLS 1.3 continuam disponíveis usando conjuntos AES-GCM. Clientes que suportam apenas ChaCha20 não conseguirão se conectar.

O módulo validado recusaria o ChaCha20 de qualquer forma; removê-lo da configuração significa que o servidor nunca anuncia um conjunto que não consegue concluir, o que mantém a configuração implantada autoexplicativa para um avaliador.

### Autenticação básica de métricas

Quando a autenticação de métricas do nginx está habilitada, o hash de senha usa SHA-256 crypt em vez do formato MD5 da Apache (`apr1`), que o módulo validado recusa. Isso é transparente, a menos que você mesmo gere as entradas de `.htpasswd`, caso em que deve usar `openssl passwd -5`.

### Parsers de scan

Alguns parsers usam MD5 para construir chaves de deduplicação. Esse é um uso não relacionado à segurança e é explicitamente anotado como tal, portanto esses parsers continuam funcionando normalmente sob FIPS. Nenhuma funcionalidade de parser é perdida.

## Notas de implantação

- **Terminação de TLS.** Se o TLS terminar em um load balancer na frente do DefectDojo, esse dispositivo é responsável por sua própria postura FIPS e deve ser documentado separadamente no seu plano de segurança do sistema. A imagem `-fips` do nginx cobre o TLS terminado pelo próprio DefectDojo.
- **Banco de dados e cache.** PostgreSQL e Redis são produtos separados. Em um ambiente FIPS, use instâncias compatíveis com FIPS — por exemplo, um banco de dados gerenciado que ofereça um endpoint FIPS — e documente-os como componentes herdados.
- **Escopo de conformidade.** O DefectDojo em si não é um módulo criptográfico e não possui certificado próprio. O que essas imagens oferecem é criptografia validada realizada por módulos que a possuem, sendo executados em modo aprovado pelo FIPS. Seu avaliador vai querer os nomes dos módulos e os números de certificado, que aparecem na saída de evidência acima.
