---
title: Guia de Instalação do DefectDojo Pro
description: Instale o DefectDojo Pro no Kubernetes usando o Helm chart, abrangendo
  infraestrutura, segredos e a instalação em si
draft: false
weight: 13
audience: pro
---

<!--
  Gerado a partir do repositório do Helm chart do DefectDojo Pro.
  Fonte: docs/INSTALLATION_GUIDE.md na versão do chart 3.1.304.
  Edite o guia de origem, não este arquivo. Edições locais são substituídas
  na próxima vez que o chart for lançado.
-->
Cobre a implantação no AWS EKS e no OpenShift (ROSA). O fluxo de trabalho é o mesmo
para ambos: configurar a infraestrutura, criar os segredos e instalar o chart.

---

## Pre-Install Checklist

Reúna as informações a seguir antes de começar. Tê-las prontas evita
atrasos durante o processo de instalação.

### Infrastructure Details

| Item | Exemplo | Onde encontrar |
|------|---------|-------------------|
| **Host do PostgreSQL** | `mydb.abc123.us-east-1.rds.amazonaws.com` | Console do AWS RDS ou `aws rds describe-db-instances` |
| **Porta do PostgreSQL** | `5432` | Geralmente 5432, a menos que personalizada |
| **Nome do banco de dados PostgreSQL** | `dojodb` | Seu DBA ou saídas do Terraform/CloudFormation — deve ser criado antes da instalação (veja a nota abaixo) |
| **Banco de dados do orquestrador** | `dojodb-ddorch` | Conceda à role da aplicação a permissão `CREATEDB` ou pré-crie `<dbname>-ddorch` — veja [Pré-checagem: banco de dados do orquestrador (ddorch)](#pre-flight-orchestrator-ddorch-database) |
| **Nome de usuário do PostgreSQL** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **Senha do PostgreSQL** | — | AWS Secrets Manager, estado do Terraform ou seu DBA |
| **Endpoint do Redis/ElastiCache** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Senha do Redis** | — | Omita se a autenticação estiver desativada (somente VPC). Verifique: `aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **ID do sistema de arquivos EFS** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **ID do access point do EFS** (se aplicável) | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **UID/GID do access point do EFS** | UID `1001`, GID `1337` | Deve corresponder ao security context do container (veja a nota abaixo) |
| **Nome de domínio (FQDN)** | `dojo.example.com` | Seu administrador de DNS (veja as notas específicas de plataforma abaixo) |
| **ARN do certificado ACM** (EKS com HTTPS) | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **Domínio de apps do OpenShift** (somente ROSA) | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **fsGroup do namespace do OpenShift** (somente ROSA) | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'` — use o valor inicial |
| **Arquivo de licença** | `onprem-dojopro.lic` | Fornecido pelo suporte do DefectDojo |

> **Crie os bancos de dados antes de instalar.** O chart não cria
> bancos de dados em um servidor PostgreSQL externo. Crie os dois bancos a seguir
> no seu servidor de banco de dados, de propriedade do usuário da aplicação, antes de executar
> `helm install`:
>
> - `dojodb` — o banco de dados principal do DefectDojo
> - `dojodb-ddorch` — o banco de dados do orquestrador (ddorch), sempre nomeado a partir
>   do banco principal com o sufixo `-ddorch`. Alternativamente, conceda à
>   role da aplicação a permissão `CREATEDB` e o ddorch cria esse banco sozinho na primeira
>   inicialização.
>
> Veja [Pré-checagem: verificar conectividade do banco de dados](#pre-flight-verify-database-connectivity)
> e [Pré-checagem: banco de dados do orquestrador (ddorch)](#pre-flight-orchestrator-ddorch-database)
> para comandos `CREATE DATABASE` prontos para executar.

> **UID/GID do access point do EFS:** Se o seu sistema de arquivos EFS usa um access point,
> sua configuração de usuário POSIX **deve** usar UID `1001` e GID `1337` para corresponder
> ao security context do container do DefectDojo. Uma incompatibilidade causa erros de `Permission
> denied` durante a inicialização, quando os containers tentam criar
> subdiretórios de mídia. Verifique com:
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **FQDN do OpenShift/ROSA:** No ROSA, as Routes geram automaticamente hostnames usando o
> padrão `<release-name>-<namespace>.apps.<cluster-domain>`. Por exemplo, se
> seu release é `dojopro` no namespace `dojopro`, o hostname da Route será
> `dojopro-dojopro.apps.abc123.p1.openshiftapps.com`. Determine o domínio de apps
> do seu cluster com:
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```
>
> Use o FQDN resultante para `dojo.fqdn`, `dojo.url` e `dojo.hosts.main`.

> **fsGroup do OpenShift/ROSA:** Você precisará do valor inicial de supplemental-groups
> do seu namespace para `securityContext.openshift.fsGroup`. Consulte isso agora para evitar
> ter que editar seu arquivo de values depois:
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### Secrets to Generate

Os segredos a seguir devem ser gerados novos para a sua implantação. Use os
comandos mostrados para criar valores criptograficamente aleatórios:

| Segredo | Chave no Secret do K8s | Gerar com |
|--------|-------------------|---------------|
| Chave secreta do Django | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| Chave de criptografia AES-256 | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| Segredo do cloud portal | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| Segredo compartilhado dos connectors | `DD_CONNECTORS_SHARED_SECRET` | Use o mesmo valor de `CLOUD_PORTAL_SECRET_KEY` |
| Senha do admin | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| Senha de métricas | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### Secrets from Your Infrastructure

Estes vêm da sua infraestrutura existente — não os gere:

| Segredo | Chave no Secret do K8s | Origem |
|--------|-------------------|--------|
| Senha do banco de dados | `DD_DATABASE_PASSWORD` | Sua senha do PostgreSQL |
| URL de conexão do banco de dados | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Senha do Redis | `redis-password` (em um secret `dojopro-redis` separado) | Sua senha do Redis, ou pule se não houver autenticação |
| URL do serviço de e-mail | `DD_EMAIL_URL` | `consolemail://` para testes, ou sua URL SMTP |

### Optional (leave empty to disable)

| Segredo | Chave no Secret do K8s | Finalidade |
|--------|-------------------|---------|
| Chave do bucket EPSS | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | Enriquecimento do score EPSS |

> **Dica:** Copie `secrets-template.yaml` e preencha os valores acima. Veja
> [Gerar Segredos](#generate-secrets) para instruções detalhadas sobre como criar
> o Secret do Kubernetes.

---

## Prerequisites

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

Para OpenShift/ROSA, instale também:
```bash
brew install rosa openshift-cli
```

### Outbound Connectivity Requirements

Em ambientes de rede restritos, as seguintes conexões de saída devem ser
permitidas antes da instalação. Regras de firewall podem exigir solicitações
de mudança com antecedência — verifique se estão em vigor antes de prosseguir.

**Container Registry (Required)**

Todos os nós do cluster devem conseguir alcançar o registro de containers do DefectDojo na porta 443:

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> Para ambientes air-gapped, veja
> [Registro Privado / Ambientes Air-Gapped](#private-registry-air-gapped-environments).

**Database (Required)**

Nós do cluster até sua instância PostgreSQL, geralmente na porta 5432.

- RDS na mesma VPC: garanta que o security group do nó do EKS tenha entrada
  permitida na porta 5432
- RDS em uma VPC ou conta diferente: é necessário VPC peering ou Transit Gateway
- Externo/on-premises: o caminho de VPN ou Direct Connect deve permitir a porta 5432

**EPSS Updates (Recommended)**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**KEV Feed (Recommended)**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**AWS Services (EKS only, Required)**

O driver EBS CSI e o ALB Controller exigem acesso a endpoints da API da AWS na
porta 443:

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com` (se estiver usando EFS)

### AWS EKS Prerequisites

Os componentes a seguir devem estar instalados no seu cluster EKS antes de implantar
o DefectDojo Pro. A implantação falhará sem eles.

**EBS CSI Driver** (necessário somente ao usar o perfil mínimo com PostgreSQL e Redis
embutidos — não é necessário se você estiver usando RDS e ElastiCache externos):

```bash
# Associate IAM OIDC provider
eksctl utils associate-iam-oidc-provider \
  --cluster <your-cluster> --region <region> --approve

# Create IAM role for EBS CSI
eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EBS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-ebs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EBS_CSI_DriverRole \
  --force
```

**EFS CSI Driver** (necessário ao usar armazenamento EFS — o backend de armazenamento
recomendado para implantações multi-réplica no EKS):

```bash
# Create IAM role for EFS CSI
eksctl create iamserviceaccount \
  --name efs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EFS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-efs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EFS_CSI_DriverRole \
  --force
```

**AWS Load Balancer Controller** (necessário para ingress ALB):

As instruções de instalação variam de acordo com a versão do EKS. Siga o
[guia oficial de instalação do AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/).

---

## Extract the Chart Package

O chart é distribuído como um zip contendo um pacote Helm `.tgz`. Extraia ambos antes
de prosseguir. Use um caminho de extração versionado para evitar sobrescrever
silenciosamente os presets ao extrair uma versão mais nova do chart posteriormente:

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

Defina uma variável `CHART` apontando para o diretório do chart extraído. Todos
os comandos `helm` subsequentes neste guia usam `$CHART`:

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **Por que a extração é necessária para usuários de CLI:** Os arquivos de preset
> (`presets/platforms/*.yaml`, `presets/profiles/*.yaml`) estão empacotados dentro do
> pacote `.tgz`. O `helm install -f` exige arquivos no sistema de arquivos local — ele
> não consegue ler arquivos de dentro de um `.tgz` empacotado. Você deve extrair o chart
> para acessar os presets.
>
> **Usuários do ArgoCD não precisam extrair.** O ArgoCD lê `valueFiles` diretamente
> de dentro do pacote do chart. Veja [Implantar com ArgoCD](#deploy-with-argocd).

---

## Prepare Your Values File

O template de configuração do cliente (`template.yaml`) e o template de segredos
(`secrets-template.yaml`) estão disponíveis separadamente no portal de suporte do
DefectDojo, ou em support@defectdojo.com. Eles não estão incluídos no `.tgz` do
chart. Depois de obter o template, copie-o e preencha seus dados:

```bash
cp template.yaml my-company.yaml
```

No mínimo, defina:

| Configuração | Descrição |
|---------|-------------|
| `dojo.fqdn` | Seu nome de domínio (ROSA: veja a [nota sobre FQDN](#infrastructure-details) acima) |
| `dojo.url` | URL completa incluindo o protocolo (ex.: `https://dojo.example.com`) |
| `dojo.hosts.main` | Deve corresponder ao seu FQDN |
| `dojo.secureCookies` | Defina como `false` no **OpenShift/ROSA** (veja o aviso abaixo) |
| `dojo.admin.*` | `user`, `email`, `firstName`, `lastName` — conta de admin |
| `database.host`, `.port`, `.name`, `.user` | Detalhes de conexão do PostgreSQL (a senha vai nos segredos) |
| `celery.broker.host` | Seu endpoint do Redis/ElastiCache |
| `redis.enabled` | **Deve ser `false`** ao usar Redis externo (veja o aviso abaixo) |
| `storage.type` | Backend de armazenamento — veja as notas específicas de plataforma |
| `certificates.*` | Configuração de certificado TLS |
| `django.ingress.*` ou `django.route.*` | Ingress (EKS) ou Route (OpenShift) — o preset define os padrões |
| `securityContext.openshift.fsGroup` | **Somente ROSA** — valor inicial de supplemental-groups do namespace |

> **AVISO — `redis.enabled` deve ser explicitamente definido como `false` ao usar
> Redis/ElastiCache externo.** Os presets de perfil `standard` e `performance`
> definem `redis.enabled: true` por padrão. Se seu arquivo de values não sobrescrever
> isso, o chart implantará um Redis dentro do cluster **junto com** o seu broker
> externo, resultando em uma configuração quebrada. Adicione isto ao seu arquivo de values:
>
> ```yaml
> redis:
>   enabled: false
> ```

> **AVISO — `dojo.secureCookies` deve ser `false` no OpenShift/ROSA.** Ao usar
> Routes do OpenShift com terminação TLS edge, `secureCookies: true`
> (o padrão em `template.yaml`) causa loops de redirecionamento e falhas no login.
> Isso não é opcional — Routes com terminação edge exigem:
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**Notas sobre armazenamento:**
- **EKS:** Use EFS — não EBS. Volumes EBS não podem ser compartilhados entre nós,
  causando erros de `Multi-Attach`. Veja [Problemas Conhecidos](#known-issues-chart-version-2.57.1).
  Se o seu EFS usar um access point, defina também `storage.efs.accessPointId` —
  veja [Access Points do EFS](#efs-access-points).
- **OpenShift/ROSA:** O preset da plataforma usa por padrão `storage.type: "pvc"` com
  `createNew: true`, que usa a StorageClass padrão do cluster. Para
  implantações multi-nó, use NFS via EFS (`storage.type: "nfs"`).

Opcionalmente, defina a verbosidade de log:
- `config.logLevel` — nível de log da aplicação Django (padrão: `"INFO"`)
- `celery.logLevel` — nível de log do worker/beat do Celery (padrão: `"INFO"`)

Defina qualquer um deles como `"DEBUG"` para solução de problemas. Veja [Verbosidade de Log](#log-verbosity)
para saber como alternar isso em tempo de execução sem editar seu arquivo de values.

Não coloque segredos ou conteúdo de licença neste arquivo. Isso é tratado nas
próximas duas seções.

Veja `template.yaml` para a lista completa de opções.

### Pre-flight: Verify Database Connectivity

Confirme que seu banco de dados está acessível antes de prosseguir — isso economizará
tempo significativo de solução de problemas depois. Suba um pod temporário com `psql`:

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

Uma conexão bem-sucedida se parece com:

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

Se isso falhar com `database "dojodb" does not exist`, sua instância RDS está
acessível, mas o banco de dados ainda não foi criado. Crie-o:

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

Depois, execute novamente a verificação de conectividade acima para confirmar.

Se falhar por outros motivos, verifique:
- **Regras de security group / firewall** — a porta 5432 deve estar aberta do cluster
  até o host do banco de dados
- **Privilégios do usuário do banco de dados** — o usuário deve ter permissões de CREATE,
  ALTER e SELECT no banco de dados de destino, além de `CREATEDB` ou de um banco de dados
  do orquestrador pré-criado (veja a próxima seção)

> O chart também inclui verificações integradas: um init container que aguarda
> conectividade TCP com o banco de dados, e um `helm test` que valida uma conexão
> PostgreSQL completa após a implantação. Esta etapa de pré-checagem detecta problemas
> antes de você investir tempo criando segredos e executando `helm install`.

### Pre-flight: Orchestrator (ddorch) Database

O orquestrador (`ddorch`, habilitado por padrão) armazena seu estado de workflow em um
**segundo banco de dados**, ao lado do banco de dados principal do DefectDojo. Na inicialização,
ele pega o nome do banco de dados de `DD_DATABASE_URL`, acrescenta `-ddorch` e cria esse
banco de dados se ele não existir — banco de dados principal `dojodb` significa que o
orquestrador usa `dojodb-ddorch`.

Se a role da aplicação não tiver permissão para criar bancos de dados, o pod do ddorch
falha na inicialização com:

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

Satisfaça **uma** das opções a seguir antes de instalar:

**Opção A — conceda `CREATEDB` à role da aplicação** e deixe o ddorch criar
seu banco de dados na primeira inicialização:

```sql
ALTER ROLE defectdojo CREATEDB;
```

**Opção B — pré-crie o banco de dados do orquestrador**, nomeado a partir do seu
banco de dados principal com o sufixo `-ddorch` e de propriedade do mesmo usuário
da aplicação. O hífen no nome exige aspas duplas em SQL:

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

Usando a mesma abordagem de pod temporário da verificação de conectividade acima:

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## Generate Secrets

Duas opções aqui.

### Option A: External Secret (recommended for GitOps)

Crie um Secret do Kubernetes com as 12 chaves necessárias antes de instalar o chart.
Use o `secrets-template.yaml` fornecido pelo suporte do DefectDojo como ponto de
partida (veja [Preparar Seu Arquivo de Values](#prepare-your-values-file) para saber
como obtê-lo):

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

Edite o arquivo, substitua todos os valores de placeholder e depois aplique:
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

O secret também pode ser gerenciado pelo External Secrets Operator, Sealed Secrets,
ou qualquer outra ferramenta que crie Secrets do Kubernetes. O chart não se importa
com como o secret chegou lá — basta definir `dojo.existingSecret` com o nome dele.

No momento da instalação:
```bash
--set dojo.existingSecret=dojopro-secrets
```

O chart pula automaticamente a renderização do seu Secret integrado quando
`dojo.existingSecret` está definido — nenhuma flag adicional é necessária.

Se o seu Redis externo exigir autenticação, o `secrets-template.yaml` também
inclui um Secret `dojopro-redis` separado. O chart lê as credenciais do Redis a partir de
`redis.auth.existingSecret` (padrão: `dojopro-redis`). Se o seu Redis não tiver
senha (por exemplo, ElastiCache somente VPC), você pode pular isso.

### Option B: Inline Secrets (simpler, not GitOps-friendly)

Passe os valores de segredo diretamente em um arquivo de values:

```yaml
dojo:
  secretKey: ""                    # openssl rand -hex 25
  credentialAES256Key: ""          # openssl rand -hex 16
  cloudPortalSecretKey: ""         # openssl rand -hex 25
  connectorsSharedSecret: ""       # openssl rand -hex 25 (or reuse cloudPortalSecretKey)
  admin:
    password: ""                   # openssl rand -base64 16
  emailUrl: "consolemail://"
  proEnhancementsEpssBucketKey: "" # leave empty if not using EPSS

database:
  password: ""                     # your PostgreSQL password

redis:
  auth:
    password: ""                   # your Redis password (omit if Redis has no auth)

monitoring:
  password: ""                     # openssl rand -hex 16
```

Salve isso como `my-secrets.yaml` e passe com `-f` no momento da instalação.

> Não faça commit de arquivos de segredos no controle de versão.

---

## Create Internal TLS Certificates

O chart precisa de certificados TLS internos para comunicação serviço a serviço.

Crie dois secrets TLS do Kubernetes no seu namespace antes de instalar:

1. `dojopro-internal-tls` — um secret TLS com `tls.crt` e `tls.key` para
   criptografia serviço a serviço (nginx ↔ connectors, etc.)
2. `dojopro-internal-ca` — um secret contendo o certificado da CA sob a
   chave `ca.crt`, usado pelos connectors para validar o certificado TLS interno

Você pode gerar uma CA autoassinada e um certificado de servidor com `openssl`, ou
usar a CA interna da sua organização. O CN/SAN do certificado do servidor **deve** cobrir
o nome do serviço nginx interno usado pelo release do Helm. Por padrão, isso é
`<release-name>-nginx` (por exemplo, `dojopro-nginx` se o seu release se chamar
`dojopro`).

Exemplo gerando uma CA autoassinada e um certificado de servidor:
```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# Generate CA
# basicConstraints + keyUsage MUST be set explicitly. Without them the CA may
# be rejected as not a valid CA (e.g. "x509: certificate signed by unknown
# authority" / missing keyUsage) depending on your local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-internal-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# Generate server cert with correct SANs and usage extensions
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes \
  -subj "/CN=${RELEASE_NAME}-nginx" \
  -addext "subjectAltName=DNS:${RELEASE_NAME}-nginx,DNS:${RELEASE_NAME}-nginx.${NAMESPACE}.svc.cluster.local" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -copy_extensions copyall

# Create the Kubernetes secrets
kubectl create secret tls dojopro-internal-tls \
  --cert=server.crt --key=server.key \
  -n $NAMESPACE

kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=ca.crt \
  -n $NAMESPACE
```

> **Erro comum:** Usar `nginx-internal` como CN/SAN em vez de
> `<release-name>-nginx`. O pod dos connectors valida o certificado TLS
> em relação ao nome de serviço real (`<release-name>-nginx.<namespace>.svc.cluster.local`),
> e falhará com um erro `x509: certificate is valid for ... not ...` se
> o SAN não corresponder.

Depois defina no seu arquivo de values:
```yaml
certificates:
  generation:
    enabled: false
  internal:
    source: "secret"
    secretName: "dojopro-internal-tls"
    caBundle:
      secretName: "dojopro-internal-ca"
      key: "ca.crt"
```

### ddorch mTLS Certificates

Além dos secrets TLS internos acima, o orquestrador `ddorch` exige um
trio separado de certificados mTLS, consumido pelo servidor ddorch e por todo
worker que se comunica com ele (`ddorch-workers`, `integrators`). Eles são
entregues ao chart no momento da instalação via `--set-file` (eles **não** são
lidos a partir de um secret do Kubernetes pré-existente):

- `orch_tls_root.ca` — certificado da CA
- `orch_tls.crt` — certificado do servidor
- `orch_tls.key` — chave privada do servidor

Sem esses três arquivos, o `helm install` falha com
`ddorch.tls.rootCa is required`.

O SAN do certificado do servidor **deve** incluir todos os hostnames que os
workers usam para alcançar o ddorch:

- `ddorch` — nome curto do serviço dentro do cluster
- `<release-name>-ddorch` — nome de serviço totalmente qualificado (ex.: `dojopro-ddorch`)
- `<release-name>-ddorch.<namespace>.svc.cluster.local` — FQDN do cluster
- `nginx` — o `SERVER_TLS_SERVER_NAME` padrão usado pelos workers estilo hatchet
- `localhost`, `127.0.0.1` — workers no mesmo pod alcançando o ddorch pelo loopback do hostAlias

Exemplo gerando o trio:

```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# ddorch CA
# As with the internal CA, set basicConstraints + keyUsage explicitly so the
# generated cert is a valid signing CA regardless of local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout orch_ca.key -out orch_ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-ddorch-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# ddorch server cert
openssl req -newkey rsa:2048 -keyout orch_server.key -out orch_server.csr -nodes \
  -subj "/CN=ddorch" \
  -addext "subjectAltName=DNS:ddorch,DNS:${RELEASE_NAME}-ddorch,DNS:${RELEASE_NAME}-ddorch.${NAMESPACE}.svc.cluster.local,DNS:nginx,DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in orch_server.csr -CA orch_ca.crt -CAkey orch_ca.key \
  -CAcreateserial -out orch_server.crt -days 365 -copy_extensions copyall
```

Passe-os para `helm install` / `helm template`:

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> O helper `scripts/bootstrap-aws-eks.sh` gera e reutiliza esses certificados
> automaticamente via `dojopro-orch-certs-configmap` — se você estiver usando
> esse script, não precisa criá-los manualmente.

---

## License

O chart precisa de uma licença do DefectDojo Pro.

### Inspecting Your License

Antes de implantar, verifique se sua licença é válida e não expirou:

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

Isso exibe os metadados da licença, incluindo:
- `not_after` — data de expiração da licença
- `license_package` — confirma o seu tier

> **Secrets de pull de imagem:** Quando `images.pullSecrets.extractFromLicense: true`
> está definido (o padrão nos presets de plataforma), o chart extrai automaticamente
> a service account do GCP embutida no seu arquivo de licença e cria o secret de pull
> de imagem necessário para puxar as imagens do DefectDojo do registro de containers.
> Nenhuma extração ou decodificação manual é necessária. Se você estiver usando um
> registro privado em vez disso, defina `extractFromLicense: false` e forneça seu
> próprio pull secret — veja [Registro Privado / Ambientes Air-Gapped](#private-registry-air-gapped-environments).

### Option 1: --set-file (standard Helm install)

Passe o arquivo de licença no momento da instalação:
```bash
--set-file license.contents=/path/to/license.lic
```

### Option 2: Existing Secret (GitOps / ArgoCD)

Crie um Secret do Kubernetes contendo a licença e depois diga ao chart para usá-lo.
Isso evita a necessidade de `--set-file` ou de armazenar a licença no git.

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

Depois, no seu arquivo de values ou nas flags do helm:
```yaml
license:
  existingSecret: "dojopro-license"
```

O secret pode ser gerenciado pelo External Secrets Operator, Sealed Secrets, ou kubectl puro.

> **Importante:** `license.existingSecret` **não é compatível** com a configuração
> padrão `images.pullSecrets.extractFromLicense: true`. O chart precisa do conteúdo
> da licença disponível no momento da renderização para extrair as credenciais
> embutidas do registro de containers. Se você usar `license.existingSecret`, também
> deve desativar a extração automática do pull secret e fornecer o seu próprio:
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```
>
> Se você quiser que o chart extraia automaticamente os pull secrets da licença
> (o padrão), use a **Opção 1** (`--set-file license.contents=`) em vez disso.


---

## FIPS 140-3 Mode (optional)

Para ambientes sujeitos ao FedRAMP **SC-13** ou similar, o chart pode implantar
as variantes de imagem `-fips`, cuja criptografia é realizada pelo **OpenSSL
FIPS Provider 3.1.2** (certificado NIST CMVP **#4985**) e, para os serviços em Go,
pelo **Go Cryptographic Module v1.0.0** (CMVP **#5247**).

A aplicação ocorre dentro do container, portanto não é necessário um kernel de
host habilitado para FIPS — o que torna isso viável em runtimes gerenciados,
onde o SO do host não está sob seu controle.

Desativado por padrão; a saída renderizada permanece inalterada quando está desligado.

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

Imagens com a tag `-fips` devem estar disponíveis no seu registro. Entre em
contato com hello@defectdojo.com para obter acesso.

### Components without a FIPS variant

O Sensei e o PostgreSQL/Redis **embutidos** não têm build FIPS — a imagem valkey
empacotada é baseada em Alpine, que não possui OpenSSL validado para FIPS. Uma
instalação FIPS deve, portanto, usar datastores externos e manter o Sensei desativado:

```yaml
fips:
  enabled: true
sensei:
  enabled: false
postgresql:
  enabled: false    # point at an external FIPS-compliant database
redis:
  enabled: false    # point at an external FIPS-compliant cache
```

Com `fips.validate: true` (o padrão), o chart **falha ao renderizar** se você
habilitar o FIPS junto com qualquer um deles, nomeando os responsáveis:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

Isso é proposital. Uma implantação em que a maioria dos serviços usa criptografia
validada e um ou dois silenciosamente não usam é pior do que uma falha óbvia:
parece estar em conformidade e só se revela durante uma avaliação. Defina
`fips.validate: false` somente se você tiver aceitado esse risco explicitamente.

### Verifying after deploy

Todo pod executa uma verificação de inicialização fail-closed — se o provider
validado não estiver ativo, o container encerra em vez de atender requisições.
As evidências que ele imprime geralmente são o que um avaliador precisa:

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

Mudanças de comportamento a serem consideradas (o hashing de senha passa a usar
PBKDF2, o ChaCha20 é removido da lista de cifras TLS) são abordadas na página
de Modo FIPS 140-3 da documentação do produto.

---

## Pre-flight: Validar Templates

Antes de instalar, execute `helm template` para renderizar e validar todos os manifests
sem tocar no cluster. Isso detecta erros de values, campos obrigatórios ausentes
e problemas de YAML antes de você se comprometer com `helm install`:

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  > /dev/null
```

Use as mesmas flags que você pretende passar para `helm install`. Se isso for concluído sem erros,
seus values são válidos. Se falhar, a mensagem de erro identificará o campo ausente
ou inválido — corrija seu arquivo de values e execute novamente até passar.

---

## Deploy

Combine seu overlay de plataforma, perfil de recursos, values do cliente e as
escolhas de secrets + licença que você fez acima.

### AWS EKS

> **HTTPS é fortemente recomendado para acesso via navegador no EKS.**
> Quando o TLS de ingress está ativo, o chart habilita automaticamente
> `SECURE_SSL_REDIRECT` e define os cookies de CSRF/sessão como `Secure`, o que significa
> que o login pelo navegador falhará sem um listener HTTPS no ALB. Configure um
> certificado ACM antes de fazer o deploy para a melhor experiência.
>
> Se você precisar executar sem HTTPS, veja
> [Deploying Without HTTPS (Not Recommended)](#deploying-without-https-not-recommended)
> abaixo.

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **Consistência de namespace:** O valor do namespace deve corresponder em todos os
> recursos: seu YAML de secrets (`metadata.namespace`), `kubectl create namespace`,
> e `helm install -n`. Se você usar um namespace customizado em vez de `dojopro`,
> substitua-o de forma consistente em todos os comandos e manifests de secrets.

**Secrets externos + secret de licença (GitOps):**

Aplique seus secrets se ainda não o fez (veja [Generate Secrets](#generate-secrets)),
e então instale:

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**Secrets inline + arquivo de licença (mais simples):**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

#### Deploying Without HTTPS (Not Recommended)

> **Aviso:** Executar sem HTTPS significa que os cookies de sessão são enviados em
> texto claro e a proteção CSRF via cookies seguros fica desabilitada. Não use
> esta configuração em produção.

Se você precisar fazer o deploy sem HTTPS temporariamente (por exemplo, testes iniciais sem
um certificado ACM), aplique **todas** as seguintes alterações no seu arquivo de values:

```yaml
dojo:
  url: "http://dojo.example.com"       # must be http://, not https://
  secureCookies: false                  # disable Secure flag on session/CSRF cookies

django:
  ingress:
    tls:
      enabled: false
    annotations:
      # HTTP-only listener — remove the HTTPS listener entirely
      alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}]'
      # Do NOT include the ssl-redirect annotation — it causes a redirect
      # loop when no HTTPS listener exists (see BUG-17 in Known Issues)
      # alb.ingress.kubernetes.io/ssl-redirect: "443"   # REMOVE this line
```

Todas as quatro alterações são obrigatórias. A ausência de qualquer uma delas resultará em loops
de redirecionamento ou login quebrado. Quando estiver pronto para habilitar o HTTPS, reverta essas alterações e
configure um certificado ACM.

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **Lembrete:** Você já deve ter o valor de `fsGroup` do seu namespace a partir da
> [Pre-Install Checklist](#infrastructure-details). Caso não tenha, procure-o agora:
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**Secrets externos + secret de licença (GitOps):**

Aplique seus secrets se ainda não o fez (veja [Generate Secrets](#generate-secrets)),
e então instale:

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**Secrets inline + arquivo de licença (mais simples):**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

---

## Deploy with ArgoCD

O DefectDojo Pro é totalmente compatível com o ArgoCD. O chart inclui presets de plataforma
e de perfil que o ArgoCD pode referenciar diretamente como `valueFiles`.

### Prerequisites

Antes de criar a Application do ArgoCD, os seguintes recursos do Kubernetes
devem existir no namespace de destino:

- Os secrets da aplicação (veja [Generate Secrets](#generate-secrets))
- O secret de licença (veja [License](#license))
- Secrets de TLS interno, se não estiver usando geração automática (veja [Create Internal TLS Certificates](#create-internal-tls-certificates))
- Material de mTLS do ddorch (veja [ddorch mTLS Certificates](#ddorch-mtls-certificates)). O ArgoCD não tem um equivalente a `--set-file`, então passe os três conteúdos PEM via parâmetros da Application (`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`). Use um plugin de gerenciamento de secrets do ArgoCD (Sealed Secrets, External Secrets ou um plugin de ConfigMap) em vez de fazer commit da chave em texto plano.

### How It Works

O ArgoCD referencia os arquivos de preset em relação à raiz do chart. Seu spec de Application
precisa de três coisas:

1. Presets de plataforma e perfil como `valueFiles`
2. Sua configuração específica de ambiente (via `valueFiles`, `values` inline, ou ambos)
3. Referências de secret e licença como `parameters`

```yaml
helm:
  valueFiles:
    - presets/platforms/aws-eks.yaml       # or openshift
    - presets/profiles/standard.yaml       # or minimal, performance
  values: |
    # Your environment-specific configuration goes here.
    # This is applied last and overrides the presets above.
    dojo:
      fqdn: dojo.example.com
      admin:
        user: admin
        email: admin@example.com
    database:
      host: your-db-host.example.com
    # ... see template.yaml for all options
  parameters:
    - name: dojo.existingSecret
      value: dojopro-secrets
    - name: license.existingSecret
      value: dojopro-license
```

### Supplying Your Configuration

Há várias maneiras de fornecer seus values específicos de ambiente ao ArgoCD:

- `values` inline no spec da Application — abordagem mais simples, sem arquivos
  ou repositórios extras necessários. Funciona bem quando sua configuração é direta.
- Um arquivo de values em um repositório git separado — use o recurso multi-source do ArgoCD
  (v2.6+) com uma variável `$ref` para trazer seu arquivo de values junto com o chart.
  Recomendado ao usar um chart publicado via OCI.
- Um arquivo de values no mesmo repositório git do chart — referencie-o em
  `valueFiles` com um caminho relativo ao diretório do chart
  (por exemplo, `../../overrides/customers/my-company.yaml`).

As três abordagens seguem o mesmo empilhamento: preset de plataforma → preset
de perfil → sua configuração. Values posteriores sobrepõem os anteriores.

### Upgrading

Quando o chart é publicado em um registro OCI, atualizar é uma única alteração
em `targetRevision` no seu spec de Application. Os presets de plataforma e perfil
são versionados junto com o chart, então eles são atualizados automaticamente.

Para detalhes completos sobre o suporte a Helm do ArgoCD, veja a
[documentação de Helm do ArgoCD](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/).

---

## Verify

```bash
# Check the initializer job completed successfully (required for first install)
kubectl get jobs -n $NAMESPACE
# The initializer job must show 1/1 COMPLETIONS. If it shows 0/1, the
# database migrations did not run and the application will not work.
# Check its logs:
#   kubectl logs -n $NAMESPACE -l app.kubernetes.io/component=initializer
# To retry: delete the failed job and run helm upgrade with the same flags:
#   kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
#   helm upgrade dojopro <chart> ... (same flags as install)

# Check all pods are running
kubectl get pods -n $NAMESPACE
# Expected components (chart 2.57+): django, celery-worker, celery-beat,
# connectors, nginx, ddorch, ddorch-workers, integrators, mcp-server, plus
# redis and postgresql if you are using the bundled copies, plus psirt and
# sensei if you enabled them (psirt.enabled, sensei.enabled).
# Note: ddorch-workers replaces the legacy kairos, rulesengine, and
# hatchet-integrators workers.

# Check ingress (EKS) or route (OpenShift)
kubectl get ingress -n $NAMESPACE    # EKS
oc get route -n $NAMESPACE           # OpenShift

# Run built-in helm tests
helm test dojopro -n $NAMESPACE --logs --timeout 5m

# Health check
# EKS (use https:// if TLS is configured, http:// otherwise):
ALB=$(kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}')
curl -sk "https://${ALB}/api/v2/health_check/light/"
# or for HTTP-only deployments:
# curl -s "http://${ALB}/api/v2/health_check/light/"

# OpenShift:
ROUTE=$(oc get route -n $NAMESPACE -o jsonpath='{.items[0].spec.host}')
curl -sk "https://${ROUTE}/api/v2/health_check/light/"
```

### Built-in Helm Tests

O chart vem com quatro testes que são executados como pods do Kubernetes quando você executa
`helm test`. Eles validam os pontos de integração críticos entre o DefectDojo
e seus serviços de apoio:

| Teste | O que verifica |
|------|----------------|
| `test-database` | Conecta-se ao PostgreSQL usando as credenciais configuradas, executa `SELECT version()`, e confirma que o banco de dados está aceitando queries. Tenta novamente por até 60 segundos. |
| `test-redis-broker` | Conecta-se ao broker Redis/Valkey, envia um `PING`, e então realiza um ciclo de set/get/delete para verificar o acesso de leitura e escrita. |
| `test-django-health` | Acessa o endpoint `/api/v2/health_check/light/` no serviço nginx interno e confirma uma resposta HTTP 2xx/3xx. Executa após os testes de banco de dados e broker (hook-weight 10). |
| `test-storage` | Monta o volume de mídia e realiza um ciclo de escrita/leitura/exclusão para confirmar que o backend de armazenamento é acessível e gravável pela aplicação. Executa por último (hook-weight 15). |

Os testes são executados em ordem por hook-weight — testes de infraestrutura (banco de dados, broker)
primeiro, depois testes em nível de aplicação (health, storage). Se um teste anterior
falhar, os testes seguintes ainda podem ser executados, mas provavelmente também falharão.

Para executar os testes novamente após um deployment ou alteração de configuração com falha:
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

Os pods de teste são limpos automaticamente antes de cada execução
(política de exclusão `before-hook-creation`). Para inspecionar manualmente os logs de um pod de teste com falha:
```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### Retrieve the Admin Password

A senha inicial de admin é armazenada no secret da aplicação. Recupere-a
com:

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Se você usou secrets inline em vez de um secret externo, a senha está no
secret gerenciado pelo chart:

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Faça login na URL configurada com o nome de usuário admin (padrão: `admin`) e
esta senha. Altere a senha após o primeiro login.

---

## Operations

### Log Verbosity

O chart expõe duas configurações de nível de log, ambas com o padrão `INFO`:

| Configuração | Controla | Variável de ambiente |
|---------|----------|---------|
| `config.logLevel` | Logging da aplicação Django | `DD_LOG_LEVEL` |
| `celery.logLevel` | Logging do worker e beat do Celery | `DD_CELERY_LOG_LEVEL` |

Para aumentar a verbosidade para solução de problemas, defina uma ou ambas como `DEBUG` no
seu arquivo de values e execute `helm upgrade`:

```yaml
config:
  logLevel: "DEBUG"
celery:
  logLevel: "DEBUG"
```

```bash
helm upgrade dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set config.logLevel=DEBUG \
  --set celery.logLevel=DEBUG \
  --wait --timeout 15m
```

As flags `--set` sobrepõem as configurações do arquivo de values, então você pode alternar o log
de debug sem editar arquivos. Depois que o problema for resolvido, execute `helm upgrade`
novamente sem as flags `--set` para voltar aos seus padrões configurados.

O deployment do Django também suporta `django.uwsgi.enableDebug: true`, que
define `DD_DEBUG=True` para depuração de framework em nível mais baixo. Isso produz
saída significativamente maior e deve ser usado apenas para investigações curtas.

### Scan Import Isolation

As importações de scan (`/api/v2/import-scan/` e `/api/v2/reimport-scan/`) são analisadas
de forma síncrona e podem consumir grandes quantidades de memória do worker. Por padrão, o
chart executa um deployment `django-import` dedicado (uwsgi na porta 3032 atrás de
seu próprio Service) e o nginx do pod Django roteia os endpoints de importação para ele.
Uma importação pesada não consegue esgotar (ou causar OOM em) os workers web interativos, e o
pool de importadores (writers) escala independentemente dos pods web (readers).

Ajustes sob `django.uwsgiImport`:

```yaml
django:
  uwsgiImport:
    enabled: true          # false routes imports back to the main uwsgi pool
    replicas: 2            # importer pods (ignored when autoscaling is on)
    maxBodySizeMb: null    # client_max_body_size on the import routes; null
                           # derives dojo.scanMaxFileSize + 5 (multipart
                           # overhead), so raising scanMaxFileSize just works.
                           # Set an integer to override.
    performance:
      processes: 2         # concurrent imports per pod = processes x threads
      threads: 4
    resources:
      requests:
        cpu: "100m"
        memory: "512Mi"
      limits:
        memory: "4Gi"
    terminationGracePeriodSeconds: 60   # raise toward 1800 to let in-flight
                                        # imports finish on rollouts/drains
    autoscaling:
      enabled: false       # scale importers on their own CPU signal
    horizontalpodautoscaler:
      minReplicas: 2
      maxReplicas: 5
      averageUtilization: 60
```

Notas operacionais:

- Os pods de importador montam o volume de mídia compartilhado, então precisam de
  armazenamento com suporte a ReadWriteMany para poderem ser agendados livremente entre os nós. Os backends de
  armazenamento do chart (`efs`, `filestore`, `gcsfuse`, `nfs`, e o PVC de mídia RWX
  padrão) atendem a esse requisito; um PVC ReadWriteOnce não atende.
- O autoscaling de importadores está desligado por padrão porque um scale-down remove qualquer
  importação que aquele pod esteja executando assim que `terminationGracePeriodSeconds` expira.
  Se você habilitá-lo, aumente o período de graça para que importações em andamento possam terminar.
- Um PodDisruptionBudget (`podDisruptionBudget.djangoImport`) protege o
  pool de importadores durante interrupções voluntárias sempre que mais de um importador
  está em execução.

O perfil `minimal` desabilita o deployment de importador para manter o footprint
pequeno; as importações então compartilham o pool uwsgi único, como antes.

### PSIRT Advisory Engine (opcional)

O chart pode fazer o deploy do PSIRT Advisory Engine, um serviço para elaborar e
publicar advisories de segurança a partir dos achados do DefectDojo. Está desabilitado por padrão.
Quando habilitado, ele aparece em `/psirt/` no seu host principal do DefectDojo — o
sidecar nginx faz o proxy dele, então nenhum ingress ou entrada de DNS extra é necessário.

```yaml
psirt:
  enabled: true
  # REQUIRED: full async connection URL. Use a dedicated database (its
  # migrations must not share DefectDojo's database).
  databaseUrl: "postgresql+asyncpg://pae:<password>@<host>:5432/pae"
  # Pre-shared secret for autonomous advisory publishing. The scheduler sends
  # it to DefectDojo as an X-Psirt-Secret header (no minted token, no UI step);
  # the chart injects the SAME value into the DefectDojo pods so they accept it.
  # Optional — omit to disable autonomous publishing (the pod still boots).
  psirtSharedSecret: "<high-entropy secret>"
  # Strongly recommended: pin both secrets. Left empty they are re-generated
  # on every helm upgrade, which logs out active sessions and invalidates
  # stored DefectDojo tokens.
  sessionSecretKey: ""   # any 64-character string
  fernetSaltB64: ""      # python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`psirtSharedSecret` é um valor simples que você escolhe — nenhum usuário do DefectDojo ou
token emitido está envolvido. Defina uma string de alta entropia (por exemplo,
`python -c "import secrets; print(secrets.token_urlsafe(48))"`). O chart conecta
esse valor tanto ao Secret do engine psirt quanto aos pods do DefectDojo, então um único valor
habilita a publicação automática em uma instalação nova, sem nenhuma etapa pós-boot. Rotação:
altere-o e execute `helm upgrade`.

Configuração do banco de dados: aponte `databaseUrl` para o mesmo host PostgreSQL que o DefectDojo
usa (ou qualquer outro host acessível) com um nome de banco de dados à sua escolha. O
pod cria o banco de dados no primeiro início se ele não existir, o que exige uma
concessão única como superusuário postgres:

```sql
ALTER ROLE pae CREATEDB;
```

Notas operacionais:

- Mantenha `psirt.replicas` em 1. O serviço executa seu próprio agendador de jobs interno,
  e uma segunda réplica executaria cada job agendado duas vezes.
- O pod monta o volume de mídia compartilhado (os anexos de advisory ficam em
  `<media>/pae/uploads`), então a mesma orientação de armazenamento ReadWriteMany do
  pool de importadores se aplica.
- HTTPS de saída é necessário para feeds de advisory e consultas ao NVD. Com
  `networkPolicy.profile=aggressive`, a lista de CIDRs permitidos
  (`networkPolicy.externalAPIs.allowedCidrs`) deve cobrir esses endpoints.
- Um `psirt.nvdApiKey` opcional eleva o limite de taxa do NVD de 5 para 50
  requisições a cada 30 segundos.

### Sensei scan/fix engine (opcional)

O chart pode fazer o deploy do Sensei engine, o serviço por trás dos jobs de
scanning server-side e de remediação automática (fix). Está desabilitado por padrão e não precisa de
configuração extra para iniciar:

```yaml
sensei:
  enabled: true
```

O engine não mantém secrets de longa duração. As credenciais de scan/fix e as URLs de endpoint
vão junto com cada job, despachadas a partir da configuração criptografada de worker do DefectDojo.
Django e Celery alcançam o engine dentro do cluster (`SENSEI_ENGINE_URL` é conectado
automaticamente ao configmap compartilhado), então nenhum ingress ou entrada de DNS é
necessário.

Notas operacionais:

- O engine chama o DefectDojo de volta na URL pública do seu site (`dojo.url`) por
  padrão. Defina `sensei.ddCallbackUrl` para sobrepor — para tráfego puramente interno ao
  cluster, aponte-o para o listener nginx interno, mas nesse caso o engine deve confiar
  na CA interna do DefectDojo.
- As credenciais de LLM para jobs de fix normalmente são definidas no aplicativo (AI Model Settings)
  e transportadas por job. Defina `sensei.llm.*` apenas quando o engine precisar ler a
  chave a partir do seu próprio ambiente; prefira `sensei.llm.existingSecret` em vez do
  `sensei.llm.apiKey` em texto plano.
- Para executar o engine contra o Google Vertex AI em vez de uma chave de API de provedor,
  defina `sensei.llm.provider: vertex` e `sensei.llm.vertexProject` para o projeto GCP
  que hospeda o Vertex (`sensei.llm.vertexRegion` normalmente é `global`). O
  pod se autentica com Application Default Credentials, então forneça a ele uma conta de serviço
  do GCP através de `sensei.serviceAccountName` + Workload Identity, ou
  monte um arquivo de chave com `sensei.extraVolumesRaw` e
  `sensei.extraVolumeMounts`, e então aponte `GOOGLE_APPLICATION_CREDENTIALS` para
  ele via `sensei.extraEnv`.
- `sensei.llm.fallbackChain` aceita uma lista separada por vírgulas de entradas `provider` ou
  `provider:model` para as quais o engine recorre quando o
  provedor primário retorna uma falha passível de nova tentativa. Encerrar a cadeia em um
  fornecedor diferente (por exemplo `vertex-gemini:gemini-2.5-pro`) mantém os jobs de fix
  em execução durante uma interrupção do provedor primário.
- A imagem do scanner é pesada. `sensei.maxConcurrentJobs` (padrão 3) limita
  os jobs paralelos por pod, e os recursos padrão
  (requisição de 1Gi / limite de 4Gi) são dimensionados para esse limite — aumente ambos juntos.
- Um HPA baseado em CPU (1 a 4 réplicas) está ativado por padrão. Defina
  `sensei.hpa.maxReplicas` igual a `sensei.hpa.minReplicas` para fixar a
  contagem em `sensei.replicas`.
- HTTPS de saída é necessário para clones de repositório, APIs de hospedagem git e
  APIs de provedores de LLM. Com `networkPolicy.profile=aggressive`, a lista de
  CIDRs permitidos (`networkPolicy.externalAPIs.allowedCidrs`) deve cobrir esses
  endpoints.

### Rotating TLS Certificates

O chart usa duas categorias de certificados TLS, cada uma com um procedimento de
rotação diferente.

#### Internal TLS (service-to-service)

Esses são os secrets `dojopro-internal-tls` e `dojopro-internal-ca` usados
para a comunicação entre nginx, connectors e outros serviços internos.

```bash
# Replace the existing secret with new cert/key
kubectl create secret tls dojopro-internal-tls \
  --cert=new-server.crt \
  --key=new-server.key \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Replace the CA bundle
kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=new-ca.crt \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart affected pods to pick up new certs
kubectl rollout restart deployment -n $NAMESPACE
```

#### Ingress TLS (external/browser-facing)

A rotação depende de como você configurou o TLS:

- **Gerenciado pelo ACM (EKS):** A renovação é automática — nenhuma ação necessária.
- **cert-manager:** A renovação é automática com base nas configurações `duration` e
  `renewBefore` (padrões: 2160h / 720h).
- **Certificados gerenciados do GKE:** A renovação é automática — nenhuma ação necessária.
- **Certificado manual via secret do Kubernetes:** Atualize o secret ao qual o ingress
  faz referência usando o mesmo padrão `kubectl create secret tls ... --dry-run=client`
  mostrado acima.
- **Certificados internos gerados automaticamente:** O chart pode regenerá-los com
  `helm upgrade` se `certificates.generation.enabled: true`.

> No Kubernetes, a fonte da verdade é o objeto Secret — atualizar o secret
> e fazer o rollout do deployment é como funciona a rotação de certificados.

> Se você usa o External Secrets Operator ou Sealed Secrets para gerenciar os secrets de TLS,
> a rotação é tratada nessa camada e os secrets do Kubernetes são atualizados
> automaticamente — nenhuma etapa manual de `kubectl` é necessária.

---

## Values File Layering

O chart empilha arquivos de values. Os arquivos posteriores prevalecem:

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

Os presets de plataforma e os presets de perfil são embarcados dentro do chart (`dojopro/presets/`).
Eles estão incluídos no `.tgz` empacotado e são versionados junto com o chart. Os clientes
não precisam modificá-los.

Ao usar `helm install` a partir do chart extraído, referencie-os usando a
variável `$CHART` definida durante a [extração](#extract-the-chart-package):
```
-f $CHART/presets/platforms/aws-eks.yaml
```

Ao usar o ArgoCD, referencie-os em relação à raiz do chart:
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

Não coloque limites de recursos em arquivos de cliente nem configuração de plataforma em arquivos de perfil.
Mantenha cada camada focada em uma única coisa.

> **Versionamento de presets — ArgoCD vs CLI:** O ArgoCD referencia os presets de dentro
> do pacote do chart, então eles são atualizados automaticamente quando você altera
> `targetRevision`. Usuários de CLI devem reextrair os presets ao atualizar para uma nova
> versão do chart para obter quaisquer alterações nos padrões de plataforma ou perfil. Use um
> caminho de extração versionado (por exemplo, `dojopro-2.55.4/`) para evitar confusão
> entre versões do chart — veja [Extract the Chart Package](#extract-the-chart-package).

---

## Customization & Extensibility

Além dos arquivos de values de plataforma/perfil/cliente, o chart oferece pontos de extensão
de primeira classe para conectar sua própria infraestrutura — sidecars, init
containers, variáveis de ambiente, volumes, contas de serviço, restrições de agendamento e
manifests extras arbitrários — sem fazer fork do chart:

- **Hooks por componente** — `extraEnv`, `extraEnvFrom`, `extraVolumesRaw`,
  `extraVolumeMounts`, `extraInitContainers`, `extraContainers`, `hostAliases`,
  `priorityClassName`, `topologySpreadConstraints`, `dnsConfig`, e
  `serviceAccountName` em cada workload (django, celery worker/beat,
  connectors, ddorch, ddorch-workers, integrators, mcp-server, psirt).
- **`extraManifests` de nível superior** — renderiza YAML arbitrário fornecido pelo usuário
  (ConfigMaps, Secrets, NetworkPolicies, etc.) junto com o chart, passado
  pelo `tpl` do Helm com o contexto raiz do chart.
- **Consumo como umbrella chart** — o `dojopro` pode ser embutido como subchart
  via dependência `file://` ou OCI, útil para distribuir pacotes de clientes que
  sobrepõem recursos adicionais ao redor do chart.
- **Validação com schema** — `values.schema.json` cobre cada hook, então
  os editores obtêm autocomplete e `helm lint`/`helm install` validam suas
  sobreposições.

Veja o guia BYO Extensibility — incluído como
**Appendix: Bring Your Own Infrastructure (BYO)** na edição em PDF — para
padrões, exemplos e garantias de estabilidade de upgrade.

---

## Network Policies

O chart vem com NetworkPolicies para cada componente, habilitadas por padrão
(`networkPolicy.enabled: true`). Uma linha de base de negação padrão é restrita aos pods
desta release (pelos labels `app.kubernetes.io/name` + `app.kubernetes.io/instance`),
então ela nunca afeta outros workloads que compartilham o namespace.

O quão rígidas são as regras é controlado por **`networkPolicy.profile`**:

| Perfil | Egress | Ingress pod-a-pod | Ingress externo |
|---------|--------|--------------------|------------------|
| `standard` (padrão) | Todo egress permitido (`0.0.0.0/0`) | Todo tráfego entre os pods desta própria release é permitido | Restrito ao ingress controller / load balancer |
| `aggressive` | Allowlist granular por componente (DNS, banco de dados/broker, serviços específicos dentro do cluster, apenas APIs externas explicitamente permitidas) | Allowlist granular por componente | Restrito ao ingress controller / load balancer |

- **`standard`** é recomendado para a maioria dos clusters. Ele evita quebras causadas por
  dependências de egress específicas do cluster (o metadata server do GKE, o NodeLocal
  DNSCache, endpoints de armazenamento/API em nuvem) e por chamadas de serviço internas à aplicação,
  ao mesmo tempo em que mantém o ingress externo restrito ao caminho de ingress: a release
  confia em seus próprios pods, mas o tráfego externo ainda passa pela porta da frente.
- **`aggressive`** impõe uma allowlist rígida em ambas as direções. Se você usá-la,
  pode ser necessário ajustar as exceções em `networkPolicy` para o seu cluster:
  - `nodeLocalDns` — permite o resolver NodeLocal DNSCache (link-local
    `169.254.20.10` por padrão, na porta 53). Necessário em clusters que executam
    o NodeLocal DNSCache (por exemplo, o addon do GKE), caso contrário a resolução de DNS falha.
  - `dnsSelectors` — sobrepõe o alvo de egress de DNS para uma configuração de DNS customizada.
  - `allowExternalAPIs` / `externalAPIs` — controla o egress para APIs HTTPS
    externas e quais CIDRs são bloqueados (por exemplo, metadata em nuvem).

Defina o perfil em qualquer arquivo de values, por exemplo:

```yaml
networkPolicy:
  profile: aggressive
```

> **As verificações de saúde do GKE** são tratadas em ambos os perfis — os intervalos de
> probe do load balancer GCE (`130.211.0.0/22`, `35.191.0.0/16`) sempre têm permissão para
> alcançar o backend django no GKE. Veja [GCP GKE](#gcp-gke).

### Ingress controller access (502 Bad Gateway)

Em clusters que não são GKE/OpenShift, a NetworkPolicy do django permite a entrada do ingress
controller selecionando seu namespace pelo label `kubernetes.io/metadata.name` que o
Kubernetes aplica automaticamente a todo namespace. Por padrão, isso espera que o controller
esteja em um namespace chamado **`ingress-nginx`**, com os pods do controller carregando o label
`app.kubernetes.io/name: ingress-nginx` (o padrão do chart ingress-nginx).

Se seu ingress controller estiver em um namespace com nome diferente, usar
labels de pod diferentes, ou for um controller totalmente diferente (Traefik, um ALB,
etc.), a policy irá descartar silenciosamente seu tráfego e as requisições retornarão **502 Bad
Gateway** (`connect() failed (110: Operation timed out)` nos logs do controller). Aponte a policy para sua origem real de ingress com `networkPolicy.ingressSource`:

```yaml
networkPolicy:
  ingressSource:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: <ingress-namespace>
      podSelector:
        matchLabels:
          app.kubernetes.io/name: <controller-label>
```

Ou ajuste `networkPolicy.ingressNamespace` / `networkPolicy.ingressControllerLabel`
se apenas os nomes forem diferentes. Veja os comentários sob `networkPolicy` em
`values.yaml` para mais exemplos de `ingressSource` (Traefik, OpenShift router, AWS
ALB).

---

## Upgrading

O caminho de upgrade recomendado busca o chart diretamente do registro OCI do
DefectDojo — nenhuma extração de zip é necessária:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Um upgrade OCI típico se parece com isto (os mesmos arquivos de values e flags `--set`
do instalação original):

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --wait --timeout 15m
```

O fluxo de zip empacotado usado na instalação também funciona para upgrades —
substitua `helm install` por `helm upgrade` contra o caminho `$CHART` extraído.

Veja o [Upgrade Guide](/get_started/pro/onprem/upgrading_on_kubernetes/) — incluído como **Appendix: Upgrading
DefectDojo Pro** na edição em PDF — para autenticação, upgrades via ArgoCD,
verificação, rollback e solução de problemas.

---

## Desinstalando

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> PVCs, bancos de dados externos e secrets externos não são excluídos.
> Faça essa limpeza separadamente.

### Limpando PersistentVolumes

PersistentVolumes com uma política de reclaim `Retain` são **de escopo de cluster** — eles
não são removidos por `helm uninstall` ou pela exclusão do namespace. Se você reinstalar
o DefectDojo em um namespace diferente, os metadados de propriedade do PV órfão entrarão em
conflito com a nova instalação e bloquearão o `helm install`.

Verifique se há PVs órfãos após a desinstalação:

```bash
kubectl get pv | grep dojopro
```

Se algum permanecer, exclua-o:

```bash
kubectl delete pv dojopro-media-pv
```

> **Observação:** excluir o PV remove a referência do volume no Kubernetes, mas os
> dados subjacentes permanecem no backend de armazenamento (por exemplo, no sistema de arquivos EFS). Isso
> é seguro se você pretende reinstalar, mas deve ser feito de forma intencional.

---

## Testes locais com PostgreSQL e Redis incorporados

> **Esta configuração é apenas para testes e avaliação locais. Não use
> PostgreSQL ou Redis incorporados em produção.** As implantações de produção devem
> usar serviços gerenciados (por exemplo, RDS, ElastiCache) para confiabilidade, backups e
> escalonamento. O suporte do DefectDojo não cobre problemas com bancos de dados incorporados em
> ambientes de produção.

O chart pode implantar seu próprio PostgreSQL e Redis para testes locais rápidos usando
o profile `minimal`. Isso evita a necessidade de infraestrutura externa de banco de dados e broker.

Adicione o seguinte ao seu arquivo de values:

```yaml
# Enable embedded PostgreSQL (instead of external RDS)
postgresql:
  enabled: true
  database:
    password: "your-password"   # required — must match DD_DATABASE_PASSWORD in your secrets

database:
  external: false

# Enable embedded Redis (instead of external ElastiCache)
redis:
  enabled: true

celery:
  broker:
    external: false
```

> **Importante: `postgresql.database.password` é obrigatório** quando
> `postgresql.enabled` é `true` e `database.existingSecret` não está definido. O
> chart falhará ao renderizar sem ele. Essa senha deve corresponder ao valor de
> `DD_DATABASE_PASSWORD` nos secrets da aplicação.

> **Credenciais padrão do PostgreSQL incorporado:** os padrões do chart para o
> PostgreSQL incorporado são o usuário `dojodbusr` e o nome de banco de dados `dojodb`
> (definidos no `values.yaml` do chart). Seu `DD_DATABASE_URL` nos secrets da
> aplicação deve usar esses valores, não os placeholders de banco de dados externo em
> `secrets-template.yaml`. Por exemplo:
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

O profile `minimal` (`dojopro/presets/profiles/minimal.yaml`) define solicitações de
recursos reduzidas apropriadas para um cluster de teste de nó único, mas não
ativa esses flags de banco de dados/broker — você mesmo deve defini-los.

> **Observação sobre privilégios de contêiner:** os contêineres incorporados de PostgreSQL e Redis
> **não** são executados como root — o PostgreSQL é executado como UID 999 e o Redis como UID 1001.
> A única exceção é o **init container** do PostgreSQL (`init-chmod-data`),
> que é executado como root (UID 0) para definir a propriedade do diretório no volume de dados
> antes que o processo principal seja iniciado. Esse é um padrão comum para StatefulSets
> com armazenamento persistente. Se o seu cluster impõe um Pod Security Standard `restricted`
> ou um SCC do OpenShift que proíbe init containers como root, desabilite-o com
> `postgresql.initContainer.enabled: false` (veja [Problemas Conhecidos](#known-issues-chart-version-2.57.1)).

Ao usar o PostgreSQL incorporado no EKS, você também precisará do driver CSI do EBS
(veja [Pré-requisitos do AWS EKS](#aws-eks-prerequisites)) e pode precisar ajustar
os padrões de armazenamento (veja [Problemas Conhecidos](#known-issues-chart-version-2.57.1)).

Valide seus values antes de instalar — o caminho minimal exige mais
overrides e tem mais chance de apresentar erros de renderização:

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/minimal.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  > /dev/null
```

Se isso for concluído sem erros, prossiga com o `helm install` usando os mesmos flags.

> **Use `--timeout 30m` para instalações minimal/com banco de dados novo.** O PostgreSQL
> incorporado tem recursos reduzidos, e o initializer precisa executar todas as migrations
> de banco de dados do zero em um banco de dados novo. Em testes, isso levou ~23 minutos,
> o que excede o `--timeout 15m` usado nos exemplos de instalação padrão.
> Um timeout faz com que o `helm install` reporte `INSTALLATION FAILED` mesmo que
> a implantação seja concluída com sucesso em segundo plano. Usar `--timeout 30m`
> evita a falha falsa e o status de release `failed` resultante dela.

---

## Registro Privado / Ambientes Air-Gapped

Se o seu cluster não conseguir fazer pull do registro padrão do DefectDojo, espelhe as
imagens no seu próprio registro e configure o chart para usá-lo.

### Opção 1: Override global de registro

Defina `global.imageRegistry` para redirecionar todos os pulls de imagem. O chart remove
o registro original de `images.prefix` e adiciona o seu:

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

Isso afeta todas as imagens (django, nginx, celery, connectors, redis, etc.).

### Opção 2: Overrides por imagem

Para um controle mais refinado, defina `images.registry` (afeta as imagens principais da
aplicação) e sobrescreva imagens individuais:

```yaml
images:
  registry: "my-registry.example.com"
  prefix: "defectdojo/"          # path within your registry
  tag: "2.53.0"
  connectors:
    registry: "my-registry.example.com"
    repository: "defectdojo/connectors"
    tag: "2.53.0"
  redis:
    registry: "my-registry.example.com"
    repository: "defectdojo/redis"
    tag: "7.2.4"
```

### Image pull secrets para registros privados

Se o seu registro exigir autenticação, crie um pull secret e faça referência a ele:

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

Ou deixe que o chart crie um a partir de credenciais explícitas:

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

O comportamento padrão (`extractFromLicense: true`) extrai credenciais de conta de
serviço do GCP a partir do arquivo de licença para fazer pull do registro do DefectDojo. Desabilite
isso ao usar seu próprio registro:

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## Sobrescrevendo Anotações de Plataforma

O chart injeta automaticamente anotações específicas de plataforma no Ingress e no Service
com base em `cloudProvider` (por exemplo, anotações ALB para EKS, anotações GCE para
GKE). Se você precisar de controle total sobre as anotações — por exemplo, usando um controller
de ingress nginx no EKS em vez de ALB — defina `platformAnnotations.enabled: false`
e forneça as suas próprias:

```yaml
django:
  ingress:
    platformAnnotations:
      enabled: false
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "500m"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
  service:
    platformAnnotations:
      enabled: false
    annotations: {}
```

Quando `platformAnnotations.enabled` é `true` (o padrão), o chart mescla as
anotações de plataforma com suas anotações personalizadas. Suas anotações têm
precedência em caso de conflito de chaves, mas você não consegue remover uma anotação de plataforma
sem esse toggle.

### Limite de tamanho de upload do Ingress

Por padrão, o chart define `nginx.ingress.kubernetes.io/proxy-body-size: "2400m"`
no Ingress para que uploads grandes de resultados de scan e relatórios em PDF passem pelo
nginx-ingress sem um erro `413 Request Entity Too Large`. Sobrescreva via:

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

Isso se aplica sempre que o nginx-ingress for o controller — incluindo nginx-ingress
rodando sobre EKS, GKE ou AKS. Controllers que não são nginx ignoram a
anotação e devem ser ajustados por meio de seus próprios mecanismos (limites de inspeção de
corpo do AWS WAF, request-body-limit do AppGW, `tuningOptions` do HAProxy da Route do OpenShift).

---

## Notas Específicas de Plataforma

### AWS EKS

- Requer o AWS Load Balancer Controller para o ingress ALB
- Requer o driver CSI do EFS se estiver usando armazenamento EFS
- O TLS termina no ALB via certificados ACM
- Defina `certificates.ingress.source: "acm"` e forneça `acmCertArn`
- `dojo.secureCookies: true` funciona bem, já que o ALB lida com HTTPS

#### Access Points do EFS

Se o seu sistema de arquivos EFS estiver configurado com um **access point** (recomendado para
impor a propriedade de UID/GID no mount), você **deve** definir
`storage.efs.accessPointId` no seu arquivo de values. Sem isso, o PV monta a
raiz do EFS com propriedade de root, e os contêineres do DefectDojo (executando como UID 1001)
não conseguem criar subdiretórios de mídia — fazendo o initializer falhar com
erros de `Permission denied`.

Verifique os access points do seu EFS:

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

Se existir um access point, adicione-o ao seu arquivo de values:

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **Importante:** o campo `volumeHandle` do PersistentVolume é
> **imutável** após a criação. Se você instalar inicialmente sem um access
> point e depois precisar adicionar um, deverá excluir o PV e o PVC existentes
> antes de executar `helm upgrade`:
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> Isso é seguro — excluir o PV remove apenas a referência do Kubernetes; os dados
> no sistema de arquivos EFS não são afetados.

#### Storage Classes em clusters hardened / governados por GitOps

Duas suposições sobre storage class atrapalham clusters com nomenclatura personalizada de
StorageClass ou onde recursos de escopo de cluster são gerenciados fora do chart da aplicação.

**PVCs provisionados dinamicamente usam `gp3` por padrão no EKS.** Qualquer PVC que o chart
provisiona dinamicamente — o volume Redis incorporado (`redis.enabled: true`) e
o volume de mídia `storage.type: "pvc"` — resolve sua StorageClass para o
padrão da plataforma, que é `gp3` no EKS. Se o seu cluster não tiver uma StorageClass
chamada `gp3` (comum em clusters hardened com nomenclatura personalizada), o PVC permanece
em `Pending` com um evento `storageclass.storage.k8s.io "gp3" not found` e os
pods nunca sobem.

Sobrescreva isso de uma das duas formas:

- **Globalmente (recomendado)** — uma única alavanca para todo PVC provisionado pelo chart:

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- **Por componente**, se você precisar de classes diferentes:

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  A ordem de resolução é: valor por componente → `storage.defaultStorageClass` →
  padrão da plataforma (`gp3`). Defina um valor como `""` para recair no StorageClass
  padrão do cluster. Isso **não** se aplica ao caminho de mídia EFS padrão
  (veja abaixo), que não usa StorageClass.

**O volume de mídia EFS padrão não precisa de StorageClass.** Quando
`storage.type: "efs"`, o chart vincula o PV de mídia estaticamente via o `volumeHandle`
do sistema de arquivos EFS e um `claimRef` — tanto o PV quanto o PVC usam um
`storageClassName` vazio. A StorageClass `efs-sc` **não** precisa existir para que o
PVC de mídia se vincule.

O chart só cria uma StorageClass `efs-sc` de escopo de cluster se você optar explicitamente
por provisionamento **dinâmico** de EFS com `storageClasses.efs.enabled: true`
(padrão: `false`). Em clusters onde recursos de escopo de cluster são governados
fora do chart da aplicação (GitOps), deixe no padrão `false` — o
caminho estático de EFS acima não exige StorageClass nem objetos de escopo de cluster
deste chart. Se você realmente quiser provisionamento dinâmico de EFS sob GitOps, crie
a StorageClass fora de banda e mantenha `storageClasses.efs.enabled: false`.

### GCP GKE

- Usa o controller de ingress do GCE (`className: "gce"`) com o TLS terminando no
  load balancer do Google Cloud
- O preset `gcp-gke.yaml` anexa automaticamente um `FrontendConfig` (redirecionamento HTTP→HTTPS +
  política SSL) e um `BackendConfig` ao ingress
- O load balancer do GCE faz health-check do backend django diretamente a partir dos ranges
  do Google (`130.211.0.0/22`, `35.191.0.0/16`). As NetworkPolicies do chart permitem
  isso automaticamente no GKE em ambos os valores de `networkPolicy.profile`, de modo que
  o probe `/nginx_health` seja bem-sucedido e o backend reporte saudável — veja
  [Políticas de Rede](#network-policies)

#### TLS gerenciado pelo Google vs BYO

O preset `gcp-gke.yaml` usa **certificados gerenciados pelo Google** por padrão. Escolha
uma das duas abordagens:

- **Gerenciado pelo Google (padrão):** o GCP provisiona e renova o certificado. Basta
  listar seus domínios — nenhum secret TLS do Kubernetes é necessário:

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **Traga o seu próprio (BYO):** forneça um secret TLS do Kubernetes existente no
  namespace do release e aponte o ingress para ele:

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  Isso renderiza `spec.tls[].secretName` no ingress e omite a
  anotação `networking.gke.io/managed-certificates`.

> **Suporte do script de bootstrap:** `scripts/bootstrap/bootstrap-gcp-gke.sh` só
> cobre os fluxos de certificado nativos do GCP (`google-managed` e `pre-shared`). Para o
> caminho BYO `secret`, instale com `helm` diretamente (crie o secret TLS primeiro,
> depois passe `certificates.ingress.source=secret` e
> `certificates.ingress.secretName=<your-secret>`).

> A renovação de certificados gerenciados pelo Google é automática — veja
> [Rotacionando Certificados TLS](#rotating-tls-certificates).

### OpenShift / ROSA

- Usa Routes por padrão (`django.route.enabled: true`), mas Ingress também é suportado
- Para usar Ingress em vez disso: defina `django.ingress.enabled: true` e `django.route.enabled: false`
- Apenas um pode estar habilitado por vez (o chart valida a exclusividade mútua)
- **`dojo.secureCookies` deve ser `false`** ao usar Routes com terminação edge (o padrão).
  Isso é obrigatório — não opcional. Veja o [aviso em Preparando Seu Arquivo de Values](#prepare-your-values-file).
- `securityContext.openshift.fsGroup` deve corresponder ao range de supplemental-groups do seu
  namespace (veja a [Checklist de Pré-Instalação](#infrastructure-details) para saber como consultar isso)
- NFS via EFS funciona bem — use `storage.type: "nfs"` com o nome DNS do EFS como server

#### Usando Ingress em vez de Routes no OpenShift

O OpenShift vem com um controller de ingress padrão baseado em HAProxy. Se você preferir
Ingress em vez de Routes (por exemplo, por consistência com outros clusters ou para usar um
controller de ingress personalizado), configure seus values assim:

```yaml
django:
  ingress:
    enabled: true
    className: "openshift-default"   # or your custom ingress class
    platformAnnotations:
      enabled: false                 # recommended — provide your own annotations
    pathType: "Prefix"
    path: "/"
    tls:
      enabled: true
    annotations: {}                  # add your ingress controller annotations here
  route:
    enabled: false
  nginx:
    tls:
      enabled: false
      generateCertificate: false
```

Os helpers de plataforma do chart continuarão tratando corretamente os security contexts, o
resolver de DNS e os padrões de armazenamento para o OpenShift, independentemente do método
de exposição escolhido.

---

## Problemas Conhecidos (Versão do Chart 2.57.1)

Estes são bugs confirmados na versão atual do chart. As soluções alternativas estão
documentadas aqui até que uma versão corrigida seja lançada.

### Instalação minimal apenas com PostgreSQL ou Redis local

Os problemas a seguir só se aplicam se você estiver usando o PostgreSQL ou Redis
embutidos no chart (`postgresql.enabled: true` ou `broker.external: false`).
Eles não afetam implantações de produção que usam bancos de dados e brokers externos.

**Não use EBS para o volume de mídia (BUG-14, BUG-15)**

Os volumes EBS suportam apenas `ReadWriteOnce` — eles só podem ser anexados a um único
nó por vez. O DefectDojo exige que o volume de mídia seja compartilhado entre
múltiplos pods (django, celery-worker, initializer, connectors), que podem estar
agendados em nós diferentes. Quando isso acontece, os pods ficam presos em
`ContainerCreating` com um erro `Multi-Attach error`, porque o EBS não consegue montar o
volume em mais de um nó simultaneamente. Isso também afeta o `helm test`,
onde o pod de test-storage pode ser agendado em um nó diferente dos
pods da aplicação.

**Use EFS (ou outro backend de armazenamento com suporte a `ReadWriteMany`) em vez de EBS
para o volume de mídia.** O EFS suporta acesso concorrente de todos os nós do
cluster e é o backend de armazenamento recomendado para implantações no EKS.

Se você precisar usar EBS para testes em um cluster de nó único, sobrescreva os
padrões:

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

Tenha em mente que, mesmo com esse override, o EBS vai falhar assim que os pods forem
agendados em múltiplos nós (por exemplo, durante escalonamento, substituição de nó ou
`helm test`). O EFS evita isso completamente.

**Init container do PostgreSQL entra em conflito com security context non-root (BUG-16)**

Desabilite-o se você encontrar `CreateContainerConfigError`:

```yaml
postgresql:
  initContainer:
    enabled: false
```

### Todas as implantações

**Pod de connectors em crashloop enquanto o initializer está em execução (Comportamento Esperado)**

Durante a primeira instalação, o pod de connectors entrará em `CrashLoopBackOff`
enquanto o job do initializer está executando as migrations do banco de dados. Isso é esperado —
o pod de connectors tenta chamar a API do Django (`/api/connectors/v1/config/`),
que retorna um 500 porque o schema do banco de dados ainda não foi totalmente migrado.
Assim que o job do initializer for concluído com sucesso (mostrando `1/1 COMPLETIONS` em
`kubectl get jobs`), o pod de connectors se recuperará no próximo ciclo de reinício.
Nenhuma intervenção manual é necessária.

**Falha do initializer após as migrations deixa o banco de dados em estado irrecuperável (BUG-18)**

Se o job do initializer falhar **depois** de executar as migrations do banco de dados mas
**antes** de popular os dados iniciais (por exemplo, devido a erros de permissão de armazenamento
ou limites de recursos), o banco de dados fica em um estado parcialmente inicializado — as tabelas
existem, mas a tabela `dojo_system_settings` está vazia. Em reinícios subsequentes,
o initializer falha imediatamente com:

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

Isso cria um loop de crash sem recuperação automática. **Solução alternativa:** redefina o
schema do banco de dados e execute o initializer novamente:

```bash
# Drop and recreate the public schema
kubectl run psql-reset --rm -i --tty=false --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d <your-db-name> -U <your-db-user> \
     -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO <your-db-user>;"

# Delete the failed initializer job and trigger a new one
kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
helm upgrade dojopro $CHART ... (same flags as install)
```

> **Prevenção:** garanta que as permissões de armazenamento (especialmente os access points do EFS —
> veja [Access Points do EFS](#efs-access-points)) e os limites de recursos estejam corretamente
> configurados **antes** da primeira instalação. Execute `helm template` para validar seus
> values e verifique as permissões de mount do EFS com um pod de teste, se possível.

**Aviso de token do Hatchet nos logs (Informativo)**

Quando `hatchet.enabled: false` (o padrão), os pods registrarão o seguinte
aviso na inicialização:

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

Isso é **esperado e inofensivo**. A partir do chart 2.57, a execução de workflows em
segundo plano foi consolidada em `ddorch` + `ddorch-workers`, que substituem os
workers legados baseados em Hatchet (`kairos`, `rulesengine`,
`hatchet-integrators`). O código do cliente Hatchet ainda é inicializado na
inicialização, então o aviso continua aparecendo quando o Hatchet está desabilitado, mas nada
depende dele. O aviso pode ser ignorado com segurança.

### HTTPS não configurado

**A anotação ssl-redirect do ALB exige um listener HTTPS (BUG-17)**

O preset do EKS inclui uma anotação `ssl-redirect` que assume que existe um listener
HTTPS no ALB. Se você não configurou um certificado ACM e um listener
HTTPS, essa anotação causa um loop de redirecionamento. Configure o HTTPS
(recomendado) ou veja
[Implantando Sem HTTPS (Não Recomendado)](#deploying-without-https-not-recommended)
para o conjunto completo de alterações necessárias.

---

## Solução de Problemas

### Pods presos em CrashLoopBackOff

Verifique os logs:
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

Geralmente é um dos seguintes: secrets ausentes ou incorretos (verifique todas as 12 chaves), banco de dados
inacessível (verifique `database.host` e os security groups), ou certificado TLS interno ausente
(verifique se o secret `dojopro-internal-tls` existe).

### Misturando secrets externos e inline

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

Escolha uma abordagem. Se você estiver usando `dojo.existingSecret`, remova todos os valores
de secret inline (`dojo.secretKey`, `dojo.admin.password`, `monitoring.password`, etc.)
dos seus arquivos de values.

### O schema diz que admin.password é obrigatório

Defina `dojo.existingSecret` — o schema remove a exigência de senha quando
um secret externo está configurado.

### Erros de permissão de fsGroup no OpenShift

Se os pods falharem com erros de permissão em volumes NFS, verifique se
`securityContext.openshift.fsGroup` está dentro do range de supplemental-groups do seu
namespace. Veja a consulta de fsGroup em
[Implantação → OpenShift / ROSA](#openshift-rosa).

### ALB não aparece (EKS)

Verifique se o AWS Load Balancer Controller está em execução:
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

Verifique os eventos do ingress:
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## Apêndice: Template de Configuração do Cliente

O template completo (`template.yaml`) está disponível no portal de suporte do
DefectDojo ou em support@defectdojo.com. Copie-o, substitua os placeholders
`REPLACE_*` e remova as seções que não se aplicam à sua plataforma. O
template inclui exemplos comentados para:

- Identificação de plataforma (`cloudProvider`)
- Configuração de image pull secret
- Configuração de Ingress e Route (Ingress para EKS/GKE/OpenShift, Route para OpenShift)
- Opções de armazenamento EFS e NFS
- Configuração de certificado e TLS
- Security contexts (uwsgi, nginx, fsGroup do OpenShift)
- Políticas de rede
- Opções de entrega de licença (arquivo, secret, inline)

---

## Histórico de Revisões

| Data       | Versão | Alterações                                                              |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | Adiciona o PSIRT Advisory Engine opcional (`psirt.enabled`): servido em `/psirt/` via o sidecar nginx, banco de dados dedicado via `psirt.databaseUrl`, orientação de pinning de secret, regras de política de rede, hooks BYO |
| 2026-04-17 | 2.57.1  | Documenta `ddorch` + `ddorch-workers` (novo par de orquestradores que substitui kairos/rulesengine/hatchet-integrators); adiciona os flags `--set-file` `ddorch.tls.rootCa/cert/key` aos comandos de pre-flight e deploy; nova seção de certificados mTLS do ddorch com requisitos de SAN; mcp-server listado nos pods esperados; PDBs adicionados para o ddorch (singleton) e ddorch-workers; nota de pré-requisitos do ArgoCD sobre a entrega de certificado do ddorch; atualiza o aviso do Hatchet para refletir a consolidação de workers |
| 2026-03-25 | 2.55.4  | Adiciona documentação de access point do EFS e campo de template; documenta a recuperação de crash do initializer (BUG-18); documenta o crashloop dos connectors durante a inicialização como esperado; esclarece que o aviso de token do Hatchet é inofensivo; corrige âncora obsoleta de problemas conhecidos; caminho de extração do chart com versão; consolida a orientação sem HTTPS; limpeza de PV na desinstalação; nota de consistência de namespace; observação sobre versionamento de preset ArgoCD vs CLI |
| 2026-03-11 | 2.53.0  | Corrige caminhos de comando do helm; adiciona extração do chart, pré-requisitos do EKS, verificação de BD pre-flight, aviso de HTTPS, rotação de TLS, seção de problemas conhecidos |
