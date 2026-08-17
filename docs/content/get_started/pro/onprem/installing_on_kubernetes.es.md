---
title: Guía de instalación de DefectDojo Pro
description: Instale DefectDojo Pro en Kubernetes mediante el chart de Helm, abarcando
  la infraestructura, los secretos y la instalación en sí
draft: false
weight: 13
audience: pro
---

<!--
  Generado a partir del repositorio del chart de Helm de DefectDojo Pro.
  Fuente: docs/INSTALLATION_GUIDE.md en la versión de chart 3.1.304.
  Edite la guía de origen, no este archivo. Las modificaciones locales se
  sobrescriben la próxima vez que se publique el chart.
-->
Cubre la implementación en AWS EKS y OpenShift (ROSA). El flujo de trabajo es
el mismo para ambos: configurar la infraestructura, crear los secretos e
instalar el chart.

---

## Lista de verificación previa a la instalación

Reúna la siguiente información antes de comenzar. Tenerla lista evita
retrasos durante el proceso de instalación.

### Detalles de la infraestructura

| Elemento | Ejemplo | Dónde encontrarlo |
|------|---------|-------------------|
| **Host de PostgreSQL** | `mydb.abc123.us-east-1.rds.amazonaws.com` | Consola de AWS RDS o `aws rds describe-db-instances` |
| **Puerto de PostgreSQL** | `5432` | Normalmente 5432, salvo que se haya personalizado |
| **Nombre de la base de datos PostgreSQL** | `dojodb` | Su DBA o las salidas de Terraform/CloudFormation; debe crearse antes de la instalación (vea la nota siguiente) |
| **Base de datos del orquestador** | `dojodb-ddorch` | Otorgue al rol de la aplicación el privilegio `CREATEDB` o cree previamente `<dbname>-ddorch`; consulte [Verificación previa: base de datos del orquestador (ddorch)](#pre-flight-orchestrator-ddorch-database) |
| **Nombre de usuario de PostgreSQL** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **Contraseña de PostgreSQL** | — | AWS Secrets Manager, el estado de Terraform o su DBA |
| **Endpoint de Redis/ElastiCache** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Contraseña de Redis** | — | Omítala si la autenticación está deshabilitada (solo VPC). Verifique con: `aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **ID del sistema de archivos EFS** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **ID del punto de acceso de EFS** (si corresponde) | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **UID/GID del punto de acceso de EFS** | UID `1001`, GID `1337` | Debe coincidir con el contexto de seguridad del contenedor (vea la nota siguiente) |
| **Nombre de dominio (FQDN)** | `dojo.example.com` | Su administrador de DNS (vea las notas específicas de la plataforma más abajo) |
| **ARN del certificado ACM** (EKS con HTTPS) | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **Dominio de apps de OpenShift** (solo ROSA) | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **fsGroup del namespace de OpenShift** (solo ROSA) | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'`: use el valor inicial |
| **Archivo de licencia** | `onprem-dojopro.lic` | Proporcionado por el soporte de DefectDojo |

> **Cree las bases de datos antes de instalar.** El chart no crea bases de
> datos en un servidor PostgreSQL externo. Cree ambas bases de datos
> siguientes en su servidor de base de datos, con el usuario de la
> aplicación como propietario, antes de ejecutar `helm install`:
>
> - `dojodb`: la base de datos principal de DefectDojo
> - `dojodb-ddorch`: la base de datos del orquestador (ddorch), siempre
>   nombrada como la base de datos principal con el sufijo `-ddorch`. Como
>   alternativa, otorgue al rol de la aplicación el privilegio `CREATEDB` y
>   ddorch la creará por sí mismo en el primer arranque.
>
> Consulte [Verificación previa: comprobar la conectividad de la base de datos](#pre-flight-verify-database-connectivity)
> y [Verificación previa: base de datos del orquestador (ddorch)](#pre-flight-orchestrator-ddorch-database)
> para ver comandos `CREATE DATABASE` listos para ejecutar.

> **UID/GID del punto de acceso de EFS:** Si su sistema de archivos EFS usa
> un punto de acceso, su configuración de usuario POSIX **debe** usar UID
> `1001` y GID `1337` para coincidir con el contexto de seguridad del
> contenedor de DefectDojo. Una discrepancia provoca errores de `Permission
> denied` durante la inicialización, cuando los contenedores intentan crear
> los subdirectorios de medios. Verifíquelo con:
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **FQDN de OpenShift/ROSA:** En ROSA, las Routes generan automáticamente
> nombres de host con el patrón `<release-name>-<namespace>.apps.<cluster-domain>`.
> Por ejemplo, si su release es `dojopro` en el namespace `dojopro`, el nombre
> de host de la Route será `dojopro-dojopro.apps.abc123.p1.openshiftapps.com`.
> Determine el dominio de apps de su clúster con:
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```
>
> Use el FQDN resultante para `dojo.fqdn`, `dojo.url` y `dojo.hosts.main`.

> **fsGroup de OpenShift/ROSA:** Necesitará el valor inicial de
> supplemental-groups de su namespace para `securityContext.openshift.fsGroup`.
> Búsquelo ahora para evitar tener que editar su archivo de valores más
> adelante:
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### Secretos que se deben generar

Los siguientes secretos deben generarse de forma nueva para su
implementación. Use los comandos indicados para crear valores
criptográficamente aleatorios:

| Secreto | Clave en el Secret de K8s | Generar con |
|--------|-------------------|---------------|
| Clave secreta de Django | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| Clave de cifrado AES-256 | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| Secreto del portal en la nube | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| Secreto compartido de los conectores | `DD_CONNECTORS_SHARED_SECRET` | Use el mismo valor que `CLOUD_PORTAL_SECRET_KEY` |
| Contraseña de administrador | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| Contraseña de métricas | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### Secretos provenientes de su infraestructura

Estos provienen de su infraestructura existente; no los genere:

| Secreto | Clave en el Secret de K8s | Origen |
|--------|-------------------|--------|
| Contraseña de la base de datos | `DD_DATABASE_PASSWORD` | Su contraseña de PostgreSQL |
| URL de conexión a la base de datos | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Contraseña de Redis | `redis-password` (en un secret `dojopro-redis` independiente) | Su contraseña de Redis, u omítala si no hay autenticación |
| URL del servicio de correo | `DD_EMAIL_URL` | `consolemail://` para pruebas, o su URL de SMTP |

### Opcional (déjelo vacío para deshabilitar)

| Secreto | Clave en el Secret de K8s | Propósito |
|--------|-------------------|---------|
| Clave del bucket de EPSS | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | Enriquecimiento de la puntuación EPSS |

> **Consejo:** copie `secrets-template.yaml` y complete los valores
> anteriores. Consulte [Generar secretos](#generate-secrets) para obtener
> instrucciones detalladas sobre cómo crear el Secret de Kubernetes.

---

## Requisitos previos

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

Para OpenShift/ROSA, instale también:
```bash
brew install rosa openshift-cli
```

### Requisitos de conectividad saliente

En entornos de red restringidos, deben permitirse las siguientes conexiones
salientes antes de la instalación. Las reglas de firewall pueden requerir
solicitudes de cambio con antelación; verifique que estén implementadas antes
de continuar.

**Registro de contenedores (obligatorio)**

Todos los nodos del clúster deben poder alcanzar el registro de contenedores
de DefectDojo por el puerto 443:

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> Para entornos aislados (air-gapped), consulte
> [Registro privado/entornos aislados](#private-registry-air-gapped-environments).

**Base de datos (obligatorio)**

Nodos del clúster hacia su instancia de PostgreSQL, normalmente por el
puerto 5432.

- RDS en la misma VPC: asegúrese de que el grupo de seguridad de los nodos de
  EKS tenga permitido el tráfico entrante por el puerto 5432
- RDS en una VPC o cuenta diferente: se requiere VPC peering o Transit
  Gateway
- Externo/local: la ruta de VPN o Direct Connect debe permitir el puerto
  5432

**Actualizaciones de EPSS (recomendado)**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**Fuente de KEV (recomendado)**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**Servicios de AWS (solo EKS, obligatorio)**

El controlador EBS CSI y el ALB Controller requieren acceso a los endpoints
de la API de AWS por el puerto 443:

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com` (si usa EFS)

### Requisitos previos de AWS EKS

Los siguientes componentes deben estar instalados en su clúster EKS antes de
implementar DefectDojo Pro. Sin ellos, la implementación fallará.

**Controlador EBS CSI** (solo obligatorio si usa el perfil mínimo con
PostgreSQL y Redis integrados; no es necesario si usa RDS y ElastiCache
externos):

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

**Controlador EFS CSI** (obligatorio si usa almacenamiento EFS, el backend de
almacenamiento recomendado para implementaciones EKS con múltiples
réplicas):

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

**AWS Load Balancer Controller** (obligatorio para el ingress de ALB):

Las instrucciones de instalación varían según la versión de EKS. Siga la
[guía oficial de instalación de AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/).

---

## Extraer el paquete del chart

El chart se distribuye como un zip que contiene un paquete Helm `.tgz`.
Extraiga ambos antes de continuar. Use una ruta de extracción con versión
para evitar sobrescribir silenciosamente los presets cuando extraiga una
versión más reciente del chart más adelante:

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

Defina una variable `CHART` que apunte al directorio del chart extraído.
Todos los comandos `helm` posteriores en esta guía usan `$CHART`:

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **Por qué la extracción es necesaria para los usuarios de la CLI:** los
> archivos de presets (`presets/platforms/*.yaml`, `presets/profiles/*.yaml`)
> vienen incluidos dentro del paquete `.tgz`. `helm install -f` requiere
> archivos en el sistema de archivos local: no puede leer archivos desde
> dentro de un `.tgz` empaquetado. Debe extraer el chart para acceder a los
> presets.
>
> **Los usuarios de ArgoCD no necesitan extraer nada.** ArgoCD lee
> `valueFiles` directamente desde dentro del paquete del chart. Consulte
> [Implementar con ArgoCD](#deploy-with-argocd).

---

## Prepare su archivo de valores

La plantilla de configuración del cliente (`template.yaml`) y la plantilla de
secretos (`secrets-template.yaml`) están disponibles por separado en el
portal de soporte de DefectDojo, o solicitándolas a support@defectdojo.com.
No se incluyen en el `.tgz` del chart. Una vez que tenga la plantilla,
cópiela y complete sus datos:

```bash
cp template.yaml my-company.yaml
```

Como mínimo, configure lo siguiente:

| Configuración | Descripción |
|---------|-------------|
| `dojo.fqdn` | Su nombre de dominio (ROSA: consulte la [nota sobre FQDN](#infrastructure-details) anterior) |
| `dojo.url` | URL completa, incluido el protocolo (por ejemplo, `https://dojo.example.com`) |
| `dojo.hosts.main` | Debe coincidir con su FQDN |
| `dojo.secureCookies` | Configúrelo como `false` en **OpenShift/ROSA** (vea la advertencia siguiente) |
| `dojo.admin.*` | `user`, `email`, `firstName`, `lastName`: cuenta de administrador |
| `database.host`, `.port`, `.name`, `.user` | Datos de conexión de PostgreSQL (la contraseña va en los secretos) |
| `celery.broker.host` | Su endpoint de Redis/ElastiCache |
| `redis.enabled` | **Debe ser `false`** si usa un Redis externo (vea la advertencia siguiente) |
| `storage.type` | Backend de almacenamiento; consulte las notas específicas de la plataforma |
| `certificates.*` | Configuración de certificados TLS |
| `django.ingress.*` o `django.route.*` | Ingress (EKS) o Route (OpenShift); el preset define los valores predeterminados |
| `securityContext.openshift.fsGroup` | **Solo ROSA**: valor inicial de supplemental-groups del namespace |

> **ADVERTENCIA:** `redis.enabled` debe configurarse explícitamente como
> `false` cuando se usa un Redis/ElastiCache externo. Los presets de perfil
> `standard` y `performance` configuran `redis.enabled: true` de forma
> predeterminada. Si su archivo de valores no anula esto, el chart
> implementará un Redis dentro del clúster **junto con** su broker externo,
> lo que da como resultado una configuración incorrecta. Agregue esto a su
> archivo de valores:
>
> ```yaml
> redis:
>   enabled: false
> ```

> **ADVERTENCIA:** `dojo.secureCookies` debe ser `false` en OpenShift/ROSA.
> Al usar Routes de OpenShift con terminación TLS en el borde (edge),
> `secureCookies: true` (el valor predeterminado en `template.yaml`) provoca
> bucles de redirección y fallos de inicio de sesión. Esto no es opcional:
> las Routes con terminación en el borde requieren:
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**Notas sobre almacenamiento:**
- **EKS:** use EFS, no EBS. Los volúmenes EBS no se pueden compartir entre
  nodos, lo que provoca errores de `Multi-Attach`. Consulte [Problemas
  conocidos](#known-issues-chart-version-2.57.1). Si su EFS usa un punto de
  acceso, configure también `storage.efs.accessPointId`; consulte [Puntos de
  acceso de EFS](#efs-access-points).
- **OpenShift/ROSA:** el preset de la plataforma usa de forma predeterminada
  `storage.type: "pvc"` con `createNew: true`, lo que utiliza el
  StorageClass predeterminado del clúster. Para implementaciones con varios
  nodos, use NFS a través de EFS (`storage.type: "nfs"`).

De manera opcional, configure el nivel de detalle de los registros:
- `config.logLevel`: nivel de registro de la aplicación Django (valor
  predeterminado: `"INFO"`)
- `celery.logLevel`: nivel de registro del worker/beat de Celery (valor
  predeterminado: `"INFO"`)

Configure cualquiera de los dos como `"DEBUG"` para solucionar problemas.
Consulte [Nivel de detalle de los registros](#log-verbosity) para saber cómo
activarlo en tiempo de ejecución sin editar su archivo de valores.

No coloque secretos ni el contenido de la licencia en este archivo. Estos se
tratan en las dos secciones siguientes.

Consulte `template.yaml` para ver la lista completa de opciones.

### Verificación previa: comprobar la conectividad de la base de datos

Confirme que su base de datos sea accesible antes de continuar; esto
ahorrará bastante tiempo de resolución de problemas más adelante. Cree un
pod temporal con `psql`:

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

Una conexión exitosa se ve así:

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

Si esto falla con `database "dojodb" does not exist`, su instancia de RDS es
accesible, pero la base de datos aún no se ha creado. Créela:

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

Luego vuelva a ejecutar la comprobación de conectividad anterior para
confirmarlo.

Si falla por otros motivos, revise lo siguiente:
- **Reglas de grupo de seguridad/firewall**: el puerto 5432 debe estar
  abierto desde el clúster hacia el host de la base de datos
- **Privilegios del usuario de la base de datos**: el usuario debe tener
  permisos CREATE, ALTER y SELECT en la base de datos de destino, además de
  `CREATEDB` o una base de datos del orquestador creada previamente (vea la
  siguiente sección)

> El chart también incluye comprobaciones integradas: un init container que
> espera la conectividad TCP con la base de datos, y `helm test`, que valida
> una conexión completa a PostgreSQL después de la implementación. Este paso
> de verificación previa detecta problemas antes de que invierta tiempo
> creando secretos y ejecutando `helm install`.

### Verificación previa: base de datos del orquestador (ddorch)

El orquestador (`ddorch`, habilitado de forma predeterminada) almacena su
estado de flujo de trabajo en una **segunda base de datos**, junto a la base
de datos principal de DefectDojo. Al iniciar, toma el nombre de la base de
datos de `DD_DATABASE_URL`, le agrega `-ddorch` y crea esa base de datos si
no existe; si la base de datos principal es `dojodb`, el orquestador usa
`dojodb-ddorch`.

Si al rol de la aplicación no se le permite crear bases de datos, el pod de
ddorch falla al iniciar con:

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

Cumpla con **una** de las siguientes opciones antes de instalar:

**Opción A: otorgue `CREATEDB` al rol de la aplicación** y deje que ddorch
cree su base de datos en el primer arranque:

```sql
ALTER ROLE defectdojo CREATEDB;
```

**Opción B: cree previamente la base de datos del orquestador**, con el
nombre de su base de datos principal más el sufijo `-ddorch`, y con el mismo
usuario de la aplicación como propietario. El guion en el nombre requiere
comillas dobles en SQL:

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

Usando el mismo enfoque de pod temporal que en la comprobación de
conectividad anterior:

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## Generar secretos

Aquí hay dos opciones.

### Opción A: Secret externo (recomendado para GitOps)

Cree un Secret de Kubernetes con las 12 claves requeridas antes de instalar
el chart. Use `secrets-template.yaml`, proporcionado por el soporte de
DefectDojo, como punto de partida (consulte [Prepare su archivo de
valores](#prepare-your-values-file) para saber cómo obtenerlo):

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

Edite el archivo, reemplace todos los valores de marcador de posición y
luego aplíquelo:
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

El secret también puede administrarse con External Secrets Operator, Sealed
Secrets o cualquier otra herramienta que cree Secrets de Kubernetes. Al
chart no le importa cómo llegó el secret; solo configure `dojo.existingSecret`
con su nombre.

En el momento de la instalación:
```bash
--set dojo.existingSecret=dojopro-secrets
```

El chart omite automáticamente la generación de su Secret integrado cuando
se configura `dojo.existingSecret`; no se necesitan indicadores adicionales.

Si su Redis externo requiere autenticación, `secrets-template.yaml` también
incluye un Secret `dojopro-redis` independiente. El chart lee las
credenciales de Redis desde `redis.auth.existingSecret` (valor
predeterminado: `dojopro-redis`). Si su Redis no tiene contraseña (por
ejemplo, un ElastiCache solo de VPC), puede omitirlo.

### Opción B: secretos en línea (más simple, no apto para GitOps)

Pase los valores de los secretos directamente en un archivo de valores:

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

Guarde esto como `my-secrets.yaml` y páselo con `-f` en el momento de la
instalación.

> No incluya archivos de secretos en el control de versiones.

---

## Crear certificados TLS internos

El chart necesita certificados TLS internos para la comunicación entre
servicios.

Cree dos secrets TLS de Kubernetes en su namespace antes de instalar:

1. `dojopro-internal-tls`: un secret TLS con `tls.crt` y `tls.key` para el
   cifrado entre servicios (nginx ↔ connectors, etc.)
2. `dojopro-internal-ca`: un secret que contiene el certificado de la CA
   bajo la clave `ca.crt`, usado por los connectors para validar el
   certificado TLS interno

Puede generar una CA y un certificado de servidor autofirmados con
`openssl`, o usar la CA interna de su organización. El CN/SAN del
certificado del servidor **debe** cubrir el nombre del servicio nginx
interno usado por el release de Helm. De forma predeterminada, este es
`<release-name>-nginx` (por ejemplo, `dojopro-nginx` si su release se llama
`dojopro`).

Ejemplo de generación de una CA y un certificado de servidor autofirmados:
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

> **Error común:** usar `nginx-internal` como CN/SAN en lugar de
> `<release-name>-nginx`. El pod de connectors valida el certificado TLS
> contra el nombre de servicio real
> (`<release-name>-nginx.<namespace>.svc.cluster.local`), y fallará con un
> error `x509: certificate is valid for ... not ...` si el SAN no coincide.

Luego configure en su archivo de valores:
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

### Certificados mTLS de ddorch

Además de los secrets TLS internos anteriores, el orquestador `ddorch`
requiere un trío de certificados mTLS independiente, usado por el servidor
ddorch y por cada worker que se comunica con él (`ddorch-workers`,
`integrators`). Estos se entregan al chart en el momento de la instalación
mediante `--set-file` (**no** se leen de un secret de Kubernetes
preexistente):

- `orch_tls_root.ca`: certificado de la CA
- `orch_tls.crt`: certificado del servidor
- `orch_tls.key`: clave privada del servidor

Sin estos tres archivos, `helm install` falla con
`ddorch.tls.rootCa is required`.

El SAN del certificado del servidor **debe** incluir todos los nombres de
host que los workers usan para llegar a ddorch:

- `ddorch`: nombre corto del servicio dentro del clúster
- `<release-name>-ddorch`: nombre de servicio completo (por ejemplo,
  `dojopro-ddorch`)
- `<release-name>-ddorch.<namespace>.svc.cluster.local`: FQDN del clúster
- `nginx`: el `SERVER_TLS_SERVER_NAME` predeterminado usado por los workers
  de tipo hatchet
- `localhost`, `127.0.0.1`: workers en el mismo pod que llegan a ddorch a
  través del loopback de hostAlias

Ejemplo de generación del trío:

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

Páselos a `helm install`/`helm template`:

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> El script auxiliar `scripts/bootstrap-aws-eks.sh` genera y reutiliza estos
> certificados automáticamente mediante `dojopro-orch-certs-configmap`; si
> usa ese script, no necesita crearlos manualmente.

---

## Licencia

El chart necesita una licencia de DefectDojo Pro.

### Inspeccionar su licencia

Antes de implementar, verifique que su licencia sea válida y no haya
expirado:

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

Esto muestra los metadatos de la licencia, incluidos:
- `not_after`: fecha de vencimiento de la licencia
- `license_package`: confirma su nivel

> **Secretos de extracción de imágenes:** cuando se configura
> `images.pullSecrets.extractFromLicense: true` (el valor predeterminado en
> los presets de plataforma), el chart extrae automáticamente la cuenta de
> servicio de GCP incrustada en su archivo de licencia y crea el secret de
> extracción de imágenes necesario para obtener las imágenes de DefectDojo
> del registro de contenedores. No se requiere extracción ni decodificación
> manual. Si en cambio usa un registro privado, configure
> `extractFromLicense: false` y proporcione su propio secret de extracción;
> consulte [Registro privado/entornos aislados](#private-registry-air-gapped-environments).

### Opción 1: --set-file (instalación estándar de Helm)

Pase el archivo de licencia en el momento de la instalación:
```bash
--set-file license.contents=/path/to/license.lic
```

### Opción 2: Secret existente (GitOps/ArgoCD)

Cree un Secret de Kubernetes que contenga la licencia y luego indíquele al
chart que lo use. Esto evita tener que usar `--set-file` o almacenar la
licencia en git.

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

Luego, en su archivo de valores o en las opciones de helm:
```yaml
license:
  existingSecret: "dojopro-license"
```

El secret puede administrarse con External Secrets Operator, Sealed
Secrets o kubectl simple.

> **Importante:** `license.existingSecret` **no es compatible** con la
> configuración predeterminada `images.pullSecrets.extractFromLicense: true`.
> El chart necesita que el contenido de la licencia esté disponible en el
> momento de la generación (render) para extraer las credenciales del
> registro de contenedores incrustadas. Si usa `license.existingSecret`,
> también debe deshabilitar la extracción automática del secret de
> extracción de imágenes y proporcionar el suyo propio:
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```
>
> Si desea que el chart extraiga automáticamente los secretos de extracción
> a partir de la licencia (el valor predeterminado), use en su lugar la
> **Opción 1** (`--set-file license.contents=`).


---

## Modo FIPS 140-3 (opcional)

Para entornos sujetos a FedRAMP **SC-13** o similares, el chart puede
implementar las variantes de imagen `-fips`, cuya criptografía se realiza
mediante el **OpenSSL FIPS Provider 3.1.2** (certificado CMVP del NIST
**n.º 4985**) y, para los servicios en Go, el **Go Cryptographic Module
v1.0.0** (CMVP **n.º 5247**).

La aplicación de esta política ocurre dentro del contenedor, por lo que no
se requiere un kernel de host habilitado para FIPS; esto es lo que hace que
sea viable en runtimes administrados donde el sistema operativo del host no
está bajo su control.

Deshabilitado de forma predeterminada; la salida generada no cambia cuando
está desactivado.

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

Las imágenes con la etiqueta `-fips` deben estar disponibles en su
registro. Póngase en contacto con hello@defectdojo.com para obtener acceso.

### Componentes sin variante FIPS

Sensei y el PostgreSQL/Redis **integrados** no tienen una compilación FIPS:
la imagen de valkey incluida está basada en Alpine, que no cuenta con
OpenSSL validado para FIPS. Por lo tanto, una instalación FIPS debe usar
almacenes de datos externos y dejar Sensei deshabilitado:

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

Con `fips.validate: true` (el valor predeterminado), el chart **falla al
generarse** si habilita FIPS junto con cualquiera de ellos, indicando los
componentes responsables:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

Esto es intencional. Una implementación en la que la mayoría de los
servicios usan criptografía validada, y uno o dos no lo hacen de forma
silenciosa, es peor que un fallo evidente: parece conforme y solo se
descubre durante una evaluación. Configure `fips.validate: false` únicamente
si ha aceptado ese riesgo de forma explícita.

### Verificar después de la implementación

Cada pod ejecuta una comprobación de inicio de tipo fail-closed: si el
proveedor validado no está activo, el contenedor se cierra en lugar de
servir tráfico. La evidencia que imprime suele ser lo que un evaluador
necesita:

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

Los cambios de comportamiento a tener en cuenta (el hash de contraseñas pasa
a PBKDF2, ChaCha20 se elimina de la lista de cifrados TLS) se describen en
la página del Modo FIPS 140-3 de la documentación del producto.

---

## Verificación previa: validar plantillas

Antes de instalar, ejecute `helm template` para renderizar y validar todos los manifiestos
sin tocar el clúster. Esto detecta errores de valores, campos obligatorios
faltantes y problemas de YAML antes de comprometerse con `helm install`:

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

Use las mismas opciones que planea pasar a `helm install`. Si esto finaliza sin errores,
sus valores son válidos. Si falla, el mensaje de error identificará el campo faltante
o inválido; corrija su archivo de valores y vuelva a ejecutarlo hasta que pase.

---

## Implementar

Combine su overlay de plataforma, el perfil de recursos, los valores del cliente y las
opciones de secretos y licencia que eligió anteriormente.

### AWS EKS

> **Se recomienda encarecidamente usar HTTPS para el acceso desde el navegador en EKS.**
> Cuando el TLS de ingress está activo, el chart habilita automáticamente
> `SECURE_SSL_REDIRECT` y establece las cookies de CSRF/sesión como `Secure`, lo que
> significa que el inicio de sesión desde el navegador fallará sin un listener HTTPS en el ALB.
> Configure un certificado ACM antes de implementar para obtener la mejor experiencia.
>
> Si necesita ejecutar sin HTTPS, consulte
> [Implementar sin HTTPS (no recomendado)](#deploying-without-https-not-recommended)
> a continuación.

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **Consistencia del namespace:** el valor del namespace debe coincidir en todos los
> recursos: su YAML de secretos (`metadata.namespace`), `kubectl create namespace`
> y `helm install -n`. Si usa un namespace personalizado en lugar de `dojopro`,
> reemplácelo de forma consistente en todos los comandos y manifiestos de secretos.

**Secretos externos + secreto de licencia (GitOps):**

Aplique sus secretos si aún no lo ha hecho (consulte [Generar secretos](#generate-secrets)),
luego instale:

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

**Secretos en línea + archivo de licencia (más simple):**
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

#### Implementar sin HTTPS (no recomendado)

> **Advertencia:** ejecutar sin HTTPS significa que las cookies de sesión se envían en
> texto plano y la protección CSRF mediante cookies seguras queda deshabilitada. No use
> esta configuración en producción.

Si necesita implementar sin HTTPS temporalmente (por ejemplo, para pruebas iniciales sin
un certificado ACM), aplique **todos** los siguientes cambios en su archivo de valores:

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

Los cuatro cambios son obligatorios. Si falta alguno, se producirán bucles de
redirección o fallos en el inicio de sesión. Cuando esté listo para habilitar HTTPS,
revierta estos cambios y configure un certificado ACM.

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **Recordatorio:** ya debería tener el valor `fsGroup` de su namespace de la
> [Lista de verificación previa a la instalación](#infrastructure-details). Si no, búsquelo ahora:
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**Secretos externos + secreto de licencia (GitOps):**

Aplique sus secretos si aún no lo ha hecho (consulte [Generar secretos](#generate-secrets)),
luego instale:

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

**Secretos en línea + archivo de licencia (más simple):**
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

## Implementar con ArgoCD

DefectDojo Pro es totalmente compatible con ArgoCD. El chart incluye presets de
plataforma y de perfil que ArgoCD puede referenciar directamente como `valueFiles`.

### Requisitos previos

Antes de crear la Application de ArgoCD, los siguientes recursos de Kubernetes
deben existir en el namespace de destino:

- Los secretos de la aplicación (consulte [Generar secretos](#generate-secrets))
- El secreto de licencia (consulte [Licencia](#license))
- Los secretos de TLS interno, si no usa autogeneración (consulte [Crear certificados TLS internos](#create-internal-tls-certificates))
- El material de mTLS de ddorch (consulte [Certificados mTLS de ddorch](#ddorch-mtls-certificates)). ArgoCD no tiene un equivalente de `--set-file`, así que pase el contenido de los tres PEM mediante parámetros de la Application (`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`). Use un plugin de gestión de secretos de ArgoCD (Sealed Secrets, External Secrets o un plugin de ConfigMap) en lugar de confirmar la clave en texto plano.

### Cómo funciona

ArgoCD referencia los archivos de preset de forma relativa a la raíz del chart. Su
especificación de Application necesita tres cosas:

1. Los presets de plataforma y de perfil como `valueFiles`
2. Su configuración específica del entorno (mediante `valueFiles`, `values` en línea, o ambos)
3. Las referencias de secreto y licencia como `parameters`

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

### Cómo proporcionar su configuración

Hay varias formas de proporcionar sus valores específicos del entorno a ArgoCD:

- `values` en línea en la especificación de la Application: el enfoque más simple, sin
  necesidad de archivos ni repositorios adicionales. Funciona bien cuando su configuración
  es sencilla.
- Un archivo de valores en un repositorio git separado: use la función multi-source de
  ArgoCD (v2.6+) con una variable `$ref` para extraer su archivo de valores junto con el chart.
  Recomendado cuando se usa un chart publicado en OCI.
- Un archivo de valores en el mismo repositorio git que el chart: referéncielo en
  `valueFiles` con una ruta relativa al directorio del chart
  (por ejemplo, `../../overrides/customers/my-company.yaml`).

Los tres enfoques siguen la misma estratificación: preset de plataforma → preset de
perfil → su configuración. Los valores posteriores anulan a los anteriores.

### Actualización

Cuando el chart se publica en un registro OCI, actualizar es un único cambio en
`targetRevision` dentro de su especificación de Application. Los presets de plataforma y
de perfil están versionados junto con el chart, por lo que se actualizan automáticamente.

Para obtener información completa sobre la compatibilidad de ArgoCD con Helm, consulte la
[documentación de ArgoCD Helm](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/).

---

## Verificar

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

### Tests de Helm integrados

El chart incluye cuatro tests que se ejecutan como pods de Kubernetes al ejecutar
`helm test`. Validan los puntos de integración críticos entre DefectDojo
y sus servicios de respaldo:

| Test | Qué verifica |
|------|----------------|
| `test-database` | Se conecta a PostgreSQL usando las credenciales configuradas, ejecuta `SELECT version()`, y confirma que la base de datos acepta consultas. Reintenta durante hasta 60 segundos. |
| `test-redis-broker` | Se conecta al broker Redis/Valkey, envía un `PING`, y luego realiza un ciclo de set/get/delete para verificar el acceso de lectura y escritura. |
| `test-django-health` | Consulta el endpoint `/api/v2/health_check/light/` en el servicio nginx interno y confirma una respuesta HTTP 2xx/3xx. Se ejecuta después de los tests de base de datos y broker (hook-weight 10). |
| `test-storage` | Monta el volumen de medios y realiza un ciclo de escritura/lectura/eliminación para confirmar que el backend de almacenamiento es accesible y que la aplicación puede escribir en él. Se ejecuta al final (hook-weight 15). |

Los tests se ejecutan en orden según hook-weight: primero los tests de
infraestructura (base de datos, broker), luego los tests a nivel de aplicación
(salud, almacenamiento). Si un test anterior falla, los tests posteriores pueden
seguir ejecutándose, pero es probable que también fallen.

Para volver a ejecutar los tests después de una implementación fallida o un cambio de
configuración:
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

Los pods de test se limpian automáticamente antes de cada ejecución
(política de eliminación `before-hook-creation`). Para inspeccionar manualmente los
logs de un pod de test fallido:
```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### Recuperar la contraseña de administrador

La contraseña de administrador inicial se almacena en el secreto de la aplicación.
Recupérela con:

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Si usó secretos en línea en lugar de un secreto externo, la contraseña está en
el secreto gestionado por el chart:

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Inicie sesión en su URL configurada con el nombre de usuario administrador
(predeterminado: `admin`) y esta contraseña. Cambie la contraseña después del
primer inicio de sesión.

---

## Operaciones

### Nivel de detalle de los logs

El chart expone dos ajustes de nivel de log, ambos con valor predeterminado `INFO`:

| Ajuste | Controla | Variable de entorno |
|---------|----------|---------|
| `config.logLevel` | Logging de la aplicación Django | `DD_LOG_LEVEL` |
| `celery.logLevel` | Logging del worker y del beat de Celery | `DD_CELERY_LOG_LEVEL` |

Para aumentar el nivel de detalle con fines de resolución de problemas, establezca
uno o ambos en `DEBUG` en su archivo de valores y ejecute `helm upgrade`:

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

Las opciones `--set` anulan la configuración del archivo de valores, por lo que
puede activar y desactivar el logging de depuración sin editar archivos. Una vez
resuelto el problema, ejecute `helm upgrade` nuevamente sin las opciones `--set`
para volver a sus valores predeterminados configurados.

El deployment de Django también admite `django.uwsgi.enableDebug: true`, que
establece `DD_DEBUG=True` para depuración de bajo nivel del framework. Esto produce
una cantidad de salida significativamente mayor y solo debe usarse para
investigaciones breves.

### Aislamiento de importación de escaneos

Las importaciones de escaneos (`/api/v2/import-scan/` y `/api/v2/reimport-scan/`) se
analizan de forma síncrona y pueden consumir grandes cantidades de memoria del worker.
De forma predeterminada, el chart ejecuta un deployment dedicado `django-import`
(uwsgi en el puerto 3032 detrás de su propio Service) y el nginx del pod de Django
enruta los endpoints de importación hacia él.
Una importación pesada no puede agotar (ni causar un OOM en) los workers web
interactivos, y el pool de importadores (escritores) escala de forma independiente
de los pods web (lectores).

Parámetros ajustables bajo `django.uwsgiImport`:

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

Notas operativas:

- Los pods importadores montan el volumen de medios compartido, por lo que necesitan
  almacenamiento con capacidad ReadWriteMany para poder programarse libremente entre
  nodos. Los backends de almacenamiento del chart (`efs`, `filestore`, `gcsfuse`,
  `nfs`, y el PVC de medios RWX predeterminado) cumplen este requisito; un PVC
  ReadWriteOnce no lo cumple.
- El autoescalado de importadores está desactivado de forma predeterminada porque un
  escalado hacia abajo desaloja la importación que ese pod esté ejecutando en cuanto
  vence `terminationGracePeriodSeconds`.
  Si lo habilita, aumente el período de gracia para que las importaciones en curso
  puedan finalizar.
- Un PodDisruptionBudget (`podDisruptionBudget.djangoImport`) protege el pool de
  importadores durante interrupciones voluntarias siempre que se ejecute más de un
  importador.

El perfil `minimal` deshabilita el deployment de importadores para mantener la huella
reducida; en ese caso, las importaciones comparten el pool uwsgi único como antes.

### Motor de asesorías PSIRT (opcional)

El chart puede implementar el PSIRT Advisory Engine, un servicio para redactar y
publicar asesorías de seguridad a partir de los hallazgos de DefectDojo. Está
desactivado de forma predeterminada.
Cuando está habilitado, aparece bajo `/psirt/` en su host principal de DefectDojo;
el sidecar de nginx lo expone mediante proxy, por lo que no se necesita ingress
ni entrada DNS adicional.

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

`psirtSharedSecret` es un valor simple que usted elige; no interviene ningún usuario
de DefectDojo ni token generado. Establezca una cadena de alta entropía (por ejemplo,
`python -c "import secrets; print(secrets.token_urlsafe(48))"`). El chart la integra
tanto en el Secret del motor psirt como en los pods de DefectDojo, de modo que un
solo valor habilita la publicación autónoma en una instalación nueva sin ningún paso
posterior al arranque. Rotación: cámbielo y ejecute `helm upgrade`.

Configuración de la base de datos: apunte `databaseUrl` al mismo host de PostgreSQL
que usa DefectDojo (o a cualquier otro host accesible) con un nombre de base de
datos de su elección. El pod crea la base de datos en el primer inicio si no
existe, lo cual requiere una concesión única como superusuario de postgres:

```sql
ALTER ROLE pae CREATEDB;
```

Notas operativas:

- Mantenga `psirt.replicas` en 1. El servicio ejecuta su propio planificador de
  tareas interno, y una segunda réplica ejecutaría cada tarea programada dos veces.
- El pod monta el volumen de medios compartido (los adjuntos de asesorías se
  guardan bajo `<media>/pae/uploads`), por lo que aplican las mismas indicaciones
  de almacenamiento ReadWriteMany que para el pool de importadores.
- Se requiere HTTPS saliente para los feeds de asesorías y las consultas a NVD.
  Con `networkPolicy.profile=aggressive`, la lista de CIDR permitidos
  (`networkPolicy.externalAPIs.allowedCidrs`) debe cubrir esos endpoints.
- Un `psirt.nvdApiKey` opcional eleva el límite de tasa de NVD de 5 a 50
  solicitudes por 30 segundos.

### Motor de escaneo/corrección Sensei (opcional)

El chart puede implementar el motor Sensei, el servicio detrás de las tareas de
escaneo del lado del servidor y de corrección automática (fix). Está desactivado
de forma predeterminada y no necesita configuración adicional para arrancar:

```yaml
sensei:
  enabled: true
```

El motor no conserva secretos de larga duración. Las credenciales de escaneo/corrección
y las URL de endpoint viajan con cada tarea, despachadas desde la configuración cifrada
de workers de DefectDojo.
django y celery alcanzan al motor dentro del clúster (`SENSEI_ENGINE_URL` se integra
automáticamente en el configmap compartido), por lo que no se necesita ingress ni
entrada DNS.

Notas operativas:

- El motor llama de vuelta a DefectDojo en la URL pública de su sitio (`dojo.url`)
  de forma predeterminada. Establezca `sensei.ddCallbackUrl` para anularlo; para
  tráfico puramente dentro del clúster, apúntelo al listener interno de nginx, pero
  entonces el motor debe confiar en la CA interna de DefectDojo.
- Las credenciales de LLM para las tareas de corrección normalmente se configuran
  dentro de la aplicación (Configuración de modelo de IA) y se transportan por cada
  tarea. Establezca `sensei.llm.*` solo cuando el motor deba leer la clave desde su
  propio entorno; prefiera `sensei.llm.existingSecret` en lugar del texto plano
  `sensei.llm.apiKey`.
- Para ejecutar el motor contra Google Vertex AI en lugar de una clave de API de
  proveedor, establezca `sensei.llm.provider: vertex` y `sensei.llm.vertexProject`
  con el proyecto de GCP que aloja Vertex (`sensei.llm.vertexRegion` suele ser
  `global`). El pod se autentica con Application Default Credentials, así que
  asígnele una cuenta de servicio de GCP mediante `sensei.serviceAccountName` +
  Workload Identity, o monte un archivo de clave con `sensei.extraVolumesRaw` y
  `sensei.extraVolumeMounts`, y luego apunte `GOOGLE_APPLICATION_CREDENTIALS` a él
  mediante `sensei.extraEnv`.
- `sensei.llm.fallbackChain` toma una lista separada por comas de entradas
  `provider` o `provider:model` a las que recurre el motor cuando el proveedor
  principal devuelve un fallo reintentable. Terminar la cadena en un proveedor
  distinto (por ejemplo, `vertex-gemini:gemini-2.5-pro`) mantiene las tareas de
  corrección funcionando durante una interrupción del proveedor principal.
- La imagen del escáner es pesada. `sensei.maxConcurrentJobs` (predeterminado 3)
  limita las tareas paralelas por pod, y los recursos predeterminados
  (solicitud de 1Gi / límite de 4Gi) están dimensionados para ese límite; aumente
  ambos juntos.
- Un HPA basado en CPU (de 1 a 4 réplicas) está activado de forma predeterminada.
  Establezca `sensei.hpa.maxReplicas` igual a `sensei.hpa.minReplicas` para fijar
  el número en `sensei.replicas` en su lugar.
- Se requiere HTTPS saliente para clones de repositorios, API de alojamiento de git
  y API de proveedores de LLM. Con `networkPolicy.profile=aggressive`, la lista de
  CIDR permitidos (`networkPolicy.externalAPIs.allowedCidrs`) debe cubrir esos
  endpoints.

### Rotación de certificados TLS

El chart usa dos categorías de certificados TLS, cada una con un procedimiento de
rotación diferente.

#### TLS interno (servicio a servicio)

Son los secretos `dojopro-internal-tls` y `dojopro-internal-ca` usados para la
comunicación entre nginx, connectors y otros servicios internos.

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

#### TLS de ingress (externo/de cara al navegador)

La rotación depende de cómo haya configurado el TLS:

- **Gestionado por ACM (EKS):** la renovación es automática; no se requiere ninguna acción.
- **cert-manager:** la renovación es automática según los ajustes `duration` y
  `renewBefore` (predeterminados: 2160h / 720h).
- **Certificados gestionados de GKE:** la renovación es automática; no se requiere
  ninguna acción.
- **Certificado manual mediante secreto de Kubernetes:** actualice el secreto al que
  hace referencia el ingress usando el mismo patrón `kubectl create secret tls ...
  --dry-run=client` mostrado anteriormente.
- **Certificados internos autogenerados:** el chart puede regenerarlos con
  `helm upgrade` si `certificates.generation.enabled: true`.

> En Kubernetes, la fuente de verdad es el objeto Secret; actualizar el secreto
> y reiniciar el deployment es cómo funciona la rotación de certificados.

> Si usa External Secrets Operator o Sealed Secrets para gestionar los secretos TLS,
> la rotación se maneja en esa capa y los secretos de Kubernetes se actualizan
> automáticamente; no se necesitan pasos manuales con `kubectl`.

---

## Estratificación de archivos de valores

El chart apila archivos de valores. Los archivos posteriores prevalecen:

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

Los presets de plataforma y de perfil se incluyen dentro del chart
(`dojopro/presets/`). Están incluidos en el `.tgz` empaquetado y versionados junto
con el chart. Los clientes no necesitan modificarlos.

Al usar `helm install` desde el chart extraído, referéncielos usando la variable
`$CHART` establecida durante la [extracción](#extract-the-chart-package):
```
-f $CHART/presets/platforms/aws-eks.yaml
```

Al usar ArgoCD, referéncielos de forma relativa a la raíz del chart:
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

No coloque límites de recursos en los archivos del cliente ni configuración de
plataforma en los archivos de perfil. Mantenga cada capa enfocada en una sola cosa.

> **Versionado de presets: ArgoCD vs. CLI:** ArgoCD referencia los presets desde
> dentro del paquete del chart, por lo que se actualizan automáticamente cuando
> cambia `targetRevision`. Los usuarios de la CLI deben volver a extraer los
> presets al actualizar a una nueva versión del chart para incorporar cualquier
> cambio en los valores predeterminados de plataforma o perfil. Use una ruta de
> extracción versionada (por ejemplo, `dojopro-2.55.4/`) para evitar confusión
> entre versiones del chart; consulte [Extraer el paquete del chart](#extract-the-chart-package).

---

## Personalización y extensibilidad

Más allá de los archivos de valores de plataforma/perfil/cliente, el chart
proporciona puntos de extensión de primera clase para conectar su propia
infraestructura: sidecars, init containers, variables de entorno, volúmenes,
cuentas de servicio, restricciones de programación y manifiestos adicionales
arbitrarios, sin necesidad de bifurcar el chart:

- **Hooks por componente**: `extraEnv`, `extraEnvFrom`, `extraVolumesRaw`,
  `extraVolumeMounts`, `extraInitContainers`, `extraContainers`, `hostAliases`,
  `priorityClassName`, `topologySpreadConstraints`, `dnsConfig`, y
  `serviceAccountName` en cada workload (django, celery worker/beat,
  connectors, ddorch, ddorch-workers, integrators, mcp-server, psirt).
- **`extraManifests` de nivel superior**: renderiza YAML arbitrario proporcionado
  por el usuario (ConfigMaps, Secrets, NetworkPolicies, etc.) junto con el chart,
  pasado a través de `tpl` de Helm con el contexto raíz del chart.
- **Consumo como umbrella chart**: `dojopro` puede incrustarse como subchart
  mediante una dependencia `file://` u OCI, útil para distribuir paquetes de
  cliente que agregan recursos adicionales alrededor del chart.
- **Validación consciente del esquema**: `values.schema.json` cubre cada hook,
  de modo que los editores obtienen autocompletado y `helm lint`/`helm install`
  validan sus overrides.

Consulte la guía de extensibilidad BYO, incluida como **Apéndice: Traiga su propia
infraestructura (BYO)** en la edición en PDF, para conocer patrones, ejemplos y
garantías de estabilidad de actualización.

---

## Políticas de red

El chart incluye NetworkPolicies para cada componente, habilitadas de forma
predeterminada (`networkPolicy.enabled: true`). Una línea base de denegación por
defecto se limita a los pods de este release (mediante las etiquetas
`app.kubernetes.io/name` + `app.kubernetes.io/instance`), por lo que nunca
afecta a otros workloads que compartan el namespace.

El nivel de rigor de las reglas se controla mediante **`networkPolicy.profile`**:

| Perfil | Egress | Ingress entre pods | Ingress externo |
|---------|--------|--------------------|------------------|
| `standard` (predeterminado) | Todo el egress permitido (`0.0.0.0/0`) | Todo el tráfico entre los propios pods de este release está permitido | Restringido al controlador de ingress / balanceador de carga |
| `aggressive` | Lista de permitidos granular por componente (DNS, base de datos/broker, servicios específicos dentro del clúster, solo API externas explícitamente permitidas) | Lista de permitidos granular por componente | Restringido al controlador de ingress / balanceador de carga |

- **`standard`** se recomienda para la mayoría de los clústeres. Evita fallos
  causados por dependencias de egress específicas del clúster (el servidor de
  metadatos de GKE, NodeLocal DNSCache, endpoints de almacenamiento/API en la
  nube) y por llamadas de servicio internas de la aplicación, a la vez que
  mantiene el ingress externo restringido a la ruta de ingress: el release
  confía en sus propios pods, pero lo externo sigue entrando por la puerta
  principal.
- **`aggressive`** aplica una lista de permitidos estricta en ambas direcciones.
  Si la usa, es posible que deba ajustar las excepciones bajo `networkPolicy`
  para su clúster:
  - `nodeLocalDns`: permite el resolutor NodeLocal DNSCache (link-local
    `169.254.20.10` de forma predeterminada, en el puerto 53). Necesario en
    clústeres que ejecutan NodeLocal DNSCache (por ejemplo, el addon de GKE);
    de lo contrario, la resolución DNS falla.
  - `dnsSelectors`: anula el destino de egress de DNS para una configuración
    de DNS personalizada.
  - `allowExternalAPIs` / `externalAPIs`: controlan el egress hacia API HTTPS
    externas y qué CIDR se bloquean (por ejemplo, metadatos en la nube).

Establezca el perfil en cualquier archivo de valores, por ejemplo:

```yaml
networkPolicy:
  profile: aggressive
```

> **Las comprobaciones de salud de GKE** se manejan en ambos perfiles: los rangos
> de sondeo del balanceador de carga de GCE (`130.211.0.0/22`, `35.191.0.0/16`)
> siempre pueden acceder al backend de django en GKE. Consulte [GCP GKE](#gcp-gke).

### Acceso del controlador de ingress (502 Bad Gateway)

En clústeres que no son GKE ni OpenShift, la NetworkPolicy de django permite
la entrada del controlador de ingress seleccionando su namespace mediante la
etiqueta `kubernetes.io/metadata.name` que Kubernetes aplica automáticamente a
cada namespace. De forma predeterminada, esto espera que el controlador esté en
un namespace llamado **`ingress-nginx`**, con los pods del controlador con la
etiqueta `app.kubernetes.io/name: ingress-nginx` (el valor predeterminado del
chart ingress-nginx).

Si su controlador de ingress reside en un namespace con un nombre distinto, usa
etiquetas de pod diferentes, o es un controlador completamente distinto
(Traefik, un ALB, etc.), la política descartará silenciosamente su tráfico y
las solicitudes devolverán **502 Bad Gateway** (`connect() failed (110: Operation
timed out)` en los logs del controlador). Apunte la política a su origen real de
ingress con `networkPolicy.ingressSource`:

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

O ajuste `networkPolicy.ingressNamespace` / `networkPolicy.ingressControllerLabel`
si solo difieren los nombres. Consulte los comentarios bajo `networkPolicy` en
`values.yaml` para ver más ejemplos de `ingressSource` (Traefik, router de
OpenShift, ALB de AWS).

---

## Actualización

La ruta de actualización recomendada extrae el chart directamente desde el
registro OCI de DefectDojo, sin necesidad de extraer ningún zip:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Una actualización típica desde OCI se ve así (los mismos archivos de valores y
opciones `--set` que en la instalación original):

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

El flujo de trabajo de zip empaquetado usado en la instalación también funciona
para las actualizaciones: sustituya `helm install` por `helm upgrade` contra la
ruta extraída `$CHART`.

Consulte la [Guía de actualización](/get_started/pro/onprem/upgrading_on_kubernetes/) — incluida como **Apéndice: Actualización de
DefectDojo Pro** en la edición en PDF — para conocer la autenticación, las
actualizaciones con ArgoCD, la verificación, la reversión y la resolución de
problemas.

---

## Desinstalación

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> Los PVC, las bases de datos externas y los secretos externos no se eliminan.
> Límpielos por separado.

### Limpieza de PersistentVolumes

Los PersistentVolumes con una política de reclamación `Retain` tienen **alcance
de clúster** — no se eliminan con `helm uninstall` ni al eliminar el
namespace. Si reinstala DefectDojo en un namespace distinto, los metadatos de
propiedad del PV huérfano entrarán en conflicto con la nueva instalación y
bloquearán `helm install`.

Compruebe si quedan PV huérfanos después de desinstalar:

```bash
kubectl get pv | grep dojopro
```

Si queda alguno, elimínelo:

```bash
kubectl delete pv dojopro-media-pv
```

> **Nota:** Eliminar el PV quita la referencia del volumen en Kubernetes, pero
> los datos subyacentes persisten en el backend de almacenamiento (por
> ejemplo, un sistema de archivos EFS). Esto es seguro si piensa reinstalar,
> pero debe hacerse de forma intencionada.

---

## Pruebas locales con PostgreSQL y Redis embebidos

> **Esta configuración es solo para pruebas locales y evaluación. No use
> PostgreSQL ni Redis embebidos en producción.** Los despliegues de producción
> deben usar servicios gestionados (por ejemplo, RDS, ElastiCache) para
> garantizar fiabilidad, copias de seguridad y escalado. El soporte de
> DefectDojo no cubre incidencias con bases de datos embebidas en entornos de
> producción.

El chart puede desplegar su propio PostgreSQL y Redis para pruebas locales
rápidas usando el perfil `minimal`. Esto evita la necesidad de infraestructura
externa de base de datos y broker.

Agregue lo siguiente a su archivo de values:

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

> **Importante: `postgresql.database.password` es obligatorio** cuando
> `postgresql.enabled` es true y `database.existingSecret` no está definido.
> El chart no se podrá renderizar sin él. Esta contraseña debe coincidir con
> el valor `DD_DATABASE_PASSWORD` de los secretos de la aplicación.

> **Credenciales predeterminadas de PostgreSQL embebido:** los valores por
> defecto del chart para el PostgreSQL embebido son el usuario `dojodbusr` y
> la base de datos `dojodb` (definidos en el `values.yaml` del chart). Su
> `DD_DATABASE_URL` en los secretos de la aplicación debe usar estos valores,
> no los marcadores de posición de base de datos externa de
> `secrets-template.yaml`. Por ejemplo:
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

El perfil `minimal` (`dojopro/presets/profiles/minimal.yaml`) establece
solicitudes de recursos reducidas apropiadas para un clúster de prueba de un
solo nodo, pero no activa estos indicadores de base de datos/broker — debe
configurarlos usted mismo.

> **Nota sobre privilegios de contenedor:** los contenedores embebidos de
> PostgreSQL y Redis **no** se ejecutan como root — PostgreSQL se ejecuta con
> el UID 999 y Redis con el UID 1001. La única excepción es el **init
> container** de PostgreSQL (`init-chmod-data`), que se ejecuta como root
> (UID 0) para establecer la propiedad del directorio en el volumen de datos
> antes de que arranque el proceso principal. Este es un patrón habitual en
> StatefulSets con almacenamiento persistente. Si su clúster aplica un Pod
> Security Standard `restricted` o una SCC de OpenShift que prohíbe los init
> containers como root, desactívelo con
> `postgresql.initContainer.enabled: false` (consulte [Problemas conocidos](#known-issues-chart-version-2.57.1)).

Si usa PostgreSQL embebido en EKS, también necesitará el driver CSI de EBS
(consulte [Requisitos previos de AWS EKS](#aws-eks-prerequisites)) y es
posible que deba ajustar los valores predeterminados de almacenamiento
(consulte [Problemas conocidos](#known-issues-chart-version-2.57.1)).

Valide sus values antes de instalar — la ruta minimal requiere más overrides
y es más propensa a errores de renderizado:

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

Si esto finaliza sin errores, continúe con `helm install` usando las mismas
opciones.

> **Use `--timeout 30m` para instalaciones minimal o con base de datos
> nueva.** El PostgreSQL embebido tiene recursos reducidos, y el
> initializer debe ejecutar todas las migraciones de base de datos desde cero
> en una base de datos nueva. En pruebas, esto tardó unos 23 minutos, lo que
> supera el `--timeout 15m` usado en los ejemplos de instalación estándar. Un
> timeout hace que `helm install` informe `INSTALLATION FAILED` aunque el
> despliegue se complete correctamente en segundo plano. Usar
> `--timeout 30m` evita este fallo falso y el estado `failed` de release que
> resulta de él.

---

## Registro privado / entornos air-gapped

Si su clúster no puede descargar imágenes del registro predeterminado de
DefectDojo, replique las imágenes en su propio registro y configure el chart
para usarlo.

### Opción 1: Override global de registro

Establezca `global.imageRegistry` para redirigir todas las descargas de
imágenes. El chart elimina el registro original de `images.prefix` y
antepone el suyo:

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

Esto afecta a todas las imágenes (django, nginx, celery, connectors, redis,
etc.).

### Opción 2: Overrides por imagen

Para un control más preciso, establezca `images.registry` (afecta a las
imágenes principales de la aplicación) y sobrescriba imágenes individuales:

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

### Secretos de pull de imagen para registros privados

Si su registro requiere autenticación, cree un secreto de pull y hágale
referencia:

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

O deje que el chart cree uno a partir de credenciales explícitas:

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

El comportamiento predeterminado (`extractFromLicense: true`) extrae
credenciales de cuenta de servicio de GCP desde el archivo de licencia para
descargar imágenes del registro de DefectDojo. Desactive esto cuando use su
propio registro:

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## Sobrescribir anotaciones de plataforma

El chart inyecta automáticamente anotaciones específicas de plataforma en el
Ingress y el Service según `cloudProvider` (por ejemplo, anotaciones ALB para
EKS, anotaciones GCE para GKE). Si necesita control total sobre las
anotaciones — por ejemplo, usar un controlador de ingress nginx en EKS en
lugar de ALB — establezca `platformAnnotations.enabled: false` y proporcione
las suyas:

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

Cuando `platformAnnotations.enabled` es `true` (el valor predeterminado), el
chart combina las anotaciones de plataforma con sus anotaciones
personalizadas. Sus anotaciones tienen prioridad en caso de conflicto de
claves, pero no puede eliminar una anotación de plataforma sin este
interruptor.

### Límite de tamaño de subida del Ingress

De forma predeterminada, el chart establece
`nginx.ingress.kubernetes.io/proxy-body-size: "2400m"` en el Ingress para que
las subidas grandes de resultados de escaneo y los informes PDF pasen por
nginx-ingress sin un `413 Request Entity Too Large`. Puede sobrescribirlo así:

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

Esto se aplica siempre que nginx-ingress sea el controlador — incluido
nginx-ingress ejecutándose sobre EKS, GKE o AKS. Los controladores que no son
nginx ignoran la anotación y deben ajustarse mediante sus propios mecanismos
(límites de inspección del cuerpo en AWS WAF, request-body-limit de AppGW,
`tuningOptions` de HAProxy en OpenShift Route).

---

## Notas específicas por plataforma

### AWS EKS

- Necesita el AWS Load Balancer Controller para el ingress ALB
- Necesita el driver CSI de EFS si usa almacenamiento EFS
- El TLS termina en el ALB mediante certificados de ACM
- Establezca `certificates.ingress.source: "acm"` y proporcione `acmCertArn`
- `dojo.secureCookies: true` funciona sin problemas ya que el ALB gestiona HTTPS

#### Access Points de EFS

Si su sistema de archivos EFS está configurado con un **access point**
(recomendado para forzar la propiedad UID/GID en el mount), **debe**
establecer `storage.efs.accessPointId` en su archivo de values. Sin esto, el
PV monta la raíz de EFS con propiedad de root, y los contenedores de
DefectDojo (que se ejecutan como UID 1001) no pueden crear subdirectorios de
media — lo que provoca que el initializer falle con errores de
`Permission denied`.

Compruebe los access points de su EFS:

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

Si existe un access point, agréguelo a su archivo de values:

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **Importante:** el campo `volumeHandle` del PersistentVolume es
> **inmutable** tras su creación. Si inicialmente instala sin un access
> point y más adelante necesita agregar uno, debe eliminar el PV y el PVC
> existentes antes de ejecutar `helm upgrade`:
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> Esto es seguro — eliminar el PV solo quita la referencia de Kubernetes; los
> datos en el sistema de archivos EFS no se ven afectados.

#### Storage Classes en clústeres endurecidos o gobernados por GitOps

Hay dos supuestos sobre storage classes que causan problemas en clústeres con
nombres de StorageClass personalizados o donde los recursos de alcance de
clúster se gestionan fuera del chart de la aplicación.

**Los PVC de aprovisionamiento dinámico usan `gp3` por defecto en EKS.**
Cualquier PVC que el chart aprovisione dinámicamente — el volumen de Redis
embebido (`redis.enabled: true`) y el volumen de media
`storage.type: "pvc"` — resuelve su StorageClass al valor predeterminado de
la plataforma, que es `gp3` en EKS. Si su clúster no tiene una StorageClass
llamada `gp3` (algo común en clústeres endurecidos con nomenclatura
personalizada), el PVC queda en estado `Pending` con un evento
`storageclass.storage.k8s.io "gp3" not found` y los pods nunca arrancan.

Sobrescríbalo de una de estas dos maneras:

- **Globalmente (recomendado)** — una sola palanca para todos los PVC
  aprovisionados por el chart:

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- **Por componente**, si necesita clases distintas:

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  El orden de resolución es: valor por componente → `storage.defaultStorageClass`
  → valor predeterminado de la plataforma (`gp3`). Establezca un valor en
  `""` para volver a la StorageClass predeterminada del clúster. Esto **no**
  se aplica a la ruta de media EFS predeterminada (ver más abajo), que no usa
  ninguna StorageClass.

**El volumen de media EFS predeterminado no necesita StorageClass.** Cuando
`storage.type: "efs"`, el chart enlaza el PV de media de forma estática
mediante el `volumeHandle` del sistema de archivos EFS y un `claimRef` —
tanto el PV como el PVC usan un `storageClassName` vacío. La StorageClass
`efs-sc` **no** necesita existir para que el PVC de media se enlace.

El chart solo crea una StorageClass `efs-sc` de alcance de clúster si opta
explícitamente por el aprovisionamiento **dinámico** de EFS con
`storageClasses.efs.enabled: true` (valor predeterminado: `false`). En
clústeres donde los recursos de alcance de clúster se gobiernan fuera del
chart de la aplicación (GitOps), déjelo en el valor predeterminado `false` —
la ruta estática de EFS descrita arriba no requiere ninguna StorageClass ni
objetos de alcance de clúster de este chart. Si desea aprovisionamiento
dinámico de EFS bajo GitOps, cree la StorageClass fuera de banda y mantenga
`storageClasses.efs.enabled: false`.

### GCP GKE

- Usa el controlador de ingress GCE (`className: "gce"`) con TLS terminando
  en el balanceador de carga de Google Cloud
- El preset `gcp-gke.yaml` adjunta automáticamente un `FrontendConfig`
  (redirección HTTP→HTTPS + política SSL) y un `BackendConfig` al ingress
- El balanceador de carga GCE comprueba el estado del backend de django
  directamente desde los rangos de Google (`130.211.0.0/22`,
  `35.191.0.0/16`). Las NetworkPolicies del chart permiten esto
  automáticamente en GKE bajo ambos valores de `networkPolicy.profile`, de
  modo que el probe `/nginx_health` tiene éxito y el backend se reporta como
  saludable — consulte [Políticas de red](#network-policies)

#### TLS gestionado por Google frente a TLS propio

El preset `gcp-gke.yaml` usa por defecto **certificados gestionados por
Google**. Elija uno de estos dos enfoques:

- **Gestionado por Google (predeterminado):** GCP aprovisiona y renueva el
  certificado. Simplemente indique sus dominios — no se necesita ningún
  secreto TLS de Kubernetes:

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **Aportado por usted (BYO):** proporcione un secreto TLS de Kubernetes
  existente en el namespace de la release y apunte el ingress a él:

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  Esto genera `spec.tls[].secretName` en el ingress y omite la anotación
  `networking.gke.io/managed-certificates`.

> **Soporte del script de bootstrap:** `scripts/bootstrap/bootstrap-gcp-gke.sh`
> solo cubre los flujos de certificados nativos de GCP (`google-managed` y
> `pre-shared`). Para la ruta BYO con `secret`, instale directamente con
> `helm` (cree primero el secreto TLS, luego pase
> `certificates.ingress.source=secret` y
> `certificates.ingress.secretName=<your-secret>`).

> La renovación de los certificados gestionados por Google es automática —
> consulte [Rotación de certificados TLS](#rotating-tls-certificates).

### OpenShift / ROSA

- Usa Routes de forma predeterminada (`django.route.enabled: true`), pero
  también se admite Ingress
- Para usar Ingress en su lugar: establezca `django.ingress.enabled: true` y
  `django.route.enabled: false`
- Solo se puede habilitar uno a la vez (el chart valida la exclusividad mutua)
- **`dojo.secureCookies` debe ser `false`** cuando se usan Routes con
  terminación edge (el valor predeterminado). Esto es obligatorio, no
  opcional. Consulte la [advertencia en Preparar su archivo de values](#prepare-your-values-file).
- `securityContext.openshift.fsGroup` debe coincidir con el rango de grupos
  suplementarios de su namespace (consulte la
  [Lista de verificación previa a la instalación](#infrastructure-details)
  para saber cómo consultarlo)
- NFS a través de EFS funciona bien — use `storage.type: "nfs"` con el nombre
  DNS de EFS como servidor

#### Usar Ingress en lugar de Routes en OpenShift

OpenShift incluye un controlador de ingress basado en HAProxy por defecto. Si
prefiere Ingress en lugar de Routes (por ejemplo, para mantener coherencia
con otros clústeres o para usar un controlador de ingress personalizado),
configure sus values así:

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

Los helpers de plataforma del chart seguirán gestionando correctamente los
contextos de seguridad, el resolvedor DNS y los valores predeterminados de
almacenamiento para OpenShift, sea cual sea el método de exposición que
elija.

---

## Problemas conocidos (versión del chart 2.57.1)

Estos son errores confirmados en la versión actual del chart. Las soluciones
temporales se documentan aquí hasta que se publique una versión corregida.

### Instalación minimal solo con PostgreSQL o Redis locales

Los siguientes problemas solo se aplican si usa el PostgreSQL o Redis
integrados del chart (`postgresql.enabled: true` o `broker.external: false`).
No afectan a los despliegues de producción que usan bases de datos y brokers
externos.

**No use EBS para el volumen de media (BUG-14, BUG-15)**

Los volúmenes EBS solo admiten `ReadWriteOnce` — solo pueden conectarse a un
nodo a la vez. DefectDojo requiere que el volumen de media se comparta entre
varios pods (django, celery-worker, initializer, connectors), que pueden
programarse en nodos distintos. Cuando esto ocurre, los pods quedan atascados
en `ContainerCreating` con un error `Multi-Attach error` porque EBS no puede
montar el volumen en más de un nodo simultáneamente. Esto también afecta a
`helm test`, donde el pod de test-storage puede programarse en un nodo
distinto al de los pods de la aplicación.

**Use EFS (u otro backend de almacenamiento compatible con
`ReadWriteMany`) en lugar de EBS para el volumen de media.** EFS admite
acceso concurrente desde todos los nodos del clúster y es el backend de
almacenamiento recomendado para despliegues en EKS.

Si debe usar EBS para pruebas en un clúster de un solo nodo, sobrescriba los
valores predeterminados:

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

Tenga en cuenta que incluso con este override, EBS fallará en cuanto los
pods se programen en varios nodos (por ejemplo, durante el escalado, el
reemplazo de nodos o `helm test`). EFS evita esto por completo.

**El init container de PostgreSQL entra en conflicto con el contexto de
seguridad sin root (BUG-16)**

Desactívelo si se encuentra con `CreateContainerConfigError`:

```yaml
postgresql:
  initContainer:
    enabled: false
```

### Todos los despliegues

**El pod de connectors entra en crashloop mientras se ejecuta el
initializer (comportamiento esperado)**

Durante la primera instalación, el pod de connectors entrará en
`CrashLoopBackOff` mientras el job del initializer ejecuta las migraciones de
base de datos. Esto es esperado — el pod de connectors intenta llamar a la
API de Django (`/api/connectors/v1/config/`), que devuelve un 500 porque el
esquema de la base de datos aún no está completamente migrado. Una vez que el
job del initializer se completa correctamente (muestra `1/1 COMPLETIONS` en
`kubectl get jobs`), el pod de connectors se recuperará en su siguiente ciclo
de reinicio. No se requiere intervención manual.

**El fallo del initializer tras las migraciones deja un estado de base de
datos irrecuperable (BUG-18)**

Si el job del initializer falla **después** de ejecutar las migraciones de
base de datos pero **antes** de sembrar los datos iniciales (por ejemplo,
debido a errores de permisos de almacenamiento o límites de recursos), la
base de datos queda en un estado parcialmente inicializado — las tablas
existen pero la tabla `dojo_system_settings` está vacía. En reinicios
posteriores, el initializer falla de inmediato con:

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

Esto crea un bucle de fallos sin recuperación automática. **Solución
temporal:** restablezca el esquema de la base de datos y vuelva a ejecutar el
initializer:

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

> **Prevención:** asegúrese de que los permisos de almacenamiento
> (especialmente los access points de EFS — consulte
> [Access Points de EFS](#efs-access-points)) y los límites de recursos estén
> correctamente configurados **antes** de la primera instalación. Ejecute
> `helm template` para validar sus values, y verifique los permisos de
> montaje de EFS con un pod de prueba si es posible.

**Advertencia de token de Hatchet en los logs (informativo)**

Cuando `hatchet.enabled: false` (el valor predeterminado), los pods
registrarán la siguiente advertencia al arrancar:

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

Esto es **esperado e inofensivo**. A partir del chart 2.57, la ejecución de
flujos de trabajo en segundo plano se ha consolidado en `ddorch` +
`ddorch-workers`, que sustituyen a los workers heredados basados en Hatchet
(`kairos`, `rulesengine`, `hatchet-integrators`). El código cliente de
Hatchet aún se inicializa al arrancar, por lo que la advertencia sigue
apareciendo cuando Hatchet está desactivado, pero nada depende de ella. La
advertencia puede ignorarse con seguridad.

### HTTPS no configurado

**La anotación ssl-redirect del ALB requiere un listener HTTPS (BUG-17)**

El preset de EKS incluye una anotación `ssl-redirect` que asume que existe un
listener HTTPS en el ALB. Si no ha configurado un certificado ACM ni un
listener HTTPS, esta anotación provoca un bucle de redirección. Configure
HTTPS (recomendado) o consulte
[Desplegar sin HTTPS (no recomendado)](#deploying-without-https-not-recommended)
para conocer el conjunto completo de cambios necesarios.

---

## Solución de problemas

### Pods atascados en CrashLoopBackOff

Revise los logs:
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

Habitualmente se debe a: secretos faltantes o incorrectos (compruebe las 12
claves), base de datos inaccesible (compruebe `database.host` y los grupos
de seguridad), o falta el certificado TLS interno (compruebe que existe el
secreto `dojopro-internal-tls`).

### Mezclar secretos externos e inline

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

Elija un solo enfoque. Si usa `dojo.existingSecret`, elimine todos los
valores de secretos inline (`dojo.secretKey`, `dojo.admin.password`,
`monitoring.password`, etc.) de sus archivos de values.

### El esquema indica que admin.password es obligatorio

Establezca `dojo.existingSecret` — el esquema elimina el requisito de
contraseña cuando se configura un secreto externo.

### Errores de permisos de fsGroup en OpenShift

Si los pods fallan con errores de permisos en volúmenes NFS, compruebe que
`securityContext.openshift.fsGroup` está dentro del rango de grupos
suplementarios de su namespace. Consulte la búsqueda de fsGroup en
[Despliegue → OpenShift / ROSA](#openshift-rosa).

### El ALB no aparece (EKS)

Verifique que el AWS Load Balancer Controller esté en ejecución:
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

Compruebe los eventos del ingress:
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## Apéndice: plantilla de configuración del cliente

La plantilla completa (`template.yaml`) está disponible en el portal de
soporte de DefectDojo o solicitándola a support@defectdojo.com. Cópiela,
reemplace los marcadores `REPLACE_*` y elimine las secciones que no se
apliquen a su plataforma. La plantilla incluye ejemplos comentados para:

- Identificación de plataforma (`cloudProvider`)
- Configuración de secretos de pull de imagen
- Configuración de Ingress y Route (Ingress para EKS/GKE/OpenShift, Route
  para OpenShift)
- Opciones de almacenamiento EFS y NFS
- Configuración de certificados y TLS
- Contextos de seguridad (uwsgi, nginx, fsGroup de OpenShift)
- Políticas de red
- Opciones de entrega de licencia (archivo, secreto, inline)

---

## Historial de revisiones

| Date       | Version | Changes                                                              |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | Se agrega el PSIRT Advisory Engine opcional (`psirt.enabled`): se sirve bajo `/psirt/` a través del sidecar de nginx, base de datos dedicada mediante `psirt.databaseUrl`, guía de fijación de secretos, reglas de política de red, hooks BYO |
| 2026-04-17 | 2.57.1  | Se documentan `ddorch` + `ddorch-workers` (nuevo par de orquestador que sustituye a kairos/rulesengine/hatchet-integrators); se agregan las opciones `--set-file` `ddorch.tls.rootCa/cert/key` a los comandos de pre-flight y despliegue; nueva sección de certificados mTLS de ddorch con requisitos de SAN; mcp-server incluido en los pods esperados; se agregan PDB para ddorch (singleton) y ddorch-workers; nota de requisitos previos de ArgoCD sobre la entrega de certificados de ddorch; se actualiza la advertencia de Hatchet para reflejar la consolidación de workers |
| 2026-03-25 | 2.55.4  | Se agrega documentación y campo de plantilla para access points de EFS; se documenta la recuperación de fallos del initializer (BUG-18); se documenta el crashloop de connectors durante la inicialización como comportamiento esperado; se aclara que la advertencia de token de Hatchet es inofensiva; se corrige un anclaje obsoleto de problemas conocidos; ruta de extracción del chart versionada; se consolida la guía sin HTTPS; limpieza de PV en la desinstalación; nota de coherencia de namespace; aviso sobre versionado de presets ArgoCD frente a CLI |
| 2026-03-11 | 2.53.0  | Se corrigen las rutas de los comandos helm; se agregan la extracción del chart, los requisitos previos de EKS, la comprobación de BD previa al vuelo, el aviso de HTTPS, la rotación de TLS y la sección de problemas conocidos |
