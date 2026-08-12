---
title: Modo FIPS 140-3
date: 2026-07-27 00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro puede desplegarse con criptografía validada FIPS 140-3, para entornos sujetos al control **SC-13** de FedRAMP o requisitos similares.

El modo FIPS se distribuye como un **conjunto independiente de imágenes de contenedor**, identificado por un sufijo de etiqueta `-fips`. Las imágenes estándar no cambian: habilitar FIPS es una elección explícita, nunca un valor predeterminado silencioso.

Para obtener acceso a las imágenes FIPS, contáctenos en [hello@defectdojo.com](mailto:hello@defectdojo.com).

## Qué proporcionan las imágenes FIPS

Todas las operaciones criptográficas se realizan mediante el **OpenSSL FIPS Provider 3.1.2**, que posee el certificado NIST CMVP **[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)** bajo FIPS 140-3. Los servicios en Go utilizan el **Go Cryptographic Module v1.0.0**, certificado CMVP **[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**.

Dado que la aplicación se realiza **dentro del contenedor**, el modo FIPS no requiere que el host ejecute un kernel habilitado para FIPS. Eso es lo que lo hace viable en tiempos de ejecución de contenedores gestionados como **Amazon ECS con el tipo de lanzamiento Fargate**, donde el sistema operativo host no está bajo su control.

> **FIPS 140-3, no 140-2.** FIPS 140-3 sustituye a 140-2 y satisface un requisito redactado contra este último. Todos los certificados FIPS 140-2 pasan a la Lista Histórica de CMVP el **21 de septiembre de 2026** y dejan de admitir nuevos despliegues después de esa fecha, por lo que los sistemas nuevos deben validarse contra un módulo 140-3.

### Cobertura

| Componente | Cubierto | Módulo |
|---|:---:|---|
| Aplicación Django (`dojo`) | sí | OpenSSL FIPS Provider 3.1.2 |
| Importación asíncrona (`dojo-import-scan`) | sí | OpenSSL FIPS Provider 3.1.2 |
| Celery worker y beat | sí | OpenSSL FIPS Provider 3.1.2 |
| Inicializador (`init`) | sí | OpenSSL FIPS Provider 3.1.2 |
| Workers de orquestación (`ddorch-workers`) | sí | OpenSSL FIPS Provider 3.1.2 |
| nginx | sí | OpenSSL FIPS Provider 3.1.2 |
| Motor de avisos PSIRT | sí | OpenSSL FIPS Provider 3.1.2 |
| Connectors, Integrators, ddorch, servidor MCP | sí | Go Cryptographic Module v1.0.0 |
| **Sensei** | **parcial** | binarios del servicio: Go Cryptographic Module v1.0.0. Conjunto de escáneres incluido: **no cubierto** |
| **PostgreSQL / Redis (incrustados)** | **no** | use servicios externos compatibles con FIPS |

**Sensei es un caso parcial que vale la pena entender.** Sus propios binarios se compilan contra el módulo Go validado, por lo que el TLS y los tokens de la API de trabajos están cubiertos. La imagen también incluye un conjunto de escáneres de terceros poliglota — Node (que incluye su propio OpenSSL), Rust (rustls), Python, Ruby y binarios de Go de terceros que no compilamos — y varios de ellos obtienen bases de datos de avisos por TLS usando su propia criptografía. Ese conjunto de herramientas no se puede reunir bajo un único módulo validado, por lo que no está cubierto y no debe presentarse como tal ante un evaluador.

PostgreSQL/Redis incrustados no tienen ninguna variante FIPS. En Kubernetes, el chart se niega a renderizarse si habilita FIPS junto con Sensei o los almacenes de datos incrustados, de modo que la decisión sea explícita en lugar de una suposición (consulte [Barreras de protección](#guard-rails)).

## Habilitar el modo FIPS — Docker Compose

Dos cambios: use las imágenes `-fips` y establezca `DD_FIPS_MODE`.

**1. Apunte las etiquetas de imagen a las variantes FIPS.** En su `.env` o en la sobrescritura de compose:

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. Establezca `DD_FIPS_MODE` en los anclajes de entorno compartidos.** El archivo compose define bloques compartidos que fusiona cada servicio relevante, por lo que son tres ediciones en lugar de una por servicio:

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

Luego vuelva a crear el stack:

```bash
docker compose up -d --force-recreate
```

## Habilitar el modo FIPS — Kubernetes (Helm)

Establezca un valor. El chart selecciona las variantes de imagen `-fips` y establece `DD_FIPS_MODE` para cada pod:

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

Dado que los almacenes de datos incrustados no tienen variante FIPS y Sensei solo está parcialmente cubierto, una instalación FIPS debe usar PostgreSQL y Redis externos, y dejar Sensei deshabilitado a menos que acepte la salvedad anterior:

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

Si necesita Sensei en un entorno FIPS, habilítelo deliberadamente con
`fips.validate: false` y documente el conjunto de escáneres incluido como
no validado en su plan de seguridad del sistema.

### Barreras de protección

Si `fips.enabled` es true mientras también está habilitado un componente sin variante FIPS, **el chart se niega a renderizarse** y nombra a los responsables:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

Esto es deliberado. Un despliegue donde la mayoría de los servicios usan criptografía validada y uno o dos no lo hacen silenciosamente es peor que un fallo evidente: parece conforme, sobrevive a una inspección casual y solo sale a la luz durante una evaluación. Si ha aceptado ese riesgo por escrito, anúlelo con `fips.validate: false`.

## Habilitar el modo FIPS — Amazon ECS / Fargate

Fargate es un tipo de lanzamiento para ECS, no un servicio independiente: usted registra
definiciones de tareas de ECS con `requiresCompatibilities: ["FARGATE"]` y `networkMode: awsvpc`.

Si ya ejecuta DefectDojo Pro en ECS, solo cambian dos cosas:

**1. Las etiquetas de imagen** obtienen el sufijo `-fips`:

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2. `DD_FIPS_MODE=1`** en el bloque `environment` de cada contenedor que ejecuta
código de aplicación — uwsgi, celery worker, celery beat, el inicializador, los
workers de orquestación, nginx y psirt.

El resto de esta sección es un despliegue ECS completo con FIPS habilitado para
lectores que parten de cero.

### Qué aprovisionar primero

| Recurso | Notas |
|---|---|
| VPC con dos subredes | Subredes privadas más una puerta de enlace NAT, o subredes públicas con `assignPublicIp: ENABLED` |
| RDS para PostgreSQL | Use un endpoint compatible con FIPS y documéntelo como componente heredado |
| ElastiCache para Redis | Se usan dos bases de datos lógicas: `/0` para el broker de Celery, `/1` para la caché |
| Sistema de archivos EFS | Dos directorios: uno para `/app/media`, otro que contiene los certificados TLS de nginx |
| Entradas de Secrets Manager | URL de la base de datos, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY` y su licencia Pro |
| Application Load Balancer | Listener HTTPS, reenviando a un grupo de destino **HTTPS** en el puerto **8443** |
| Repositorios ECR | Que contienen las dos imágenes `-fips` |
| Roles IAM | Un rol de ejecución que pueda descargar de ECR, escribir logs y leer esos secretos, además de un rol de tarea |
| Grupo de logs de CloudWatch | Referenciado por la configuración `awslogs` de cada contenedor |

Coloque el certificado TLS y la clave en EFS como `dojo.crt` / `dojo.key`, más
`nginx_int.crt` / `nginx_int.key`. Ambos pares deben existir — consulte
[Tres cosas que ECS necesita](#three-things-ecs-needs-that-compose-provides-for-free)
a continuación para saber por qué.

### 1. La tarea inicializadora (ejecutar una vez por actualización)

Aplica migraciones y siembra los datos del primer arranque, luego finaliza. Es una
tarea, no un servicio.

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

Espere a que llegue a `STOPPED` con código de salida 0 antes de iniciar los servicios.

### 2. El servicio web (nginx + uwsgi)

Ambos contenedores viven en una sola tarea, de modo que nginx alcanza a uwsgi en `127.0.0.1`.

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

`USE_TLS=false` selecciona la configuración on-prem, que termina el TLS por sí misma en
8443 usando los certificados montados. Regístrela y cree un servicio conectado a
el balanceador de carga:

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. El servicio de workers (Celery worker y beat)

La misma imagen y los mismos secretos que uwsgi; el punto de entrada selecciona el proceso. Ejecute
exactamente **una** réplica de beat.

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

### 4. Confirmar que el despliegue ejecuta criptografía validada

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

Cada contenedor debe reportar el módulo antes de servir nada:

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

Si falta un contenedor en esa salida, es que nunca se inició, porque la verificación
falla de forma segura (fail closed) — revise su flujo de logs para conocer el motivo.

### Tres cosas que ECS necesita y que Compose proporciona gratis

Docker Compose le da un sistema de archivos del host desde el cual montar por enlace y DNS
para los nombres de los contenedores. Fargate no proporciona ninguna de las dos cosas, y cada
carencia impide que nginx se inicie en lugar de degradarse silenciosamente.

**1. Los certificados TLS deben existir antes de que nginx se inicie.** nginx valida cada
`ssl_certificate` al cargar la configuración, y la configuración on-prem no tiene
ninguna ruta sin certificado: el puerto 8080 solo emite un `301` hacia HTTPS, por lo que el
listener TLS 8443 es el funcional. Monte un volumen **EFS** en `/etc/nginx/certs`
que contenga `dojo.crt` / `dojo.key` y `nginx_int.crt` / `nginx_int.key`. Ambos
pares deben estar presentes aunque solo use un listener.

Alternativamente, establezca `USE_TLS=true`, lo que sirve el `nginx_TLS.conf` upstream y
permite que `GENERATE_TLS_CERTIFICATE=true` haga que el entrypoint genere su propio
certificado. Esa configuración enruta cada ruta hacia Django y no sirve
la interfaz Vue desde `/ui`, por lo que resulta adecuada para un despliegue solo de API o estrictamente detrás de un ALB.

**2. `DD_MCP_HOST` debe resolverse.** nginx resuelve los nombres de host de `proxy_pass` al
cargar la configuración. El valor predeterminado `mcp-server` se resuelve bajo Compose (nombre del contenedor) y
Helm (nombre del Service), pero `awsvpc` no da a los contenedores nombres DNS propios y
rechaza tanto `extraHosts` como `dnsSearchDomains`:

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

Apuntarlo hacia loopback cuando el servidor MCP no está desplegado hace que `/mcp` responda
`502` en lugar de impedir que arranque toda la capa web.

**3. Los archivos de configuración de nginx provienen de la imagen.** La imagen `-fips` de nginx
incorpora el conjunto de configuración on-prem, por lo que no se necesitan montajes. Compose superpone
sus propios montajes por enlace, así que el comportamiento de Compose no cambia.

### Otras particularidades de Fargate

- **El almacenamiento persistente debe ser EFS.** Fargate no puede adjuntar EBS, por lo que el
  directorio de medios (`/app/media`) necesita un volumen EFS si conserva los archivos de escaneo subidos.
- **No se requieren contenedores privilegiados ni redes de host.** Las imágenes se ejecutan
  como un usuario no root, y `awsvpc` da a cada tarea su propia interfaz de red.
- **nginx → uwsgi.** Los contenedores en la *misma* tarea comparten un espacio de nombres de red, por lo que
  ubicar nginx junto a uwsgi permite que nginx lo alcance en `127.0.0.1` — la opción más
  sencilla y correcta. Si los divide en servicios ECS separados, apunte
  `DD_UWSGI_HOST` a un nombre de descubrimiento de servicio de Cloud Map y abra el grupo de
  seguridad en el puerto de uwsgi.
- **No sobrescriba el entrypoint de uwsgi.** Establezca
  `DD_UWSGI_ENDPOINT=0.0.0.0:3031` y deje el ENTRYPOINT de la imagen intacto;
  uwsgi habla el protocolo uwsgi, que es lo que espera nginx. Reemplazar el
  entrypoint por `uwsgi --http` omite también la verificación de arranque de FIPS.
- **El inicializador es una tarea de un solo uso**, no un servicio. Ejecútelo con
  `aws ecs run-task` (o como un paso previo al despliegue) y deje que finalice; no le asigne
  un número deseado de instancias.
- **`healthCheck.retries` no puede superar 10.** Valores más altos se rechazan al
  registrar la definición de tarea.
- **Apunte el balanceador de carga al 8443** con un grupo de destino HTTPS. El listener 8080 de la
  configuración on-prem solo redirige a HTTPS, por lo que apuntar al 8080 genera un bucle.
  Un certificado autofirmado en el destino es aceptable para un ALB.
- **Terminación de TLS.** Si el ALB termina el TLS para los clientes, documente la postura FIPS
  propia del balanceador de carga por separado en su SSP.
- **Los secretos** pertenecen a Secrets Manager o SSM Parameter Store a través del
  bloque `secrets`, nunca en `environment`. Eso incluye `DD_LICENSE`.

### Recuperar evidencia en ECS

El bloque de evidencia de arranque llega al grupo de logs nombrado por la configuración
`awslogs` del contenedor:

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

Bajo demanda dentro de una tarea en ejecución (requiere `enableExecuteCommand` en el servicio):

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## Arranque con fallo seguro (fail-closed)

Con `DD_FIPS_MODE` establecido, cada contenedor verifica al arrancar que el proveedor validado esté cargado y que los algoritmos no aprobados se rechacen realmente. **Si esa verificación falla, el contenedor finaliza en lugar de iniciarse.**

El mismo razonamiento que la barrera del chart: un contenedor que retrocediera silenciosamente a criptografía no validada seguiría atendiendo tráfico mientras rompe su postura de cumplimiento, y usted no se enteraría hasta una evaluación.

## Verificar el modo FIPS

Cada contenedor imprime un bloque de evidencia al arrancar, que suele ser la forma más conveniente para un evaluador. En tiempos de ejecución gestionados llega a su agregador de logs:

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

Recupérelo con:

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

También puede verificar bajo demanda dentro de un contenedor en ejecución:

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

Para los servicios en Go, el modo FIPS se compila directamente y lo reporta el runtime de Go:

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## Diferencias de comportamiento en modo FIPS

Algunos algoritmos no aprobados no están disponibles, por lo que unos pocos comportamientos cambian. Estos son los que vale la pena planificar.

### Hashing de contraseñas

Las compilaciones FIPS usan **PBKDF2-SHA256** como hasher de contraseñas predeterminado. Argon2, bcrypt y scrypt no son funciones de derivación de claves aprobadas por FIPS y están deshabilitadas.

Los usuarios existentes no quedan bloqueados. Django vuelve a aplicar hash a cada contraseña con PBKDF2 en el siguiente inicio de sesión exitoso del usuario, y los hashes PBKDF2-SHA1 siguen siendo verificables durante la transición. Si prefiere un corte definitivo, fuerce un restablecimiento de contraseña en lugar de depender de una migración gradual.

### Conjuntos de cifrado TLS

ChaCha20-Poly1305 no está aprobado por FIPS y se elimina de toda configuración de nginx que termina TLS, y TLS 1.3 queda fijado a `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`. TLS 1.2 y TLS 1.3 siguen disponibles usando conjuntos AES-GCM. Los clientes que solo admiten ChaCha20 no podrán conectarse.

El módulo validado rechazaría ChaCha20 en cualquier caso; eliminarlo de la configuración significa que el servidor nunca anuncia un conjunto que no puede completar, lo que mantiene la configuración desplegada autodocumentada para un evaluador.

### Autenticación básica de métricas

Cuando la autenticación de métricas de nginx está habilitada, el hash de contraseña usa SHA-256 crypt en lugar del formato MD5 de Apache (`apr1`), que el módulo validado rechaza. Esto es transparente a menos que genere usted mismo las entradas de `.htpasswd`, en cuyo caso use `openssl passwd -5`.

### Parsers de escaneo

Algunos parsers usan MD5 para construir claves de deduplicación. Ese es un uso no relacionado con la seguridad y está explícitamente anotado como tal, por lo que esos parsers siguen funcionando con normalidad bajo FIPS. No se pierde ninguna funcionalidad de parser.

## Notas de despliegue

- **Terminación de TLS.** Si el TLS termina en un balanceador de carga situado delante de DefectDojo, ese dispositivo es responsable de su propia postura FIPS y debe documentarse por separado en su plan de seguridad del sistema. La imagen `-fips` de nginx cubre el TLS terminado por el propio DefectDojo.
- **Base de datos y caché.** PostgreSQL y Redis son productos independientes. En un entorno FIPS, use instancias compatibles con FIPS — por ejemplo, una base de datos gestionada que ofrezca un endpoint FIPS — y documéntelas como componentes heredados.
- **Alcance del cumplimiento.** DefectDojo en sí mismo no es un módulo criptográfico y no posee ningún certificado propio. Lo que estas imágenes proporcionan es criptografía validada realizada por módulos que sí lo tienen, ejecutándose en modo aprobado por FIPS. Su evaluador querrá los nombres de los módulos y los números de certificado, que aparecen en la salida de evidencia anterior.
