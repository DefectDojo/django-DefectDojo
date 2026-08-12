---
title: FIPS-140-3-Modus
date: 2026-07-27 00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro kann mit FIPS-140-3-validierter Kryptografie bereitgestellt werden – für Umgebungen, die der FedRAMP-Kontrolle **SC-13** oder ähnlichen Anforderungen unterliegen.

Der FIPS-Modus wird als **separater Satz von Container-Images** ausgeliefert, erkennbar am Tag-Suffix `-fips`. Die Standard-Images bleiben unverändert: Die Aktivierung von FIPS ist eine bewusste Entscheidung, niemals ein stillschweigender Standard.

Für Zugang zu den FIPS-Images kontaktieren Sie uns unter [hello@defectdojo.com](mailto:hello@defectdojo.com).

## Was die FIPS-Images bieten

Alle kryptografischen Operationen werden vom **OpenSSL FIPS Provider 3.1.2** ausgeführt, der das NIST-CMVP-Zertifikat **[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)** nach FIPS 140-3 besitzt. Go-Dienste verwenden das **Go Cryptographic Module v1.0.0**, CMVP-Zertifikat **[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**.

Da die Durchsetzung **innerhalb des Containers** erfolgt, erfordert der FIPS-Modus keinen Host mit FIPS-fähigem Kernel. Das macht ihn auf verwalteten Container-Laufzeitumgebungen wie **Amazon ECS mit dem Fargate-Starttyp** praktikabel, bei denen das Host-Betriebssystem nicht unter Ihrer Kontrolle steht.

> **FIPS 140-3, nicht 140-2.** FIPS 140-3 löst 140-2 ab und erfüllt eine Anforderung, die gegen 140-2 formuliert wurde. Alle FIPS-140-2-Zertifikate wechseln am **21. September 2026** auf die CMVP Historical List und unterstützen ab diesem Datum keine neuen Bereitstellungen mehr. Neue Systeme sollten daher gegen ein 140-3-Modul validiert werden.

### Abdeckung

| Komponente | Abgedeckt | Modul |
|---|:---:|---|
| Django-Anwendung (`dojo`) | ja | OpenSSL FIPS Provider 3.1.2 |
| Asynchroner Import (`dojo-import-scan`) | ja | OpenSSL FIPS Provider 3.1.2 |
| Celery Worker und Beat | ja | OpenSSL FIPS Provider 3.1.2 |
| Initialisierer (`init`) | ja | OpenSSL FIPS Provider 3.1.2 |
| Orchestrierungs-Worker (`ddorch-workers`) | ja | OpenSSL FIPS Provider 3.1.2 |
| nginx | ja | OpenSSL FIPS Provider 3.1.2 |
| PSIRT-Advisory-Engine | ja | OpenSSL FIPS Provider 3.1.2 |
| Connectors, Integrators, ddorch, MCP-Server | ja | Go Cryptographic Module v1.0.0 |
| **Sensei** | **teilweise** | Dienst-Binärdateien: Go Cryptographic Module v1.0.0. Gebündelte Scanner-Toolchain: **nicht abgedeckt** |
| **PostgreSQL / Redis (eingebettet)** | **nein** | externe FIPS-konforme Dienste verwenden |

**Sensei ist ein Sonderfall, den man verstehen sollte.** Die eigenen Binärdateien sind gegen das validierte Go-Modul gebaut, sodass TLS und Tokens der Job-API abgedeckt sind. Das Image bündelt außerdem eine polyglotte Scanner-Toolchain von Drittanbietern – Node (das sein eigenes OpenSSL mitbringt), Rust (rustls), Python, Ruby sowie Go-Binärdateien von Drittanbietern, die wir nicht selbst kompilieren – und mehrere davon rufen Advisory-Datenbanken über TLS mit ihrer eigenen Kryptografie ab. Diese Toolchain lässt sich nicht unter einem einzigen validierten Modul zusammenfassen, ist daher nicht abgedeckt und sollte einem Prüfer gegenüber nicht als solche dargestellt werden.

Die eingebetteten PostgreSQL-/Redis-Instanzen haben überhaupt keine FIPS-Variante. Unter Kubernetes verweigert das Chart das Rendern, wenn Sie FIPS zusammen mit Sensei oder den eingebetteten Datenspeichern aktivieren, sodass dieser Kompromiss eine bewusste Entscheidung ist und keine Annahme (siehe [Schutzmechanismen](#guard-rails)).

## FIPS-Modus aktivieren — Docker Compose

Zwei Änderungen: Verwenden Sie die `-fips`-Images und setzen Sie `DD_FIPS_MODE`.

**1. Richten Sie die Image-Tags auf die FIPS-Varianten aus.** In Ihrer `.env` oder Ihrem Compose-Override:

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. Setzen Sie `DD_FIPS_MODE` in den gemeinsamen Umgebungs-Ankern.** Die Compose-Datei definiert gemeinsame Blöcke, die jeder relevante Dienst einbindet, daher sind dies drei Änderungen statt einer pro Dienst:

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

Erstellen Sie den Stack anschließend neu:

```bash
docker compose up -d --force-recreate
```

## FIPS-Modus aktivieren — Kubernetes (Helm)

Setzen Sie einen einzigen Wert. Das Chart wählt die `-fips`-Image-Varianten aus und setzt `DD_FIPS_MODE` für jeden Pod:

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

Da die eingebetteten Datenspeicher keine FIPS-Variante haben und Sensei nur teilweise abgedeckt ist, sollte eine FIPS-Installation externes PostgreSQL und Redis verwenden und Sensei deaktiviert lassen, sofern Sie den oben genannten Vorbehalt nicht akzeptieren:

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

Wenn Sie Sensei in einer FIPS-Umgebung benötigen, aktivieren Sie es bewusst mit
`fips.validate: false` und dokumentieren Sie die gebündelte Scanner-Toolchain
in Ihrem System Security Plan als nicht validiert.

### Schutzmechanismen

Wenn `fips.enabled` auf true steht, während gleichzeitig eine Komponente ohne FIPS-Variante aktiviert ist, **verweigert das Chart das Rendern** und benennt die Verursacher:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

Das ist beabsichtigt. Eine Bereitstellung, bei der die meisten Dienste validierte Kryptografie verwenden und ein oder zwei still davon abweichen, ist schlimmer als ein offensichtlicher Fehler: Sie wirkt konform, übersteht eine oberflächliche Prüfung und fällt erst bei einem Assessment auf. Wenn Sie dieses Risiko schriftlich akzeptiert haben, überschreiben Sie es mit `fips.validate: false`.

## FIPS-Modus aktivieren — Amazon ECS / Fargate

Fargate ist ein Starttyp für ECS, kein eigenständiger Dienst: Sie registrieren ECS-Task-Definitionen mit `requiresCompatibilities: ["FARGATE"]` und `networkMode: awsvpc`.

Wenn Sie DefectDojo Pro bereits auf ECS betreiben, ändern sich nur zwei Dinge:

**1. Image-Tags** erhalten das Suffix `-fips`:

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2. `DD_FIPS_MODE=1`** im `environment`-Block jedes Containers, der Anwendungscode
ausführt — uwsgi, Celery Worker, Celery Beat, der Initialisierer, die
Orchestrierungs-Worker, nginx und psirt.

Der Rest dieses Abschnitts ist eine vollständige FIPS-fähige ECS-Bereitstellung für Leser,
die bei null anfangen.

### Was Sie zuerst bereitstellen sollten

| Ressource | Hinweise |
|---|---|
| VPC mit zwei Subnetzen | Private Subnetze plus ein NAT-Gateway, oder öffentliche Subnetze mit `assignPublicIp: ENABLED` |
| RDS für PostgreSQL | Verwenden Sie einen FIPS-fähigen Endpunkt und dokumentieren Sie ihn als geerbte Komponente |
| ElastiCache für Redis | Es werden zwei logische Datenbanken verwendet: `/0` für den Celery-Broker, `/1` für den Cache |
| EFS-Dateisystem | Zwei Verzeichnisse: eines für `/app/media`, eines mit den nginx-TLS-Zertifikaten |
| Secrets-Manager-Einträge | Datenbank-URL, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY` und Ihre Pro-Lizenz |
| Application Load Balancer | HTTPS-Listener, der an eine **HTTPS**-Zielgruppe auf Port **8443** weiterleitet |
| ECR-Repositories | Enthalten die beiden `-fips`-Images |
| IAM-Rollen | Eine Ausführungsrolle, die aus ECR pullen, Logs schreiben und diese Secrets lesen kann, sowie eine Task-Rolle |
| CloudWatch-Log-Gruppe | Wird von der `awslogs`-Konfiguration jedes Containers referenziert |

Legen Sie Zertifikat und Schlüssel für TLS auf EFS als `dojo.crt` / `dojo.key` ab,
sowie `nginx_int.crt` / `nginx_int.key`. Beide Paare müssen vorhanden sein — warum, erfahren Sie unten unter
[Drei Dinge, die ECS braucht](#three-things-ecs-needs-that-compose-provides-for-free).

### 1. Der Initialisierer-Task (einmal pro Upgrade ausführen)

Wendet Migrationen an und befüllt Erststart-Daten, dann beendet er sich. Es handelt sich um einen Task, keinen
Dienst.

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

Warten Sie, bis er mit Exit-Code 0 den Status `STOPPED` erreicht, bevor Sie die Dienste starten.

### 2. Der Web-Dienst (nginx + uwsgi)

Beide Container befinden sich in einem Task, sodass nginx uwsgi über `127.0.0.1` erreicht.

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

`USE_TLS=false` wählt die On-Premise-Konfiguration, die TLS selbst auf
Port 8443 mit den gemounteten Zertifikaten terminiert. Registrieren Sie sie und erstellen Sie einen Dienst, der mit
dem Load Balancer verbunden ist:

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. Der Worker-Dienst (Celery Worker und Beat)

Gleiches Image und gleiche Secrets wie bei uwsgi; der Entry Point wählt den Prozess aus. Führen Sie
genau **eine** Beat-Replik aus.

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

### 4. Bestätigen, dass die Bereitstellung validierte Kryptografie verwendet

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

Jeder Container sollte das Modul melden, bevor er irgendetwas bedient:

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

Fehlt ein Container in dieser Ausgabe, ist er nie gestartet, weil die Prüfung
fail-closed arbeitet — sehen Sie in seinem Log-Stream nach dem Grund.

### Drei Dinge, die ECS braucht und die Compose kostenlos mitliefert

Docker Compose stellt Ihnen ein Host-Dateisystem zum Bind-Mounten sowie DNS für
Container-Namen bereit. Fargate bietet keines von beidem, und jede Lücke verhindert den Start von nginx,
statt still zu degradieren.

**1. TLS-Zertifikate müssen existieren, bevor nginx startet.** nginx validiert beim Laden der Konfiguration jedes
`ssl_certificate`, und die On-Premise-Konfiguration hat keinen
zertifikatsfreien Pfad: Port 8080 gibt nur eine `301`-Weiterleitung auf HTTPS aus, sodass der TLS-Listener
auf 8443 der funktionale ist. Mounten Sie ein **EFS**-Volume unter `/etc/nginx/certs`,
das `dojo.crt` / `dojo.key` sowie `nginx_int.crt` / `nginx_int.key` enthält. Beide
Paare müssen vorhanden sein, auch wenn Sie nur einen Listener verwenden.

Alternativ können Sie `USE_TLS=true` setzen, wodurch die Upstream-`nginx_TLS.conf` ausgeliefert wird und
`GENERATE_TLS_CERTIFICATE=true` den Entrypoint ein eigenes
Zertifikat erzeugen lässt. Diese Konfiguration leitet jeden Pfad an Django weiter und liefert
die Vue-UI nicht von `/ui` aus, sodass sie sich für eine reine API- oder eine strikt hinter dem ALB liegende Bereitstellung eignet.

**2. `DD_MCP_HOST` muss auflösbar sein.** nginx löst `proxy_pass`-Hostnamen beim Laden der
Konfiguration auf. Der Standardwert `mcp-server` lässt sich unter Compose (Containername) und
Helm (Service-Name) auflösen, aber `awsvpc` gibt Containern keine eigenen DNS-Namen und
lehnt sowohl `extraHosts` als auch `dnsSearchDomains` ab:

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

Wenn Sie ihn auf Loopback setzen, während der MCP-Server nicht bereitgestellt ist, antwortet `/mcp` mit
`502`, statt den Start der gesamten Web-Ebene zu verhindern.

**3. Die nginx-Konfigurationsdateien stammen aus dem Image.** Das `-fips`-nginx-Image
enthält das On-Premise-Konfigurationsset fest eingebacken, sodass keine Mounts nötig sind. Compose überlagert
das mit seinen eigenen Bind-Mounts, sodass sich das Compose-Verhalten nicht ändert.

### Weitere Fargate-Besonderheiten

- **Persistenter Speicher muss EFS sein.** Fargate kann kein EBS anhängen, daher benötigt das Media-
  Verzeichnis (`/app/media`) ein EFS-Volume, wenn Sie hochgeladene Scan-Dateien aufbewahren.
- **Weder privilegierte Container noch Host-Networking sind erforderlich.** Die Images laufen
  als Non-Root-Benutzer, und `awsvpc` gibt jedem Task eine eigene Netzwerkschnittstelle.
- **nginx → uwsgi.** Container im *selben* Task teilen sich einen Netzwerk-Namespace, sodass
  nginx bei gemeinsamer Platzierung mit uwsgi diesen über `127.0.0.1` erreicht — die einfachste
  korrekte Option. Wenn Sie sie in getrennte ECS-Dienste aufteilen, richten Sie
  `DD_UWSGI_HOST` auf einen Cloud-Map-Service-Discovery-Namen und öffnen Sie die Security
  Group für den uwsgi-Port.
- **Überschreiben Sie nicht den uwsgi-Entrypoint.** Setzen Sie
  `DD_UWSGI_ENDPOINT=0.0.0.0:3031` und belassen Sie den ENTRYPOINT des Images;
  uwsgi spricht das uwsgi-Protokoll, das nginx erwartet. Wird der
  Entrypoint durch `uwsgi --http` ersetzt, wird die FIPS-Startprüfung mit übersprungen.
- **Der Initialisierer ist ein einmaliger Task**, kein Dienst. Führen Sie ihn mit
  `aws ecs run-task` aus (oder als Pre-Deploy-Schritt) und lassen Sie ihn beenden; geben Sie ihm keine
  gewünschte Anzahl (Desired Count).
- **`healthCheck.retries` darf 10 nicht überschreiten.** Höhere Werte werden bei der Registrierung
  der Task-Definition abgelehnt.
- **Richten Sie den Load Balancer auf Port 8443** mit einer HTTPS-Zielgruppe. Der 8080-Listener
  der On-Premise-Konfiguration leitet nur an HTTPS weiter, sodass ein Ziel auf 8080 eine Schleife erzeugt.
  Ein selbstsigniertes Zertifikat auf dem Ziel ist für einen ALB akzeptabel.
- **TLS-Terminierung.** Wenn der ALB TLS für Clients terminiert, dokumentieren Sie den eigenen FIPS-Status
  des Load Balancers separat in Ihrem SSP.
- **Secrets** gehören über den `secrets`-Block in den Secrets Manager oder SSM Parameter Store,
  niemals in `environment`. Das schließt `DD_LICENSE` mit ein.

### Nachweise auf ECS abrufen

Der Nachweisblock beim Start landet in der Log-Gruppe, die in der `awslogs`-Konfiguration
des Containers benannt ist:

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

Bei Bedarf innerhalb eines laufenden Tasks (erfordert `enableExecuteCommand` beim Dienst):

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## Fail-Closed-Start

Ist `DD_FIPS_MODE` gesetzt, prüft jeder Container beim Start, dass der validierte Provider geladen ist und dass nicht zugelassene Algorithmen tatsächlich verweigert werden. **Schlägt diese Prüfung fehl, beendet sich der Container, statt zu starten.**

Dieselbe Überlegung wie beim Chart-Schutzmechanismus: Ein Container, der still auf nicht validierte Kryptografie zurückfällt, würde weiterhin Traffic bedienen und dabei Ihre Compliance untergraben, ohne dass Sie es vor einem Assessment bemerken würden.

## FIPS-Modus überprüfen

Jeder Container gibt beim Start einen Nachweisblock aus, was für einen Prüfer meist die praktischste Form ist. Bei verwalteten Laufzeitumgebungen landet er in Ihrem Log-Aggregator:

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

Rufen Sie ihn ab mit:

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

Sie können auch bei Bedarf innerhalb eines laufenden Containers prüfen:

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

Bei Go-Diensten ist der FIPS-Modus einkompiliert und wird von der Go-Runtime gemeldet:

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## Verhaltensunterschiede im FIPS-Modus

Einige nicht zugelassene Algorithmen stehen nicht zur Verfügung, sodass sich ein paar Verhaltensweisen ändern. Diese sollten Sie einplanen.

### Passwort-Hashing

FIPS-Builds verwenden **PBKDF2-SHA256** als Standard-Passwort-Hasher. Argon2, bcrypt und scrypt sind keine FIPS-zugelassenen Schlüsselableitungsfunktionen und sind deaktiviert.

Bestehende Benutzer werden nicht ausgesperrt. Django hasht jedes Passwort bei der nächsten erfolgreichen Anmeldung des Benutzers auf PBKDF2 um, und PBKDF2-SHA1-Hashes bleiben während der Übergangszeit verifizierbar. Falls Sie einen harten Umstieg bevorzugen, erzwingen Sie einen Passwort-Reset, statt sich auf die schrittweise Migration zu verlassen.

### TLS-Cipher-Suiten

ChaCha20-Poly1305 ist nicht FIPS-zugelassen und wird aus jeder nginx-Konfiguration entfernt, die TLS terminiert, und TLS 1.3 wird auf `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256` festgelegt. TLS 1.2 und TLS 1.3 bleiben über AES-GCM-Suiten verfügbar. Clients, die nur ChaCha20 unterstützen, können keine Verbindung herstellen.

Das validierte Modul würde ChaCha20 ohnehin verweigern; das Entfernen aus der Konfiguration sorgt dafür, dass der Server nie eine Suite anbietet, die er nicht abschließen kann, was die bereitgestellte Konfiguration für einen Prüfer selbstdokumentierend hält.

### Basisauthentifizierung für Metriken

Wenn die Metriken-Authentifizierung von nginx aktiviert ist, verwendet der Passwort-Hash SHA-256-Crypt statt Apaches MD5-Format (`apr1`), das das validierte Modul verweigert. Das ist transparent, außer Sie erzeugen `.htpasswd`-Einträge selbst — verwenden Sie in diesem Fall `openssl passwd -5`.

### Scan-Parser

Einige Parser verwenden MD5, um Deduplizierungsschlüssel zu bilden. Das ist eine sicherheitsunkritische Verwendung und wird auch explizit so gekennzeichnet, sodass diese Parser unter FIPS normal weiterarbeiten. Es geht keine Parser-Funktionalität verloren.

## Hinweise zur Bereitstellung

- **TLS-Terminierung.** Wenn TLS an einem Load Balancer vor DefectDojo terminiert wird, ist dieses Gerät für seinen eigenen FIPS-Status verantwortlich, der separat in Ihrem System Security Plan dokumentiert werden sollte. Das `-fips`-nginx-Image deckt TLS ab, das von DefectDojo selbst terminiert wird.
- **Datenbank und Cache.** PostgreSQL und Redis sind eigenständige Produkte. Verwenden Sie in einer FIPS-Umgebung FIPS-konforme Instanzen — zum Beispiel eine verwaltete Datenbank mit FIPS-Endpunkt — und dokumentieren Sie sie als geerbte Komponenten.
- **Compliance-Umfang.** DefectDojo selbst ist kein kryptografisches Modul und besitzt kein eigenes Zertifikat. Diese Images bieten validierte Kryptografie, die von Modulen ausgeführt wird, die ein solches Zertifikat besitzen und im FIPS-zugelassenen Modus laufen. Ihr Prüfer wird die Modulnamen und Zertifikatsnummern sehen wollen, die in der obigen Nachweisausgabe erscheinen.
