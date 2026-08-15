---
title: Mode FIPS 140-3
date: 2026-07-27 00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro peut être déployé avec une cryptographie validée FIPS 140-3, pour les environnements soumis au contrôle FedRAMP **SC-13** ou à des exigences similaires.

Le mode FIPS est livré sous la forme d'un **ensemble distinct d'images de conteneur**, identifiées par un suffixe de tag `-fips`. Les images standard restent inchangées : l'activation de FIPS est un choix explicite, jamais un comportement par défaut silencieux.

Pour accéder aux images FIPS, contactez-nous à l'adresse [hello@defectdojo.com](mailto:hello@defectdojo.com).

## Ce que fournissent les images FIPS

Toutes les opérations cryptographiques sont effectuées par le **fournisseur OpenSSL FIPS Provider 3.1.2**, qui détient le certificat NIST CMVP **[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)** au titre de FIPS 140-3. Les services Go utilisent le **Go Cryptographic Module v1.0.0**, certificat CMVP **[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**.

Comme l'application des règles se fait **à l'intérieur du conteneur**, le mode FIPS n'exige pas que l'hôte exécute un noyau compatible FIPS. C'est ce qui le rend utilisable sur des runtimes de conteneurs gérés tels qu'**Amazon ECS avec le type de lancement Fargate**, où le système d'exploitation hôte n'est pas sous votre contrôle.

> **FIPS 140-3, pas 140-2.** FIPS 140-3 remplace 140-2 et satisfait une exigence rédigée par rapport à celui-ci. Tous les certificats FIPS 140-2 passeront sur la liste historique du CMVP le **21 septembre 2026** et ne prendront plus en charge les nouveaux déploiements après cette date ; les nouveaux systèmes doivent donc être validés par rapport à un module 140-3.

### Couverture

| Composant | Couvert | Module |
|---|:---:|---|
| Application Django (`dojo`) | oui | OpenSSL FIPS Provider 3.1.2 |
| Import asynchrone (`dojo-import-scan`) | oui | OpenSSL FIPS Provider 3.1.2 |
| Worker et beat Celery | oui | OpenSSL FIPS Provider 3.1.2 |
| Initialiseur (`init`) | oui | OpenSSL FIPS Provider 3.1.2 |
| Workers d'orchestration (`ddorch-workers`) | oui | OpenSSL FIPS Provider 3.1.2 |
| nginx | oui | OpenSSL FIPS Provider 3.1.2 |
| Moteur d'avis PSIRT | oui | OpenSSL FIPS Provider 3.1.2 |
| Connecteurs, intégrateurs, ddorch, serveur MCP | oui | Go Cryptographic Module v1.0.0 |
| **Sensei** | **partiel** | binaires du service : Go Cryptographic Module v1.0.0. Chaîne d'outils de scanners intégrée : **non couverte** |
| **PostgreSQL / Redis (intégrés)** | **non** | utilisez des services externes conformes FIPS |

**Sensei est un cas partiel qu'il vaut la peine de comprendre.** Ses propres binaires sont compilés à partir du module Go validé, de sorte que le TLS et les jetons de l'API de jobs sont couverts. L'image regroupe également une chaîne d'outils de scanners tiers polyglotte — Node (qui embarque son propre OpenSSL), Rust (rustls), Python, Ruby, et des binaires Go tiers que nous ne compilons pas — et plusieurs d'entre eux récupèrent des bases de données d'avis via TLS en utilisant leur propre cryptographie. Cette chaîne d'outils ne peut pas être ramenée sous un module validé unique ; elle n'est donc pas couverte et ne doit pas être présentée comme telle à un évaluateur.

Les instances PostgreSQL/Redis intégrées n'ont aucune variante FIPS. Dans Kubernetes, le chart refuse de se générer si vous activez FIPS en même temps que Sensei ou les magasins de données intégrés ; le compromis est donc une décision explicite plutôt qu'une hypothèse implicite (voir [Garde-fous](#guard-rails)).

## Activation du mode FIPS — Docker Compose

Deux changements : utiliser les images `-fips`, et définir `DD_FIPS_MODE`.

**1. Pointez les tags d'image vers les variantes FIPS.** Dans votre fichier `.env` ou votre override compose :

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. Définissez `DD_FIPS_MODE` dans les ancres d'environnement partagées.** Le fichier compose définit des blocs partagés que chaque service concerné fusionne, ce qui représente donc trois modifications plutôt qu'une par service :

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

Puis recréez la pile :

```bash
docker compose up -d --force-recreate
```

## Activation du mode FIPS — Kubernetes (Helm)

Définissez une seule valeur. Le chart sélectionne les variantes d'image `-fips` et définit `DD_FIPS_MODE` pour chaque pod :

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

Comme les magasins de données intégrés n'ont pas de variante FIPS et que Sensei n'est que partiellement couvert, une installation FIPS doit utiliser des instances PostgreSQL et Redis externes, et laisser Sensei désactivé à moins d'accepter la réserve mentionnée ci-dessus :

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

Si vous avez besoin de Sensei dans un environnement FIPS, activez-le délibérément avec
`fips.validate: false` et documentez la chaîne d'outils de scanners intégrée comme
non validée dans votre plan de sécurité système.

### Garde-fous

Si `fips.enabled` est à true alors qu'un composant sans variante FIPS est également activé, **le chart refuse de se générer** et nomme les composants fautifs :

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

Ceci est intentionnel. Un déploiement où la plupart des services utilisent une cryptographie validée alors qu'un ou deux ne le font pas silencieusement est pire qu'un échec évident : il paraît conforme, survit à une inspection superficielle, et ne se révèle que lors d'un audit. Si vous avez accepté ce risque par écrit, forcez-le avec `fips.validate: false`.

## Activation du mode FIPS — Amazon ECS / Fargate

Fargate est un type de lancement pour ECS, pas un service distinct : vous enregistrez des définitions de tâche ECS avec `requiresCompatibilities: ["FARGATE"]` et `networkMode: awsvpc`.

Si vous exécutez déjà DefectDojo Pro sur ECS, seuls deux éléments changent :

**1. Les tags d'image** reçoivent le suffixe `-fips` :

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2. `DD_FIPS_MODE=1`** dans le bloc `environment` de chaque conteneur exécutant
du code applicatif — uwsgi, celery worker, celery beat, l'initialiseur, les
workers d'orchestration, nginx et psirt.

Le reste de cette section décrit un déploiement ECS complet avec FIPS activé pour les
lecteurs partant de zéro.

### Ce qu'il faut provisionner en premier

| Ressource | Remarques |
|---|---|
| VPC avec deux sous-réseaux | Sous-réseaux privés plus une passerelle NAT, ou sous-réseaux publics avec `assignPublicIp: ENABLED` |
| RDS pour PostgreSQL | Utilisez un point de terminaison compatible FIPS et documentez-le comme composant hérité |
| ElastiCache pour Redis | Deux bases de données logiques sont utilisées : `/0` pour le broker Celery, `/1` pour le cache |
| Système de fichiers EFS | Deux répertoires : un pour `/app/media`, un contenant les certificats TLS nginx |
| Entrées Secrets Manager | URL de base de données, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY`, et votre licence Pro |
| Application Load Balancer | Écouteur HTTPS, transférant vers un groupe cible **HTTPS** sur le port **8443** |
| Dépôts ECR | Contenant les deux images `-fips` |
| Rôles IAM | Un rôle d'exécution pouvant tirer depuis ECR, écrire des journaux et lire ces secrets, plus un rôle de tâche |
| Groupe de journaux CloudWatch | Référencé par la configuration `awslogs` de chaque conteneur |

Placez le certificat et la clé TLS sur EFS sous les noms `dojo.crt` / `dojo.key`, ainsi que
`nginx_int.crt` / `nginx_int.key`. Les deux paires doivent exister — voir
[Trois éléments dont ECS a besoin](#three-things-ecs-needs-that-compose-provides-for-free)
ci-dessous pour comprendre pourquoi.

### 1. La tâche d'initialisation (à exécuter une fois par mise à niveau)

Applique les migrations et amorce les données de premier démarrage, puis se termine. C'est une tâche, pas un
service.

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

Attendez qu'elle atteigne l'état `STOPPED` avec un code de sortie 0 avant de démarrer les services.

### 2. Le service web (nginx + uwsgi)

Les deux conteneurs vivent dans une seule tâche afin que nginx puisse atteindre uwsgi sur `127.0.0.1`.

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

`USE_TLS=false` sélectionne la configuration on-prem, qui termine elle-même le TLS sur le
port 8443 à l'aide des certificats montés. Enregistrez-la et créez un service rattaché au
load balancer :

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. Le service worker (Celery worker et beat)

Même image et mêmes secrets que uwsgi ; le point d'entrée sélectionne le processus. Exécutez
exactement **une** réplique de beat.

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

### 4. Confirmez que le déploiement utilise une cryptographie validée

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

Chaque conteneur doit signaler le module avant de servir quoi que ce soit :

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

Si un conteneur est absent de cette sortie, c'est qu'il n'a jamais démarré, car la vérification
échoue de façon sécurisée (fail closed) — consultez son flux de journaux pour en connaître la raison.

### Trois éléments dont ECS a besoin et que Compose fournit gratuitement

Docker Compose vous donne un système de fichiers hôte à partir duquel faire des bind-mounts et une résolution DNS pour
les noms de conteneurs. Fargate ne fournit ni l'un ni l'autre, et chaque lacune empêche nginx de
démarrer plutôt que de dégrader silencieusement le service.

**1. Les certificats TLS doivent exister avant que nginx ne démarre.** nginx valide chaque
`ssl_certificate` au chargement de la configuration, et la configuration on-prem ne comporte pas de
chemin sans certificat : le port 8080 ne fait qu'émettre un `301` vers HTTPS, donc l'écouteur TLS
8443 est celui qui est fonctionnel. Montez un volume **EFS** sur `/etc/nginx/certs`
contenant `dojo.crt` / `dojo.key` et `nginx_int.crt` / `nginx_int.key`. Les deux
paires doivent être présentes même si vous n'utilisez qu'un seul écouteur.

Vous pouvez aussi définir `USE_TLS=true`, qui sert le fichier upstream `nginx_TLS.conf` et
permet à `GENERATE_TLS_CERTIFICATE=true` de faire générer son propre certificat par le point
d'entrée. Cette configuration redirige tous les chemins vers Django et ne sert pas
l'interface Vue depuis `/ui`, ce qui convient à un déploiement API uniquement ou strictement derrière un ALB.

**2. `DD_MCP_HOST` doit être résoluble.** nginx résout les noms d'hôte de `proxy_pass` au
chargement de la configuration. La valeur par défaut `mcp-server` se résout sous Compose (nom de conteneur) et
sous Helm (nom de Service), mais `awsvpc` ne donne aux conteneurs aucun nom DNS propre et
rejette à la fois `extraHosts` et `dnsSearchDomains` :

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

Le pointer vers le loopback lorsque le serveur MCP n'est pas déployé fait répondre `/mcp` avec un
`502` plutôt que d'empêcher le démarrage de toute la couche web.

**3. Les fichiers de configuration nginx proviennent de l'image.** L'image nginx `-fips`
intègre en dur l'ensemble de configuration on-prem, donc aucun montage n'est nécessaire. Compose superpose
ses propres bind mounts, donc le comportement de Compose reste inchangé.

### Autres spécificités de Fargate

- **Le stockage persistant doit être EFS.** Fargate ne peut pas attacher d'EBS, donc le répertoire
  média (`/app/media`) a besoin d'un volume EFS si vous conservez les fichiers de scan téléversés.
- **Aucun conteneur privilégié ni réseau hôte n'est requis.** Les images s'exécutent
  en tant qu'utilisateur non root, et `awsvpc` donne à chaque tâche sa propre interface réseau.
- **nginx → uwsgi.** Les conteneurs d'une *même* tâche partagent un espace de noms réseau, donc
  colocaliser nginx avec uwsgi permet à nginx de l'atteindre sur `127.0.0.1` — l'option correcte
  la plus simple. Si vous les séparez en services ECS distincts, faites pointer
  `DD_UWSGI_HOST` vers un nom de découverte de service Cloud Map et ouvrez le groupe de sécurité
  sur le port uwsgi.
- **Ne remplacez pas le point d'entrée d'uwsgi.** Définissez
  `DD_UWSGI_ENDPOINT=0.0.0.0:3031` et laissez l'ENTRYPOINT de l'image en place ;
  uwsgi parle le protocole uwsgi, ce que nginx attend. Remplacer le
  point d'entrée par `uwsgi --http` fait sauter au passage la vérification de démarrage FIPS.
- **L'initialiseur est une tâche à usage unique**, pas un service. Exécutez-le avec
  `aws ecs run-task` (ou comme étape préalable au déploiement) et laissez-le se terminer ; ne lui
  attribuez pas de nombre souhaité (desired count).
- **`healthCheck.retries` ne peut pas dépasser 10.** Les valeurs supérieures sont rejetées lors de
  l'enregistrement de la définition de tâche.
- **Faites pointer le load balancer vers le port 8443** avec un groupe cible HTTPS. L'écouteur
  8080 de la configuration on-prem ne fait que rediriger vers HTTPS, donc cibler le port 8080 crée une boucle.
  Un certificat auto-signé sur la cible est acceptable pour un ALB.
- **Terminaison TLS.** Si l'ALB termine le TLS pour les clients, documentez séparément la
  posture FIPS propre au load balancer dans votre SSP.
- **Les secrets** doivent se trouver dans Secrets Manager ou SSM Parameter Store via le
  bloc `secrets`, jamais dans `environment`. Cela inclut `DD_LICENSE`.

### Récupérer les preuves sur ECS

Le bloc de preuves de démarrage arrive dans le groupe de journaux nommé par la configuration
`awslogs` du conteneur :

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

À la demande, dans une tâche en cours d'exécution (nécessite `enableExecuteCommand` sur le service) :

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## Démarrage en échec sécurisé (fail-closed)

Lorsque `DD_FIPS_MODE` est défini, chaque conteneur vérifie au démarrage que le fournisseur validé est chargé et que les algorithmes non approuvés sont réellement refusés. **Si cette vérification échoue, le conteneur se termine au lieu de démarrer.**

Même raisonnement que pour le garde-fou du chart : un conteneur qui basculerait silencieusement vers une cryptographie non validée continuerait à servir du trafic tout en compromettant votre posture de conformité, et vous ne le découvririez que lors d'un audit.

## Vérifier le mode FIPS

Chaque conteneur affiche un bloc de preuves au démarrage, ce qui constitue généralement la forme la plus pratique pour un évaluateur. Sur les runtimes gérés, il arrive dans votre agrégateur de journaux :

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

Récupérez-le avec :

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

Vous pouvez également vérifier à la demande dans un conteneur en cours d'exécution :

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

Pour les services Go, le mode FIPS est compilé en dur et signalé par le runtime Go :

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## Différences de comportement en mode FIPS

Certains algorithmes non approuvés sont indisponibles, ce qui modifie quelques comportements. Voici ceux qu'il convient d'anticiper.

### Hachage des mots de passe

Les builds FIPS utilisent **PBKDF2-SHA256** comme fonction de hachage de mot de passe par défaut. Argon2, bcrypt et scrypt ne sont pas des fonctions de dérivation de clé approuvées FIPS et sont désactivées.

Les utilisateurs existants ne sont pas bloqués. Django rehache chaque mot de passe en PBKDF2 lors de la prochaine connexion réussie de l'utilisateur, et les hachages PBKDF2-SHA1 restent vérifiables pendant la transition. Si vous préférez une bascule immédiate, forcez une réinitialisation de mot de passe plutôt que de compter sur une migration progressive.

### Suites de chiffrement TLS

ChaCha20-Poly1305 n'est pas approuvé FIPS et est retiré de chaque configuration nginx qui termine le TLS, et TLS 1.3 est fixé à `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`. TLS 1.2 et TLS 1.3 restent disponibles avec les suites AES-GCM. Les clients qui ne prennent en charge que ChaCha20 ne pourront pas se connecter.

Le module validé refuserait de toute façon ChaCha20 ; le retirer de la configuration signifie que le serveur n'annonce jamais une suite qu'il ne peut pas honorer, ce qui rend la configuration déployée auto-documentée pour un évaluateur.

### Authentification de base des métriques

Lorsque l'authentification des métriques nginx est activée, le hachage du mot de passe utilise le crypt SHA-256 plutôt que le format MD5 d'Apache (`apr1`), que le module validé refuse. Cela est transparent sauf si vous générez vous-même les entrées `.htpasswd`, auquel cas utilisez `openssl passwd -5`.

### Parseurs de scan

Certains parseurs utilisent MD5 pour construire des clés de déduplication. Il s'agit d'un usage non lié à la sécurité, explicitement annoté comme tel, de sorte que ces parseurs continuent de fonctionner normalement sous FIPS. Aucune fonctionnalité de parseur n'est perdue.

## Notes de déploiement

- **Terminaison TLS.** Si le TLS se termine au niveau d'un load balancer devant DefectDojo, cet équipement est responsable de sa propre posture FIPS et doit être documenté séparément dans votre plan de sécurité système. L'image nginx `-fips` couvre le TLS terminé par DefectDojo lui-même.
- **Base de données et cache.** PostgreSQL et Redis sont des produits distincts. Dans un environnement FIPS, utilisez des instances conformes FIPS — par exemple une base de données gérée proposant un point de terminaison FIPS — et documentez-les comme composants hérités.
- **Périmètre de conformité.** DefectDojo n'est pas lui-même un module cryptographique et ne détient aucun certificat propre. Ce que ces images fournissent, c'est une cryptographie validée réalisée par des modules qui, eux, en détiennent un, fonctionnant en mode approuvé FIPS. Votre évaluateur voudra connaître les noms des modules et les numéros de certificat, qui apparaissent dans la sortie de preuves ci-dessus.
