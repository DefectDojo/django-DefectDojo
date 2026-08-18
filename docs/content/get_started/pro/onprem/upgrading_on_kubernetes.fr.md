---
title: Guide de mise à niveau de DefectDojo Pro
description: Mettez à niveau une version Helm existante de DefectDojo Pro, y compris
  le téléchargement du chart, l'exécution de la mise à niveau et la restauration
draft: false
weight: 14
audience: pro
aliases:
- /fr/get_started/pro/onprem/upgrading/
---

<!--
  Généré à partir du dépôt du chart Helm DefectDojo Pro.
  Source : docs/UPGRADE_GUIDE.md à la version de chart 3.1.304.
  Modifiez le guide source, pas ce fichier. Les modifications locales sont
  écrasées à la prochaine publication du chart.
-->
Ce guide explique comment mettre à niveau une version existante de DefectDojo Pro vers une
version de chart plus récente. La méthode recommandée consiste à récupérer le chart directement
depuis le registre OCI de DefectDojo — aucune extraction de zip n'est nécessaire. Le flux de
travail avec zip packagé utilisé lors de l'installation fonctionne également pour les mises à
niveau et est documenté ci-dessous.

Ce guide couvre :

- [Avant de mettre à niveau](#before-you-upgrade)
- [Source du chart : registre OCI](#chart-source-oci-registry)
- [S'authentifier auprès du registre](#authenticate-to-the-registry)
- [Mise à niveau via le registre OCI (recommandé)](#upgrade-via-oci-registry-recommended)
- [Mise à niveau via un zip extrait](#upgrade-via-extracted-zip)
- [Mise à niveau avec ArgoCD](#upgrade-with-argocd)
- [Vérifier la mise à niveau](#verify-the-upgrade)
- [Restauration](#rollback)
- [Dépannage](#troubleshooting)

---

## Contenu d'une mise à niveau

Une version de DefectDojo Pro se compose d'une version de chart, d'un ensemble de versions
d'images de conteneurs et des fichiers de paramètres Pro. Ces éléments sont construits et testés
ensemble et doivent évoluer ensemble. Mettre à niveau les tags d'image seuls n'est pas pris en
charge et cassera le déploiement.

Il en va de même pour les paramètres. Un nouveau `pro_settings.py` est livré avec presque chaque
version. Ne conservez jamais une ancienne copie lors d'une mise à niveau, et ne modifiez jamais
manuellement une version antérieure : l'application doit exécuter le `pro_settings.py`
correspondant à sa version. Vos propres personnalisations doivent se trouver dans
`local_settings.py`, qui est préservé lors des mises à niveau et qui est le seul des deux
fichiers à modifier.

L'utilisation du chart s'en occupe pour vous. Il fournit et monte le `pro_settings.py`
correspondant aux côtés de votre `local_settings.py`, de sorte qu'il n'y a rien à copier ni à
migrer manuellement.

## Avant de mettre à niveau

Chaque mise à niveau doit commencer de la même manière. Ignorer ces étapes est la cause la plus
fréquente d'échec des mises à niveau.

1. **Lisez les notes de version** pour chaque version comprise entre votre version actuelle et
   la version cible. Les changements majeurs, les nouveaux champs obligatoires et les prérequis
   de migration y sont signalés. La page de version GitHub de chaque tag renvoie vers le journal
   des modifications.
2. **Vérifiez votre version de chart actuelle.** C'est le point de départ de la mise à niveau :

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **Sauvegardez votre base de données.** Les mises à niveau du chart peuvent inclure des
   migrations Django qui modifient le schéma. Effectuez un dump logique (ou un instantané au
   niveau du stockage) de l'instance PostgreSQL avant de continuer.
4. **Ayez vos fichiers de valeurs à disposition.** La commande de mise à niveau doit transmettre
   le même préréglage de plateforme, le même préréglage de profil et le même fichier de valeurs
   client que ceux utilisés lors de l'installation. Des fichiers de valeurs manquants ou
   divergents provoquent des différences inattendues.
5. **Vérifiez que les références aux secrets existent toujours.** Si vous avez effectué
   l'installation avec `--set dojo.existingSecret=...` ou `--set license.existingSecret=...`,
   vérifiez que ces secrets Kubernetes sont toujours présents dans l'espace de noms.
6. **Effectuez d'abord un rendu local de la mise à niveau** pour détecter les champs manquants,
   les valeurs invalides ou les erreurs de template avant de toucher au cluster :

   ```bash
   helm template dojopro $CHART_REF \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/<size>.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     > /tmp/dojopro-upgrade-render.yaml
   ```

   `$CHART_REF` est la référence OCI (voir ci-dessous) ou le chemin du chart extrait.

> Définissez `NAMESPACE` une seule fois — chaque commande de ce guide utilise `$NAMESPACE` :
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **Le comportement par défaut des politiques réseau a changé.** Les NetworkPolicies sont
> désormais régies par `networkPolicy.profile`, dont la valeur par défaut est `standard` : tout
> le trafic sortant ainsi que le trafic entrant entre les pods de cette version sont autorisés
> (le trafic entrant externe reste restreint au chemin d'ingress). C'est plus permissif que
> l'ancienne liste d'autorisation toujours granulaire pour le trafic sortant. Pour conserver le
> comportement verrouillé, définissez `networkPolicy.profile: aggressive` et vérifiez les
> exceptions (`nodeLocalDns`, `dnsSelectors`, `externalAPIs`) — voir
> [Politiques réseau](/get_started/pro/onprem/installing_on_kubernetes/#network-policies).

> **Exigence de base de données de l'orchestrateur.** L'orchestrateur (`ddorch`) utilise une
> seconde base de données nommée `<main-db-name>-ddorch` et la crée au démarrage si elle
> n'existe pas. Si le rôle de votre application ne dispose pas de `CREATEDB`, créez-la au
> préalable (`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`) avant de mettre à niveau
> vers une version de chart qui active ddorch — sinon le pod ddorch échoue avec
> `permission denied to create database (SQLSTATE 42501)`. Voir
> [Préflight : base de données de l'orchestrateur (ddorch)](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).

> **Valeur par défaut du renommage Organization/Asset.**
> `dojo.V3EnableOrganizationAssetRelabel` a désormais pour valeur par défaut `null` (auto) : il
> est **activé pour les nouvelles installations** et **désactivé lors des mises à niveau**, de
> sorte que le renommage de l'interface (Organization/Asset remplaçant ProductType/Product) ne
> s'active jamais de manière inattendue pour une version existante. Pour activer ce renommage sur
> une version mise à niveau, définissez explicitement `dojo.V3EnableOrganizationAssetRelabel:
> true` ; une valeur explicite `true`/`false` l'emporte toujours sur la valeur automatique par
> défaut.

---

## Source du chart : registre OCI

Le chart est publié dans le GCP Artifact Registry de DefectDojo sous forme d'artefact OCI :

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Chaque version est étiquetée avec la version du chart (par exemple `2.57.2`). La version du
chart correspond à la version de l'application dans `Chart.yaml`, donc le tag que vous passez à
`helm upgrade --version` est le même numéro de version que celui affiché sur la version GitHub.

Lister les versions de chart disponibles :

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **Pourquoi OCI pour les mises à niveau ?** Les préréglages (`presets/platforms/*.yaml`,
> `presets/profiles/*.yaml`) sont intégrés dans le chart. Référencer le chart par son URL OCI
> récupère automatiquement les bonnes versions de préréglages pour le chart cible — pas d'étape
> de ré-extraction, pas de préréglages obsolètes.

---

## S'authentifier auprès du registre

Le registre est privé. Helm doit être connecté avant de pouvoir récupérer le chart. Utilisez une
clé de compte de service GCP ou un jeton d'accès de courte durée fourni par le support
DefectDojo.

**Option A — clé JSON de compte de service :**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**Option B — connexion interactive gcloud (pour les personnes disposant d'un accès au
registre) :**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

Les jetons d'accès issus de `gcloud auth print-access-token` expirent au bout d'une heure.
Relancez `helm registry login` si vous voyez une erreur `401 Unauthorized` pendant la mise à
niveau.

> **Environnements isolés / protégés par pare-feu :** si les nœuds de votre cluster peuvent
> joindre `us-south1-docker.pkg.dev` mais que votre poste de travail ne le peut pas, utilisez le
> flux de travail avec zip extrait ci-dessous. Le flux de travail OCI ne fonctionne que lorsque
> l'hôte exécutant `helm upgrade` peut joindre le registre.

---

## Mise à niveau via le registre OCI (recommandé)

Pointez `helm upgrade` directement vers l'URL OCI et fixez la version du chart avec `--version`.
Tous les fichiers de valeurs, les indicateurs `--set` et `--set-file` sont identiques à ceux de
l'installation d'origine.

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
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> Les chemins de préréglages de plateforme et de profil ci-dessus sont `presets/platforms/...`
> (sans préfixe `$CHART/`). Lorsque Helm récupère un chart depuis OCI, les préréglages se
> trouvent à l'intérieur du chart récupéré, mais `-f` pointe ici vers des **copies locales** de
> ces fichiers. Si vous ne conservez pas de copies locales des préréglages, extrayez d'abord le
> chart avec `helm pull oci://... --version $VERSION --untar` et référencez-les depuis le
> répertoire extrait — ou utilisez le flux de travail avec zip extrait.

**Variante avec secrets en ligne et fichier de licence :**

```bash
helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> Fixez toujours `--version`. Si vous l'omettez, le registre résout le tag quel qu'il soit au
> moment de la commande — ce n'est ni reproductible, ni auditable. Fixez la version afin que les
> relances, les restaurations et la réponse aux incidents se réfèrent toutes au même artefact.

---

## Mise à niveau via un zip extrait

Pour les postes de travail qui ne peuvent pas joindre le registre OCI, ou pour les clients qui
préfèrent préparer le chart sous forme de fichier local, le zip packagé de la version GitHub
fonctionne de la même manière lors d'une mise à niveau que lors d'une installation. La seule
différence par rapport à l'installation est le verbe de commande (`helm upgrade` au lieu de
`helm install`).

1. Téléchargez `dojo-pro-helm-bundled-<version>.zip` (ainsi que la signature détachée `.asc`)
   depuis la version GitHub.
2. Vérifiez la signature à l'aide de la clé publique (`dojo-pro-release-signing.asc`) comme
   indiqué dans le guide d'installation.
3. Extrayez le chart vers un **chemin versionné** pour que les préréglages n'entrent pas en
   conflit avec d'anciennes extractions :

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. Exécutez la mise à niveau avec le chemin du chart extrait — les mêmes fichiers de valeurs et
   indicateurs que votre installation d'origine :

   ```bash
   helm upgrade dojopro $CHART \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/standard.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     --set-file ddorch.tls.rootCa=orch_ca.crt \
     --set-file ddorch.tls.cert=orch_server.crt \
     --set-file ddorch.tls.key=orch_server.key \
     --wait --timeout 15m
   ```

> **Ré-extrayez à chaque mise à niveau.** Les fichiers de préréglages évoluent entre les
> versions du chart. Réutiliser une ancienne extraction fixe silencieusement votre mise à niveau
> aux anciennes valeurs par défaut des préréglages.

---

## Mise à niveau avec ArgoCD

Lorsque DefectDojo Pro est géré par ArgoCD, la mise à niveau consiste en une seule modification
de `targetRevision` dans la spec Application. Les préréglages de plateforme et de profil sont
versionnés à l'intérieur du chart, de sorte qu'ils se mettent à jour en même temps.

```yaml
spec:
  source:
    repoURL: us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2
    chart: dojopro
    targetRevision: <chart-version>    # bump this
    helm:
      valueFiles:
        - presets/platforms/aws-eks.yaml
        - presets/profiles/standard.yaml
      values: |
        # your environment-specific values
      parameters:
        - name: dojo.existingSecret
          value: dojopro-secrets
        - name: license.existingSecret
          value: dojopro-license
```

Synchronisez l'Application après avoir modifié `targetRevision`. ArgoCD récupérera le nouveau
chart depuis le registre OCI et effectuera la réconciliation.

> ArgoCD a besoin de ses propres identifiants pour le registre OCI. Configurez le secret du
> dépôt avec `type: helm` et `enableOCI: "true"`. Consultez la
> [documentation ArgoCD sur Helm OCI](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support)
> pour connaître la forme exacte du Secret.

---

## Vérifier la mise à niveau

Une fois que `helm upgrade` retourne (ou qu'ArgoCD indique Synced / Healthy), vérifiez que la
nouvelle révision est active :

```bash
# Chart revision bumped and status is deployed
helm list -n $NAMESPACE

# All pods Running and Ready — expect django, celery worker/beat,
# connectors, ddorch, ddorch-workers, and (if enabled) mcp-server
kubectl get pods -n $NAMESPACE

# Migrations succeeded — the initializer job should show Completed
kubectl get jobs -n $NAMESPACE

# App version matches the target
kubectl get deployment -n $NAMESPACE \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

Accédez à la page de connexion pour vérifier que l'interface s'affiche et que l'utilisateur admin
peut s'authentifier. Pour des vérifications programmatiques, le point de terminaison `/login/`
renvoie 200 lorsque l'application est en bonne santé.

---

## Restauration

Helm conserve l'historique des versions par révision. Si la mise à niveau entraîne une
régression du comportement, revenez à la révision précédente :

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **Les migrations de base de données ne sont pas annulées.** Le rollback Helm restaure l'état
> du manifeste (images, configurations, secrets) mais n'exécute pas `migrate --revert`. Si la
> mise à niveau a appliqué une migration de schéma que vous devez annuler, restaurez à partir de
> la sauvegarde effectuée dans [Avant de mettre à niveau](#before-you-upgrade) ou coordonnez une
> annulation manuelle de la migration avec le support DefectDojo avant de restaurer la version
> Helm.

Les utilisateurs d'ArgoCD peuvent revenir en arrière en annulant la modification de
`targetRevision` dans git (ou via `argocd app rollback`) puis en synchronisant.

---

## Dépannage

**`401 Unauthorized` lors de la récupération du chart.**
Le jeton d'accès a expiré. Relancez `helm registry login` avec un nouveau
`gcloud auth print-access-token`.

**`Error: UPGRADE FAILED: cannot patch ... field is immutable`.**
Un sélecteur ou un autre champ immuable a dérivé. Le chart fixe des labels de sélecteur stables,
donc cela signifie généralement une modification en place antérieure d'un Deployment. Capturez
le diff, supprimez la ressource fautive, puis relancez la mise à niveau afin que Helm la recrée.

**`Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`.**
Helm 4 utilise le server-side apply, qui suit la propriété des champs. Cette erreur signifie
qu'un autre gestionnaire — `kubectl edit`, `kubectl scale`, ou le contrôleur HPA
(`kube-controller-manager`) — a modifié un champ que Helm gère, le plus souvent
`.spec.replicas`. Reprenez la propriété une bonne fois pour toutes :

```bash
helm upgrade ... --force-conflicts
```

Les versions de chart intégrant ce correctif omettent `replicas` des Deployments dont le HPA
est activé, de sorte que la mise à l'échelle du HPA n'entre plus en conflit avec les mises à
niveau. Si vous avez mis à l'échelle manuellement un Deployment avec `kubectl`, préférez ajuster
la valeur `replicas`/`horizontalpodautoscaler` correspondante afin que le chart reste le
propriétaire.

**`Error: UPGRADE FAILED: timed out waiting for the condition`.**
Les pods n'ont pas atteint l'état Ready dans le délai `--timeout`. Inspectez la charge de
travail à la traîne :

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

Causes courantes : échecs de récupération d'image (authentification au registre), migration de
schéma toujours en cours (augmentez `--timeout`), ou sondes de disponibilité (readiness) qui
échouent contre un FQDN mal configuré.

**Le préréglage a changé entre les versions et mon fichier de valeurs entre désormais en conflit.**
Effectuez à nouveau le rendu avec `helm template` (voir
[Avant de mettre à niveau](#before-you-upgrade)) et réconciliez vos surcharges avec les nouvelles
valeurs par défaut du préréglage avant d'exécuter `helm upgrade`.

**`values don't meet the specifications of the schema ... got string, want boolean`.**
Une valeur on/off dans votre surcharge est entre guillemets. Helm traite `"false"` comme une
chaîne non vide, et une chaîne non vide est évaluée comme vraie (truthy), de sorte que la
fonctionnalité s'activait alors que vous vouliez la désactiver. Le schéma rejette désormais la
forme entre guillemets au lieu de la laisser passer. Retirez les guillemets :

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

Le message d'erreur indique le chemin fautif. Les valeurs non entre guillemets `false`, `no`, et
`off` sont toutes interprétées comme un véritable booléen et sont acceptées.
