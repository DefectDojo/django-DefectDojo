---
title: Guida all'aggiornamento di DefectDojo Pro
description: Aggiorna una release Helm esistente di DefectDojo Pro, incluso il recupero
  del chart, l'esecuzione dell'aggiornamento e il rollback
draft: false
weight: 14
audience: pro
aliases:
- /it/get_started/pro/onprem/upgrading/
---

<!--
  Generato dal repository del chart Helm di DefectDojo Pro.
  Fonte: docs/UPGRADE_GUIDE.md alla versione del chart 3.1.304.
  Modifica la guida di origine, non questo file. Le modifiche locali vengono sovrascritte
  al successivo rilascio del chart.
-->
Copre l'aggiornamento di un'installazione DefectDojo Pro esistente a una versione più recente del chart.
Il percorso consigliato consiste nel recuperare il chart direttamente dal registro OCI di DefectDojo —
non è richiesta alcuna estrazione dello zip. Il flusso di lavoro basato sullo zip pacchettizzato usato
al momento dell'installazione funziona anche per gli aggiornamenti ed è documentato di seguito.

Questa guida copre:

- [Prima di aggiornare](#before-you-upgrade)
- [Origine del chart: registro OCI](#chart-source-oci-registry)
- [Autenticazione al registro](#authenticate-to-the-registry)
- [Aggiornamento tramite registro OCI (consigliato)](#upgrade-via-oci-registry-recommended)
- [Aggiornamento tramite zip estratto](#upgrade-via-extracted-zip)
- [Aggiornamento con ArgoCD](#upgrade-with-argocd)
- [Verifica dell'aggiornamento](#verify-the-upgrade)
- [Rollback](#rollback)
- [Risoluzione dei problemi](#troubleshooting)

---

## Cosa copre un aggiornamento

Una release di DefectDojo Pro è una versione del chart, un insieme di versioni delle immagini container e i file delle impostazioni Pro. Questi elementi vengono costruiti e testati insieme e devono essere aggiornati insieme. Aggiornare da soli i tag delle immagini non è supportato e comprometterà il deployment.

Lo stesso vale per le impostazioni. Una nuova `pro_settings.py` viene rilasciata con quasi ogni release. Non portare mai avanti una copia tra un aggiornamento e l'altro, e non modificare mai manualmente una versione precedente: l'applicazione deve eseguire la `pro_settings.py` corrispondente alla propria versione. Le tue personalizzazioni vanno inserite in `local_settings.py`, che viene preservato negli aggiornamenti ed è l'unico dei due file che dovresti modificare.

Usare il chart si occupa di questo aspetto per te. Include e monta la `pro_settings.py` corrispondente insieme al tuo `local_settings.py`, quindi non c'è nulla da copiare o migrare manualmente.

## Prima di aggiornare

Ogni aggiornamento dovrebbe iniziare allo stesso modo. Saltare questi passaggi è la causa più comune di aggiornamenti falliti.

1. **Leggi le note di rilascio** per ogni versione tra la tua release attuale e quella di destinazione. Le modifiche non retrocompatibili, i nuovi campi obbligatori e i prerequisiti di migrazione sono segnalati lì. La pagina di release di GitHub per ogni tag rimanda al changelog.
2. **Controlla la versione attuale del tuo chart.** Questo è il punto di partenza per l'aggiornamento:

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **Esegui il backup del tuo database.** Gli aggiornamenti del chart possono includere migrazioni Django che modificano lo schema. Esegui un dump logico (o uno snapshot a livello di storage) dell'istanza PostgreSQL prima di procedere.
4. **Tieni a disposizione i tuoi file values.** Il comando di aggiornamento deve passare lo stesso preset di piattaforma, preset di profilo e file values del cliente usati all'installazione. File values mancanti o disallineati causano differenze inaspettate.
5. **Conferma che i riferimenti ai secret esistano ancora.** Se hai effettuato l'installazione con `--set dojo.existingSecret=...` o `--set license.existingSecret=...`, verifica che quei secret Kubernetes siano ancora presenti nel namespace.
6. **Renderizza prima l'aggiornamento in locale** per individuare campi mancanti, valori non validi o errori di template prima di intervenire sul cluster:

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

   `$CHART_REF` è il riferimento OCI (vedi sotto) oppure il percorso del chart estratto.

> Imposta `NAMESPACE` una sola volta — ogni comando in questa guida usa `$NAMESPACE`:
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **Il valore predefinito della policy di rete è cambiato.** Le NetworkPolicy sono ora governate da `networkPolicy.profile`, che per impostazione predefinita è `standard`: tutto l'egress e l'ingress tra i pod di questa stessa release sono consentiti (l'ingress esterno resta comunque limitato al percorso di ingress). Questo è più permissivo rispetto alla precedente allowlist di egress sempre granulare. Per mantenere il comportamento bloccato, imposta `networkPolicy.profile: aggressive` e rivedi le eccezioni (`nodeLocalDns`, `dnsSelectors`, `externalAPIs`) — vedi [Network Policies](/get_started/pro/onprem/installing_on_kubernetes/#network-policies).

> **Requisito del database dell'orchestratore.** L'orchestratore (`ddorch`) utilizza un secondo database chiamato `<main-db-name>-ddorch` e lo crea all'avvio se non esiste già. Se il ruolo della tua applicazione non ha `CREATEDB`, crealo in anticipo (`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`) prima di aggiornare a una versione del chart che abilita ddorch — altrimenti il pod ddorch fallisce con `permission denied to create database (SQLSTATE 42501)`. Vedi [Pre-flight: Orchestrator (ddorch) Database](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).

> **Valore predefinito della rietichettatura Organization/Asset.** `dojo.V3EnableOrganizationAssetRelabel` ora ha come valore predefinito `null` (automatico): è **abilitato per le nuove installazioni** e **disattivato negli aggiornamenti**, in modo che la rietichettatura dell'interfaccia (Organization/Asset al posto di ProductType/Product) non si attivi mai inaspettatamente su una release esistente. Per attivarla su una release aggiornata, imposta esplicitamente `dojo.V3EnableOrganizationAssetRelabel: true`; un valore esplicito `true`/`false` prevale sempre sul valore automatico predefinito.

---

## Origine del chart: registro OCI

Il chart è pubblicato nel GCP Artifact Registry di DefectDojo come artefatto OCI:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Ogni release è taggata con la versione del chart (ad esempio `2.57.2`). La versione del chart corrisponde alla versione dell'app in `Chart.yaml`, quindi il tag che passi a `helm upgrade --version` è lo stesso numero di versione mostrato nella release di GitHub.

Elenca le versioni disponibili del chart:

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **Perché OCI per gli aggiornamenti?** I preset (`presets/platforms/*.yaml`, `presets/profiles/*.yaml`) sono pacchettizzati all'interno del chart. Fare riferimento al chart tramite il suo URL OCI recupera automaticamente le versioni corrette dei preset per il chart di destinazione — nessun passaggio di ri-estrazione, nessun preset obsoleto.

---

## Autenticazione al registro

Il registro è privato. Helm deve effettuare l'accesso prima di poter recuperare il chart. Usa una chiave di service account GCP o un token di accesso a breve durata fornito dal supporto DefectDojo.

**Opzione A — chiave JSON del service account:**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**Opzione B — accesso interattivo con gcloud (per operatori umani con accesso al registro):**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

I token di accesso generati da `gcloud auth print-access-token` scadono dopo un'ora. Riesegui `helm registry login` se durante l'aggiornamento viene restituito un `401 Unauthorized`.

> **Ambienti air-gapped o protetti da firewall:** se i nodi del tuo cluster possono raggiungere `us-south1-docker.pkg.dev` ma la tua workstation no, usa il flusso di lavoro con lo zip estratto descritto di seguito. Il flusso di lavoro OCI funziona solo quando l'host che esegue `helm upgrade` può raggiungere il registro.

---

## Aggiornamento tramite registro OCI (consigliato)

Punta `helm upgrade` direttamente all'URL OCI e blocca la versione del chart con `--version`. Tutti i file values, i flag `--set` e i flag `--set-file` sono gli stessi dell'installazione originale.

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

> I percorsi dei preset di piattaforma e di profilo sopra riportati sono `presets/platforms/...` (senza il prefisso `$CHART/`). Quando Helm recupera un chart da OCI, i preset si trovano all'interno del chart scaricato, ma qui `-f` punta a **copie locali** di quei file. Se non mantieni copie locali dei preset, estrai prima il chart con `helm pull oci://... --version $VERSION --untar` e fai riferimento ad essi dalla directory estratta — oppure usa il flusso di lavoro con lo zip estratto.

**Variante con secret inline + file di licenza:**

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

> Blocca sempre la versione con `--version`. Ometterlo recupera qualunque tag il registro risolva al momento dell'esecuzione del comando — non ripetibile, non verificabile. Blocca la versione in modo che riesecuzioni, rollback e risposta agli incidenti facciano tutti riferimento allo stesso artefatto.

---

## Aggiornamento tramite zip estratto

Per le workstation che non possono raggiungere il registro OCI, o per i clienti che preferiscono predisporre il chart come file locale, lo zip pacchettizzato della release di GitHub funziona allo stesso modo in fase di aggiornamento come in fase di installazione. L'unica differenza rispetto all'installazione è il verbo del comando (`helm upgrade` invece di `helm install`).

1. Scarica `dojo-pro-helm-bundled-<version>.zip` (e la firma separata `.asc`) dalla release di GitHub.
2. Verifica la firma usando la chiave pubblica (`dojo-pro-release-signing.asc`) come documentato nella guida di installazione.
3. Estrai il chart in un **percorso versionato** in modo che i preset non entrino in conflitto con estrazioni precedenti:

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. Esegui l'aggiornamento usando il percorso del chart estratto — gli stessi file values e flag della tua installazione originale:

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

> **Ri-estrai a ogni aggiornamento.** I file dei preset evolvono tra le versioni del chart. Riutilizzare un'estrazione precedente blocca silenziosamente il tuo aggiornamento ai vecchi valori predefiniti dei preset.

---

## Aggiornamento con ArgoCD

Quando DefectDojo Pro è gestito da ArgoCD, l'aggiornamento consiste in una singola modifica a `targetRevision` nello spec dell'Application. I preset di piattaforma e di profilo sono versionati all'interno del chart, quindi si aggiornano in sincronia.

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

Sincronizza l'Application dopo aver modificato `targetRevision`. ArgoCD recupererà il nuovo chart dal registro OCI ed eseguirà la riconciliazione.

> ArgoCD necessita di proprie credenziali per il registro OCI. Configura il secret del repo con `type: helm` e `enableOCI: "true"`. Consulta la [documentazione Helm OCI](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support) di ArgoCD per la struttura esatta del Secret.

---

## Verifica dell'aggiornamento

Dopo che `helm upgrade` restituisce il controllo (o ArgoCD riporta Synced / Healthy), conferma che la nuova revisione sia attiva:

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

Visita la pagina di login per confermare che l'interfaccia si carichi e che l'utente amministratore possa autenticarsi. Per controlli programmatici, l'endpoint `/login/` restituisce 200 quando l'app è integra.

---

## Rollback

Helm mantiene la cronologia delle release per revisione. Se l'aggiornamento causa una regressione del comportamento, esegui il rollback alla revisione precedente:

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **Le migrazioni del database non vengono annullate dal rollback.** Il rollback di Helm ripristina lo stato del manifest (immagini, configurazioni, secret) ma non esegue `migrate --revert`. Se l'aggiornamento ha applicato una migrazione dello schema che devi annullare, ripristina dal backup effettuato in [Prima di aggiornare](#before-you-upgrade) oppure coordina con il supporto DefectDojo un'inversione manuale della migrazione prima di eseguire il rollback della release Helm.

Gli utenti ArgoCD possono eseguire il rollback annullando la modifica a `targetRevision` in git (o tramite `argocd app rollback`) e sincronizzando.

---

## Risoluzione dei problemi

**`401 Unauthorized` durante il recupero del chart.**
Il token di accesso è scaduto. Riesegui `helm registry login` con un nuovo `gcloud auth print-access-token`.

**`Error: UPGRADE FAILED: cannot patch ... field is immutable`.**
Un selector o un altro campo immutabile è stato modificato. Il chart blocca etichette di selector stabili, quindi questo di solito significa che in precedenza è stata effettuata una modifica in-place a un Deployment. Registra la differenza, elimina la risorsa incriminata e riesegui l'aggiornamento in modo che Helm la ricrei.

**`Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`.**
Helm 4 utilizza la server-side apply, che tiene traccia della proprietà dei campi. Questo errore significa che un altro manager — `kubectl edit`, `kubectl scale`, oppure il controller HPA (`kube-controller-manager`) — ha modificato un campo renderizzato da Helm, più comunemente `.spec.replicas`. Riprendi la proprietà una volta:

```bash
helm upgrade ... --force-conflicts
```

Le versioni del chart con questa correzione omettono `replicas` dai Deployment il cui HPA è abilitato, in modo che lo scaling dell'HPA non entri più in conflitto con gli aggiornamenti. Se hai scalato manualmente un Deployment con `kubectl`, preferisci invece regolare il valore corrispondente `replicas`/`horizontalpodautoscaler`, così il chart resta il proprietario.

**`Error: UPGRADE FAILED: timed out waiting for the condition`.**
I pod non hanno raggiunto lo stato Ready entro la finestra di `--timeout`. Ispeziona il workload in ritardo:

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

Cause comuni: errori di pull dell'immagine (autenticazione al registro), migrazione dello schema ancora in corso (aumenta `--timeout`), oppure probe di readiness che falliscono a causa di un FQDN configurato in modo errato.

**Il preset è cambiato tra le versioni e il mio file values ora è in conflitto.**
Ri-renderizza con `helm template` (vedi [Prima di aggiornare](#before-you-upgrade)) e riconcilia i tuoi override con i nuovi valori predefiniti del preset prima di eseguire `helm upgrade`.

**`values don't meet the specifications of the schema ... got string, want boolean`.**
Un valore on/off nel tuo override è tra virgolette. Helm tratta `"false"` come una stringa non vuota, e una stringa non vuota è "truthy", quindi la funzionalità si attivava **on** quando l'intenzione era disattivarla. Lo schema ora rifiuta la forma tra virgolette invece di lasciarla passare. Rimuovi le virgolette:

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

Il messaggio di errore indica il percorso incriminato. `false`, `no` e `off` senza virgolette vengono tutti interpretati come booleani reali e accettati.
