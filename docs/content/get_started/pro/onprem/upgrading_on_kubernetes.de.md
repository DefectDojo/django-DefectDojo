---
title: DefectDojo Pro Upgrade-Leitfaden
description: Aktualisieren Sie ein bestehendes DefectDojo Pro Helm-Release, einschließlich
  des Abrufens des Charts, der Durchführung des Upgrades und des Rollbacks
draft: false
weight: 14
audience: pro
aliases:
- /get_started/pro/onprem/upgrading/
---

<!--
  Generiert aus dem DefectDojo Pro Helm-Chart-Repository.
  Quelle: docs/UPGRADE_GUIDE.md, Chart-Version 3.1.304.
  Bearbeiten Sie den Quell-Leitfaden, nicht diese Datei. Lokale Änderungen
  werden beim nächsten Release des Charts überschrieben.
-->
Beschreibt das Upgrade eines bestehenden DefectDojo Pro Release auf eine
neuere Chart-Version. Der empfohlene Weg besteht darin, den Chart direkt aus
der DefectDojo OCI-Registry abzurufen — eine Zip-Extraktion ist nicht
erforderlich. Der bei der Installation verwendete Workflow mit dem gepackten
Zip funktioniert auch für Upgrades und wird weiter unten beschrieben.

Dieser Leitfaden behandelt:

- [Vor dem Upgrade](#before-you-upgrade)
- [Chart-Quelle: OCI-Registry](#chart-source-oci-registry)
- [Bei der Registry authentifizieren](#authenticate-to-the-registry)
- [Upgrade über die OCI-Registry (empfohlen)](#upgrade-via-oci-registry-recommended)
- [Upgrade über extrahiertes Zip](#upgrade-via-extracted-zip)
- [Upgrade mit ArgoCD](#upgrade-with-argocd)
- [Upgrade überprüfen](#verify-the-upgrade)
- [Rollback](#rollback)
- [Fehlerbehebung](#troubleshooting)

---

## Was ein Upgrade umfasst

Ein DefectDojo Pro Release besteht aus einer Chart-Version, einer Reihe von
Container-Image-Versionen und den Pro-Settings-Dateien. Diese werden
gemeinsam gebaut und getestet und müssen auch gemeinsam aktualisiert werden.
Das isolierte Aktualisieren der Image-Tags wird nicht unterstützt und
beschädigt das Deployment.

Das Gleiche gilt für die Einstellungen. Mit nahezu jedem Release wird eine
neue `pro_settings.py` ausgeliefert. Übernehmen Sie niemals eine Kopie über
ein Upgrade hinweg, und patchen Sie eine ältere Version niemals manuell: Die
Anwendung muss die `pro_settings.py` ausführen, die zu ihrer Version passt.
Ihre eigenen Anpassungen gehören in `local_settings.py`, die bei Upgrades
erhalten bleibt und von den beiden Dateien die einzige ist, die Sie
bearbeiten sollten.

Die Verwendung des Charts übernimmt dies für Sie. Er liefert die passende
`pro_settings.py` aus und mountet sie zusammen mit Ihrer `local_settings.py`,
sodass nichts manuell kopiert oder migriert werden muss.

## Vor dem Upgrade

Jedes Upgrade sollte auf die gleiche Weise beginnen. Das Überspringen dieser
Schritte ist die häufigste Ursache für fehlgeschlagene Upgrades.

1. **Lesen Sie die Release Notes** für jede Version zwischen Ihrem aktuellen
   Release und dem Zielrelease. Breaking Changes, neue Pflichtfelder und
   Migrationsvoraussetzungen werden dort aufgeführt. Die GitHub-Release-Seite
   jedes Tags verlinkt auf das Change Log.
2. **Prüfen Sie Ihre aktuelle Chart-Version.** Sie bildet die Ausgangsbasis
   für das Upgrade:

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **Sichern Sie Ihre Datenbank.** Chart-Upgrades können Django-Migrationen
   enthalten, die das Schema ändern. Erstellen Sie vor dem Fortfahren einen
   logischen Dump (oder einen Snapshot auf Storage-Ebene) der
   PostgreSQL-Instanz.
4. **Halten Sie Ihre Values-Dateien bereit.** Der Upgrade-Befehl muss
   dasselbe Plattform-Preset, Profil-Preset und dieselbe Kunden-Values-Datei
   übergeben, die bei der Installation verwendet wurden. Fehlende oder
   abweichende Values-Dateien führen zu überraschenden Diffs.
5. **Bestätigen Sie, dass Secret-Referenzen weiterhin existieren.** Wenn Sie
   mit `--set dojo.existingSecret=...` oder `--set license.existingSecret=...`
   installiert haben, überprüfen Sie, dass diese Kubernetes-Secrets im
   Namespace weiterhin vorhanden sind.
6. **Rendern Sie das Upgrade zunächst lokal**, um fehlende Felder, ungültige
   Werte oder Template-Fehler zu erkennen, bevor Sie den Cluster anfassen:

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

   `$CHART_REF` ist die OCI-Referenz (siehe unten) oder der Pfad zum
   extrahierten Chart.

> Legen Sie `NAMESPACE` einmal fest — jeder Befehl in diesem Leitfaden
> verwendet `$NAMESPACE`:
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **Standardverhalten der Netzwerkrichtlinie geändert.** NetworkPolicies
> werden jetzt durch `networkPolicy.profile` gesteuert, das standardmäßig
> auf `standard` gesetzt ist: Der gesamte Egress sowie Ingress zwischen den
> eigenen Pods dieses Releases ist erlaubt (externer Ingress bleibt weiterhin
> auf den Ingress-Pfad beschränkt). Dies ist permissiver als die bisherige,
> stets granulare Egress-Allowlist. Um das abgeriegelte Verhalten
> beizubehalten, setzen Sie `networkPolicy.profile: aggressive` und prüfen
> Sie die Ausnahmen (`nodeLocalDns`, `dnsSelectors`, `externalAPIs`) — siehe
> [Netzwerkrichtlinien](/get_started/pro/onprem/installing_on_kubernetes/#network-policies).

> **Anforderung an die Orchestrator-Datenbank.** Der Orchestrator (`ddorch`)
> verwendet eine zweite Datenbank namens `<main-db-name>-ddorch` und legt sie
> beim Start an, falls sie nicht existiert. Wenn Ihrer Anwendungsrolle
> `CREATEDB` fehlt, legen Sie sie vorab an
> (`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`), bevor Sie auf
> eine Chart-Version upgraden, die ddorch aktiviert — andernfalls schlägt der
> ddorch-Pod mit `permission denied to create database (SQLSTATE 42501)`
> fehl. Siehe
> [Pre-flight: Orchestrator-Datenbank (ddorch)](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).

> **Standardverhalten für Organization/Asset-Umbenennung.**
> `dojo.V3EnableOrganizationAssetRelabel` ist jetzt standardmäßig `null`
> (automatisch): Bei Neuinstallationen ist es **aktiviert** und bei Upgrades
> **deaktiviert**, sodass sich die UI-Umbenennung (Organization/Asset ersetzt
> ProductType/Product) bei einem bestehenden Release nie unerwartet
> einschaltet. Um sie für ein aktualisiertes Release zu aktivieren, setzen
> Sie explizit `dojo.V3EnableOrganizationAssetRelabel: true`; ein explizites
> `true`/`false` hat immer Vorrang vor dem automatischen Standardwert.

---

## Chart-Quelle: OCI-Registry

Der Chart wird als OCI-Artefakt in der DefectDojo GCP Artifact Registry
veröffentlicht:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Jedes Release wird mit der Chart-Version getaggt (zum Beispiel `2.57.2`).
Die Chart-Version stimmt mit der App-Version in `Chart.yaml` überein, sodass
der Tag, den Sie an `helm upgrade --version` übergeben, dieselbe
Versionsnummer ist, die auf der GitHub-Release-Seite angezeigt wird.

Verfügbare Chart-Versionen auflisten:

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **Warum OCI für Upgrades?** Die Presets (`presets/platforms/*.yaml`,
> `presets/profiles/*.yaml`) sind im Chart verpackt. Wenn Sie den Chart über
> seine OCI-URL referenzieren, werden automatisch die passenden
> Preset-Versionen für den Ziel-Chart abgerufen — kein erneuter
> Extraktionsschritt, keine veralteten Presets.

---

## Bei der Registry authentifizieren

Die Registry ist privat. Helm muss angemeldet sein, bevor der Chart
abgerufen werden kann. Verwenden Sie einen von DefectDojo Support
bereitgestellten GCP-Service-Account-Schlüssel oder ein kurzlebiges Access
Token.

**Option A — JSON-Schlüssel für Service-Account:**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**Option B — interaktiver gcloud-Login (für Personen mit Registry-Zugriff):**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

Access Tokens von `gcloud auth print-access-token` laufen nach einer Stunde
ab. Führen Sie `helm registry login` erneut aus, wenn während des Upgrades
ein `401 Unauthorized` angezeigt wird.

> **Air-Gapped- / Firewall-geschützte Umgebungen:** Wenn Ihre Cluster-Nodes
> `us-south1-docker.pkg.dev` erreichen können, Ihre Workstation aber nicht,
> verwenden Sie den unten beschriebenen Workflow mit dem extrahierten Zip.
> Der OCI-Workflow funktioniert nur, wenn der Host, auf dem `helm upgrade`
> läuft, die Registry erreichen kann.

---

## Upgrade über die OCI-Registry (empfohlen)

Richten Sie `helm upgrade` direkt auf die OCI-URL und fixieren Sie die
Chart-Version mit `--version`. Alle Values-Dateien, `--set`-Flags und
`--set-file`-Flags sind dieselben wie bei der ursprünglichen Installation.

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

> Die oben genannten Pfade für Plattform- und Profil-Presets lauten
> `presets/platforms/...` (ohne `$CHART/`-Präfix). Wenn Helm einen Chart von
> OCI abruft, befinden sich die Presets im abgerufenen Chart, aber `-f`
> verweist hier auf **lokale Kopien** dieser Dateien. Wenn Sie keine lokalen
> Kopien der Presets vorhalten, extrahieren Sie den Chart zunächst mit
> `helm pull oci://... --version $VERSION --untar` und referenzieren Sie sie
> aus dem extrahierten Verzeichnis — oder verwenden Sie den Workflow mit dem
> extrahierten Zip.

**Variante mit Inline-Secrets und Lizenzdatei:**

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

> Fixieren Sie immer `--version`. Ohne diese Angabe wird der Tag abgerufen,
> den die Registry im Moment des Befehls auflöst — nicht wiederholbar,
> nicht auditierbar. Fixieren Sie die Version, damit erneute Ausführungen,
> Rollbacks und Incident Response immer auf dasselbe Artefakt verweisen.

---

## Upgrade über extrahiertes Zip

Für Workstations, die die OCI-Registry nicht erreichen können, oder für
Kunden, die den Chart lieber als lokale Datei bereitstellen möchten,
funktioniert das gepackte Zip aus dem GitHub-Release beim Upgrade genauso
wie bei der Installation. Der einzige Unterschied zur Installation ist das
Befehlsverb (`helm upgrade` statt `helm install`).

1. Laden Sie `dojo-pro-helm-bundled-<version>.zip` (und die separate
   Signatur `.asc`) aus dem GitHub-Release herunter.
2. Verifizieren Sie die Signatur mit dem öffentlichen Schlüssel
   (`dojo-pro-release-signing.asc`) wie im Installationsleitfaden
   beschrieben.
3. Extrahieren Sie den Chart in einen **versionierten Pfad**, damit Presets
   nicht mit älteren Extraktionen kollidieren:

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. Führen Sie das Upgrade mit dem Pfad des extrahierten Charts aus —
   dieselben Values-Dateien und Flags wie bei Ihrer ursprünglichen
   Installation:

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

> **Bei jedem Upgrade neu extrahieren.** Preset-Dateien entwickeln sich
> zwischen Chart-Versionen weiter. Die Wiederverwendung einer alten
> Extraktion fixiert Ihr Upgrade stillschweigend auf die alten
> Preset-Standardwerte.

---

## Upgrade mit ArgoCD

Wenn DefectDojo Pro von ArgoCD verwaltet wird, ist das Upgrade eine einzige
Änderung an `targetRevision` in der Application-Spezifikation. Die
Plattform- und Profil-Presets sind im Chart versioniert und werden daher im
Gleichschritt aktualisiert.

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

Synchronisieren Sie die Application, nachdem Sie `targetRevision`
bearbeitet haben. ArgoCD ruft den neuen Chart aus der OCI-Registry ab und
gleicht ihn ab.

> ArgoCD benötigt eigene Zugangsdaten für die OCI-Registry. Konfigurieren
> Sie das Repo-Secret mit `type: helm` und `enableOCI: "true"`. Die genaue
> Struktur des Secrets finden Sie in der ArgoCD-Dokumentation
> [Helm OCI-Unterstützung](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support).

---

## Upgrade überprüfen

Nachdem `helm upgrade` zurückgekehrt ist (oder ArgoCD Synced / Healthy
meldet), bestätigen Sie, dass die neue Revision aktiv ist:

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

Rufen Sie die Login-Seite auf, um zu bestätigen, dass die UI erscheint und
sich der Admin-Benutzer anmelden kann. Für automatisierte Prüfungen liefert
der Endpunkt `/login/` den Status 200, wenn die Anwendung fehlerfrei läuft.

---

## Rollback

Helm führt die Release-Historie nach Revision. Wenn das Upgrade zu einer
Verschlechterung des Verhaltens führt, führen Sie ein Rollback zur
vorherigen Revision durch:

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **Datenbankmigrationen werden nicht zurückgerollt.** Ein Helm-Rollback
> stellt den Manifest-Zustand (Images, Konfigurationen, Secrets) wieder her,
> führt aber kein `migrate --revert` aus. Wenn das Upgrade eine
> Schemamigration angewendet hat, die Sie rückgängig machen müssen, stellen
> Sie das in [Vor dem Upgrade](#before-you-upgrade) erstellte Backup wieder
> her oder stimmen Sie eine manuelle Migrationsrücknahme mit dem DefectDojo
> Support ab, bevor Sie das Helm-Release zurückrollen.

ArgoCD-Nutzer können ein Rollback durchführen, indem sie die Änderung an
`targetRevision` in Git rückgängig machen (oder über `argocd app rollback`)
und anschließend synchronisieren.

---

## Fehlerbehebung

**`401 Unauthorized` beim Abrufen des Charts.**
Das Access Token ist abgelaufen. Führen Sie `helm registry login` mit einem
neuen `gcloud auth print-access-token` erneut aus.

**`Error: UPGRADE FAILED: cannot patch ... field is immutable`.**
Ein Selector oder ein anderes unveränderliches Feld ist abgewichen. Der
Chart fixiert stabile Selector-Labels, daher bedeutet dies meist eine
vorherige direkte Bearbeitung eines Deployments. Erfassen Sie den Diff,
löschen Sie die betroffene Ressource und führen Sie das Upgrade erneut aus,
damit Helm sie neu erstellt.

**`Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`.**
Helm 4 verwendet Server-Side Apply, das die Feldeigentümerschaft
nachverfolgt. Dieser Fehler bedeutet, dass ein anderer Manager —
`kubectl edit`, `kubectl scale` oder der HPA-Controller
(`kube-controller-manager`) — ein von Helm gerendertes Feld geändert hat, am
häufigsten `.spec.replicas`. Übernehmen Sie die Eigentümerschaft einmalig
zurück:

```bash
helm upgrade ... --force-conflicts
```

Chart-Versionen mit diesem Fix lassen `replicas` bei Deployments weg,
deren HPA aktiviert ist, sodass die HPA-Skalierung nicht mehr mit Upgrades
kollidiert. Wenn Sie ein Deployment manuell mit `kubectl` skaliert haben,
passen Sie stattdessen bevorzugt den entsprechenden Wert
`replicas`/`horizontalpodautoscaler` an, damit der Chart der Eigentümer
bleibt.

**`Error: UPGRADE FAILED: timed out waiting for the condition`.**
Pods haben innerhalb des `--timeout`-Fensters nicht den Status Ready
erreicht. Untersuchen Sie die verzögerte Workload:

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

Häufige Ursachen: fehlgeschlagene Image-Pulls (Registry-Authentifizierung),
noch laufende Schemamigration (erhöhen Sie `--timeout`) oder fehlschlagende
Readiness-Probes aufgrund eines falsch konfigurierten FQDN.

**Das Preset hat sich zwischen den Versionen geändert und meine
Values-Datei steht jetzt im Konflikt.**
Rendern Sie mit `helm template` erneut (siehe
[Vor dem Upgrade](#before-you-upgrade)) und gleichen Sie Ihre Overrides mit
den neuen Preset-Standardwerten ab, bevor Sie `helm upgrade` ausführen.

**`values don't meet the specifications of the schema ... got string, want boolean`.**
Ein An/Aus-Wert in Ihrem Override ist in Anführungszeichen gesetzt. Helm
behandelt `"false"` als nicht leeren String, und ein nicht leerer String ist
truthy, sodass die Funktion **eingeschaltet** wurde, obwohl Sie sie
ausschalten wollten. Das Schema lehnt die in Anführungszeichen gesetzte Form
jetzt ab, anstatt sie durchzulassen. Entfernen Sie die Anführungszeichen:

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

Die Fehlermeldung nennt den betroffenen Pfad. Ohne Anführungszeichen werden
`false`, `no` und `off` alle als echter Boolean interpretiert und
akzeptiert.
