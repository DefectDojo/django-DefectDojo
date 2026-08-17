---
title: DefectDojo Pro auf OpenShift bereitstellen
description: 'Was bei der Bereitstellung von selbst gehostetem DefectDojo Pro auf
  OpenShift zu beachten ist: Security Context Constraints, Routes und ReadWriteMany-Speicher'
draft: false
weight: 8
audience: pro
---

DefectDojo Pro läuft auf OpenShift 4.x, einschließlich OpenShift Container Platform, ROSA und OKD.

Diese Seite ergänzt die Installationsanleitung, die mit Ihrer DefectDojo-Pro-Lizenz geliefert wird. Diese Anleitung enthält das vollständige Verfahren, einschließlich eines eigenen Abschnitts zu OpenShift. Diese Seite beschreibt, was bei OpenShift anders ist, damit Sie wissen, was Sie vor dem Start bereithalten müssen und was Sie von den plattformspezifischen Einstellungen erwarten können.

Mit Ihren Lizenzmaterialien wird ein OpenShift-Bootstrap-Skript bereitgestellt. Es installiert auf einem vorhandenen Cluster und übernimmt den größten Teil dessen, was auf dieser Seite beschrieben wird, einschließlich Speicher, des Werts `fsGroup`, der Route und der Installation selbst. Es ist idempotent, sodass ein erneuter Lauf die bereits erstellten Ressourcen wiederverwendet, und es unterstützt einen Trockenlauf, der ausgibt, was es tun würde, ohne etwas zu ändern. Der Rest dieser Seite gilt unabhängig davon, ob Sie dieses Skript verwenden oder die Installation selbst durchführen.

## Security Context Constraints

DefectDojo Pro läuft unter der Standard-SCC `restricted-v2`. Sie müssen dem Service-Account keine erweiterte SCC wie `anyuid`, `privileged` oder eine andere gewähren.

Wenn DefectDojo Pro für OpenShift konfiguriert ist, läuft es durchgehend mit nicht privilegierten Security Contexts. Container laufen ohne Privilegien, können ihre Rechte nicht ausweiten und geben alle Capabilities ab. Die Benutzer-ID wird von OpenShift aus dem für Ihren Namespace zugewiesenen Bereich vergeben, statt auf eine feste UID festgelegt zu sein, die von der SCC abgelehnt würde.

Wenn Pods aufgrund einer fehlgeschlagenen SCC-Validierung abgelehnt werden, liegt die übliche Ursache darin, dass die Bereitstellung nicht für OpenShift konfiguriert wurde – nicht darin, dass eine Constraint gewährt werden müsste.

## Speicher muss ReadWriteMany sein

Die Django- und Celery-Worker-Pods lesen und schreiben dieselben Mediendateien, also die hochgeladenen Scans, Screenshots und generierten Berichte. Sie benötigen ein gemeinsam genutztes Volume, weshalb ReadWriteOnce-Speicher für eine Multi-Node-Bereitstellung nicht ausreicht.

Auf OpenShift ist der Standard ein PersistentVolumeClaim gegenüber der Standard-StorageClass des Clusters. Das funktioniert, wenn die Standardklasse ReadWriteMany bereitstellt, was bei Clustern mit OpenShift Data Foundation oder NFS im Hintergrund typisch ist. Für Multi-Node-Bereitstellungen, bei denen die Standardklasse ReadWriteOnce ist, konfigurieren Sie stattdessen NFS-basierten Speicher.

### fsGroup bei NFS-basiertem Speicher

OpenShift beschränkt `fsGroup` auf den dem Namespace zugewiesenen Bereich. Wenn Sie NFS- oder EFS-Speicher verwenden, müssen Sie einen Wert aus diesem Bereich angeben, da das Volume-Mount sonst mit einem Berechtigungsfehler fehlschlägt.

Lesen Sie den Anfang des Bereichs aus der Namespace-Annotation aus und verwenden Sie ihn als Ihren `fsGroup`:

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

Die Annotation enthält einen Bereich, der als Startwert und Länge angegeben ist. Verwenden Sie den Startwert. Dies ist nur für NFS- und EFS-Speicher erforderlich, nicht für den Standardpfad über PersistentVolumeClaim.

## Routes, TLS und Cookies

Auf OpenShift wird DefectDojo Pro über eine Route statt über ein Ingress bereitgestellt, mit TLS-Terminierung am Edge und einer Weiterleitung von HTTP.

Auf ROSA werden Route-Hostnamen als `<release-name>-<namespace>.apps.<cluster-domain>` generiert. Ein `dojopro`-Release im Namespace `dojopro` erhält also `dojopro-dojopro.apps.<cluster-domain>`. Die Apps-Domain des Clusters erhalten Sie mit:

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

Ein Hostname unter der Apps-Domain des Clusters wird durch das Standard-Wildcard-Zertifikat abgedeckt und benötigt keine Zertifikatskonfiguration. Für jeden anderen Hostnamen stellen Sie ein eigenes Zertifikat bereit und fügen einen CNAME auf den Route-Hostnamen hinzu.

Setzen Sie `dojo.secureCookies` auf OpenShift auf `false`. Bei einer Route mit Edge-Terminierung endet TLS am Router, und die Verbindung vom Router zum Pod erfolgt über einfaches HTTP, sodass als „secure“ markierte Cookies nie zurückgesendet werden und die Anmeldung fehlschlägt. Dies ist erforderlich und nicht optional, sobald die Route TLS am Edge terminiert.

## Ressourcenprofile

Es stehen drei Ressourcenprofile zur Verfügung, von denen Sie eines bei der Installation auswählen. `minimal` ist für Entwicklung, CI und Tests gedacht. `standard` ist für den Produktionsbetrieb bei moderater Last. `performance` ist für Produktionsbetrieb mit hoher Last und aktiviert Autoscaling.

Legen Sie Ihre Dimensionierung über das Profil fest statt durch das Überschreiben einzelner Werte, damit Ihre eigene Konfigurationsdatei nicht damit in Konflikt gerät.

## Bevor Sie beginnen

Ein OpenShift-4.x-Cluster, bei dem Sie angemeldet sind, mit lokal verfügbaren `oc`, `helm`, `openssl` und `jq`.

Ein Namespace sowie dessen Supplemental-Groups-Annotationswert, falls Sie NFS- oder EFS-Speicher verwenden.

Eine Standard-StorageClass, die ReadWriteMany bereitstellt, oder die Details eines NFS-Servers.

PostgreSQL 16 für alles, was über eine Evaluierung hinausgeht. Für die Entwicklung steht ein eingebettetes PostgreSQL zur Verfügung; wechseln Sie jedoch vor dem Produktionsbetrieb zu einer externen, verwalteten Datenbank.

Ihre DefectDojo-Pro-Lizenzdatei.

Der von Ihnen vorgesehene Route-Hostname.

## Ausgehender Netzwerkzugriff

Erlauben Sie in einem Cluster mit Egress-Beschränkungen ausgehendes HTTPS über Port 443 zur Container-Registry, die die DefectDojo-Pro-Images hostet. Der Hostname der Registry befindet sich in der mit Ihrer Lizenz gelieferten Installationsanleitung. Registry-Endpunkte liegen hinter Load Balancern, und ihre Adressen ändern sich, weshalb Sie den Hostnamen statt einer festen Adresse freigeben sollten.

Der Cluster muss außerdem Ihre Datenbank über den PostgreSQL-Port erreichen können.

Die Exploitability-Anreicherung ist optional und benötigt zwei weitere Ziele über HTTPS auf Port 443. EPSS-Werte stammen von `api.first.org`, und CISA-KEV-Daten stammen von `www.cisa.gov`. Beide werden über Content Delivery Networks ausgeliefert, deren Adressen sich ändern, weshalb Sie die Hostnamen freigeben sollten. Ohne sie läuft DefectDojo normal, und Findings werden nicht mit EPSS- oder KEV-Daten angereichert.

Wenn ausgehender Datenverkehr über einen Proxy statt direkt läuft, siehe [Running DefectDojo Behind a Forward HTTPS Proxy](/onprem_deployment/forward_proxy/).

## Der Initializer-Job muss zuerst abgeschlossen sein

Bei der Installation wird ein Kubernetes-Job ausgeführt, der Migrationen anwendet, den Admin-Benutzer erstellt und Initialdaten lädt. Dies dauert etwa fünfzehn Minuten. Bis er abgeschlossen ist, existiert der Admin-Benutzer nicht, und Sie können sich nicht anmelden, obwohl die Route bereits antwortet.

Beobachten Sie ihn:

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

Der Job ist abgeschlossen, wenn `oc get job` `1/1` completions meldet.

Die übrigen Pods warten über einen Init-Container auf den Initializer. Sobald die Datenbank initialisiert wurde, können Sie `dojo.skipInitContainer` auf `true` setzen, um dieses Warten bei nachfolgenden Upgrades zu überspringen.

## Überprüfen

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

Öffnen Sie anschließend den Route-Hostnamen und melden Sie sich an.

## Fehlerbehebung

### Pods werden durch Security Context Constraints abgelehnt

Die Bereitstellung wurde höchstwahrscheinlich nicht für OpenShift konfiguriert und ist daher auf Standardwerte zurückgefallen, die eine Benutzer-ID festlegen, die die SCC nicht zulässt. Das Gewähren von `anyuid` oder `privileged` ist nicht die Lösung und auch nicht erforderlich.

### Anmeldung leitet zurück zur Anmeldeseite

`dojo.secureCookies` ist hinter einer Route mit Edge-Terminierung auf `true` gesetzt. Setzen Sie es auf `false` und führen Sie ein Upgrade durch.

### Berechtigungsfehler beim Volume-Mount auf NFS

Der `fsGroup` liegt außerhalb des für den Namespace zulässigen Bereichs. Lesen Sie die Supplemental-Groups-Annotation aus und verwenden Sie den Anfang des Bereichs.

### Multi-Attach-Fehler oder Pods bleiben in ContainerCreating hängen

Das Volume ist ReadWriteOnce, und mehr als ein Pod versucht, es zu mounten. Prüfen Sie den Claim und die dahinterliegende Klasse:

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

Wechseln Sie zu einer ReadWriteMany-Klasse oder zu NFS-basiertem Speicher.

### Zertifikatswarnungen im Browser

Das Standard-TLS der Route verwendet das Wildcard-Zertifikat des Clusters, das nur Namen unter der Apps-Domain des Clusters abdeckt. Stellen Sie für jeden anderen Hostnamen ein eigenes Zertifikat bereit.

### Logs auslesen

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

Für ausführlichere Ausgaben akzeptieren sowohl `config.logLevel` als auch `celery.logLevel` den Wert `DEBUG`.

## Upgrade durchführen

Upgrades folgen dem Standardverfahren. Siehe [Upgrading DefectDojo Pro (On-Premise)](/get_started/pro/onprem/upgrading/).

## Fragen oder Support

Wenden Sie sich bei Fragen zu einer OpenShift-Bereitstellung an Ihren Account-Repräsentanten oder an [support@defectdojo.com](mailto:support@defectdojo.com).
