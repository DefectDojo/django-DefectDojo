---
title: "Kubescape"
description: "Einrichtung des Kubescape Upstream-Connectors für DefectDojo"
weight: 85
audience: pro
---
Der Kubescape-Connector liest Kubernetes-Posture(Fehlkonfigurations)-Ergebnisse, die vom [Kubescape-Operator](https://kubescape.io/docs/install-operator/) erzeugt werden, direkt aus der Kubernetes-API des Clusters — ein ARMO-SaaS-Konto ist nicht erforderlich. Er liest die `WorkloadConfigurationScan`-Objekte, die von der im Cluster laufenden Storage-Aggregated-API des Operators bereitgestellt werden (`spdx.softwarecomposition.kubescape.io/v1beta1`). Jeder Kubernetes-**Namespace** mit Posture-Ergebnissen wird einem Eintrag (Produkt) zugeordnet; jede fehlgeschlagene Kontrolle auf einer Workload wird zu einem Befund.

#### Voraussetzungen

- Der Kubescape-Operator muss im Zielcluster mit aktiviertem Konfigurations-Scanning installiert sein (siehe [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Bestätigen Sie mit `kubectl get workloadconfigurationscans -A`, dass Ergebnisse vorhanden sind.
- Eine **kubeconfig**, die Lesezugriff auf die API-Gruppe `spdx.softwarecomposition.kubescape.io` gewährt (list/get auf `workloadconfigurationscans`) für den Zielcluster.

#### Connector-Zuordnungen

1. Geben Sie die API-Server-URL des Clusters (oder eine sprechende Cluster-Kennung) in das Feld **Location** ein.
2. Fügen Sie die **kubeconfig** für den Zielcluster in das Feld `kubeconfig` ein. Setzen Sie optional `kube_context`, um einen Kontext darin auszuwählen, und `cluster_name`, um die ermittelten Produkte zu beschriften.
3. Jeder Namespace mit Posture-Ergebnissen wird als Eintrag ermittelt; ordnen Sie die gewünschten den DefectDojo-Produkten zu.

Befunde werden pro fehlgeschlagener Kontrolle abgeleitet: Der Kontrollname und die Workload identifizieren den Befund, der Schweregrad stammt aus dem Score-Faktor der Kontrolle, die Kontroll-ID wird zur Schwachstellen-ID, und jeder Befund verlinkt auf seine Kontrollreferenz unter `https://hub.armosec.io/docs/`.
