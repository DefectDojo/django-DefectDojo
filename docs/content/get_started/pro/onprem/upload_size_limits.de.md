---
title: Upload-Größenlimits für große Scan-Dateien
description: Warum das Hochladen einer großen Scan-Datei fehlschlägt und welches Limit
  in Kubernetes- und Docker-Compose-Deployments angehoben werden muss
draft: false
weight: 10
audience: pro
---

Eine große Scan-Datei kann an mehr als einem Limit an unterschiedlichen Stellen im Anfragepfad abgelehnt werden, und der angezeigte Fehler verrät Ihnen, welches Limit Sie erreicht haben. Diese Seite beschreibt, wo sich diese Limits befinden und wie Sie sie in einem selbst gehosteten Deployment anheben.

## Welches Limit betrifft mich

| Was Sie sehen | Woher es kommt |
| --- | --- |
| Ein einfacher `413 Request Entity Too Large`, ungestylt, ohne umgebende DefectDojo-Seite | Der Ingress-Controller hat die Anfrage abgelehnt, bevor sie die Anwendung erreicht hat |
| `Report file is too large. Maximum supported size is N MB` | Das Anwendungslimit, gemeldet von DefectDojo selbst |
| Der Upload läuft eine Weile und schlägt dann fehl, anstatt sofort abgelehnt zu werden | Ein Timeout statt eines Größenlimits |

Arbeiten Sie sich von außen nach innen vor. Es bringt nichts, das Anwendungslimit zu erhöhen, wenn der Ingress-Controller die Anfrage bereits vorher ablehnt.

## Das Anwendungslimit

DefectDojo erzwingt eine eigene maximale Scan-Dateigröße und lehnt alles Größere mit einer Meldung ab, die das aktuelle Limit nennt. Der Standardwert beträgt 100 MB.

Legen Sie es im Helm-Chart in Ihren Values fest:

```yaml
dojo:
  scanMaxFileSize: 100
```

Setzen Sie für Docker-Compose-Deployments stattdessen `DD_SCAN_FILE_MAX_SIZE`, in Megabyte.

## Das Ingress-Limit

Dies ist das Limit, das einen nackten `413` ohne DefectDojo-Styling erzeugt, weil die Anfrage die Anwendung nie erreicht.

Der Chart legt eine Obergrenze für den Request-Body am Ingress fest, standardmäßig 2400 MB:

```yaml
django:
  ingress:
    maxBodySize: "2400m"
```

Dieser Wert wird als Annotation `nginx.ingress.kubernetes.io/proxy-body-size` ausgegeben. Er wird auf jeder Plattform ausgegeben und nicht nur bei generischem Kubernetes, da der nginx-Ingress-Controller häufig vor einer verwalteten Plattform eingesetzt wird. Wird er auf einen leeren String gesetzt, entfällt die Annotation; dafür ist `django.ingress.platformAnnotations.enabled` erforderlich, das standardmäßig aktiviert ist.

Andere Controller als nginx ignorieren diese Annotation. Bei diesen erhöhen Sie das Limit stattdessen über den eigenen Mechanismus des Controllers:

| Standard-Controller der Plattform | Wo sich das Limit befindet |
| --- | --- |
| EKS mit dem AWS Load Balancer Controller | ALB-Konfiguration |
| GKE mit dem GCE-Ingress-Controller | Load-Balancer-Konfiguration |
| AKS mit Application Gateway | Das Request-Body-Limit des Application Gateway |
| OpenShift Route | HAProxy `tuningOptions` auf dem Router |

### Timeouts, wenn nginx einer verwalteten Plattform vorgeschaltet ist

Der Chart gibt großzügige nginx-Proxy-Timeouts aus, 1800 Sekunden für Read, Send und Connect, zusammen mit deaktiviertem Proxy-Buffering. Diese Annotationen werden nur ausgegeben, wenn die Plattform generisches Kubernetes ist. Bei EKS, GKE, AKS und OpenShift gibt der Chart stattdessen die eigenen Annotationen dieser Plattform aus, da diese vom jeweiligen Standard-Controller gelesen werden.

Das ist relevant, wenn Sie den nginx-Ingress-Controller auf einer dieser Plattformen einsetzen. Sie erhalten die Body-Size-Annotation, da diese überall ausgegeben wird, aber nicht die Timeouts. Ein großer Upload kann dann die Größenprüfung bestehen und trotzdem mittendrin durch das Standard-Timeout des Controllers abgebrochen werden — daher stammt die dritte Zeile der obigen Tabelle. Legen Sie die Timeouts selbst fest:

```yaml
django:
  ingress:
    annotations:
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
```

## Das Limit der Import-Route

Kubernetes-Deployments führen Scan-Importe über dedizierte Pods aus, und das nginx vor den Import-Routen hat eine eigene Obergrenze für die Body-Size. Diese wird abgeleitet statt fest vorgegeben:

```yaml
django:
  uwsgiImport:
    maxBodySizeMb: null
```

Wird es auf `null` belassen, wird es als `dojo.scanMaxFileSize` plus 5 MB berechnet; dieser Puffer deckt den Overhead der Multipart-Kodierung ab. Eine Erhöhung des Anwendungslimits erhöht daher auch dieses Limit mit, und die meisten Deployments müssen es nie manuell setzen. Setzen Sie nur dann eine Ganzzahl, wenn Sie den abgeleiteten Wert überschreiben möchten.

## Docker-Compose-Deployments

Compose-Deployments haben keinen Ingress-Controller, daher gilt das Ingress-Limit nicht. Das im Deployment enthaltene nginx begrenzt Request-Bodys auf 800 MB, was die praktische Obergrenze darstellt, und das Anwendungslimit gilt zusätzlich dazu, wie überall sonst auch.

Um die nginx-Obergrenze zu erhöhen, muss eine Datei geändert werden, die mit dem Deployment ausgeliefert wird; solche Dateien werden bei einem Upgrade ersetzt und nicht wie Ihr Customizations-Verzeichnis erhalten. Wenden Sie sich vor der Änderung an den Support, damit die Änderung beim nächsten Upgrade nicht verloren geht.

## Fragen oder Support

Wenn Uploads auch nach dem Anheben des zu Ihrem Symptom passenden Limits weiterhin fehlschlagen, sammeln Sie die von Ihrem Client empfangene Antwort sowie die nginx- oder Controller-Logs zu diesem Versuch und wenden Sie sich dann an [support@defectdojo.com](mailto:support@defectdojo.com).
