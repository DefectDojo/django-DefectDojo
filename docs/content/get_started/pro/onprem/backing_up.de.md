---
title: Sichern eines selbstgehosteten Deployments
description: Die vier Dinge, die gesichert werden müssen, wo sie sich bei Compose-
  und Kubernetes-Deployments jeweils befinden, und wie Sie bestätigen, dass ein Backup
  tatsächlich wiederhergestellt werden kann
draft: false
weight: 12
audience: pro
---

Ein Deployment ist mehr als seine Datenbank. Ein Backup, das nur die Datenbank erfasst, stellt ein System wieder her, das zwar läuft, dem aber hochgeladene Dateien fehlen und das die für Ihre anderen Tools gespeicherten Anmeldedaten nicht entschlüsseln kann. Diese Seite behandelt, was gesichert werden muss, wo sich die einzelnen Teile befinden und wie Sie bestätigen, dass das Ergebnis wiederherstellbar ist.

## Die vier zu sichernden Dinge

Die Datenbank enthält Ihre Organisationen, Assets, Engagements, Tests, Befunde, Benutzer und Konfiguration.

Hochgeladene Dateien befinden sich außerhalb der Datenbank. Screenshots, Bedrohungsmodelle, Risikoakzeptanz-Dokumente und ähnliche Anhänge liegen auf einem Dateisystem, und die Datenbank enthält lediglich die Pfade dazu.

Die Deployment-Konfiguration sorgt dafür, dass die Anwendung auf dieselbe Weise wieder hochfährt, einschließlich Ihrer eigenen Customizations und TLS-Zertifikate.

Die Verschlüsselungsschlüssel sind der Teil, der am häufigsten übersehen wird. Der Credential Encryption Key macht die gespeicherten Anmeldedaten für Ihre verbundenen Tools lesbar. Stellen Sie eine Datenbank ohne diesen Schlüssel wieder her, bleiben die Anmeldedaten zwar intakt, sind aber nicht entschlüsselbar, was bedeutet, dass jede Integration von Hand neu eingerichtet werden muss.

## Die Datenbank

Die meisten selbstgehosteten Deployments verweisen auf einen verwalteten PostgreSQL-Dienst, was der Standardeinstellung des Charts entspricht und die empfohlene Einrichtung ist. Verwenden Sie in diesem Fall die automatisierten Backups und die Point-in-Time-Recovery des Anbieters, anstatt eine eigene Lösung zu bauen. Zwei Dinge sollten Sie überprüfen, statt sie anzunehmen: dass automatisierte Backups auf der Instanz tatsächlich aktiviert sind, da eine verwaltete Datenbank mit abgeschalteten Backups keine besitzt, und dass das Aufbewahrungsfenster den Anforderungen Ihrer Organisation entspricht.

Wenn Sie PostgreSQL selbst betreiben, erstellen Sie einen komprimierten Dump im Custom-Format:

```bash
pg_dump -h <db_host> -U <db_user> -Fc <db_name> > defectdojo-$(date +%F).dump
```

Stellen Sie ihn mit `pg_restore` wieder her, wobei Sie `--no-owner` und `--no-privileges` verwenden, falls das Ziel andere Rollen als die Quelle hat:

```bash
pg_restore -v --no-owner --no-privileges -h <db_host> -U <db_user> -d <db_name> defectdojo-<date>.dump
```

Erstellen Sie den Dump nach einem festen Zeitplan, speichern Sie ihn getrennt von der Maschine, die ihn erzeugt hat, und behalten Sie genügend Generationen, um ein Problem zu überstehen, das Ihnen nicht sofort auffällt.

## Hochgeladene Dateien

Bei einem Docker-Compose-Deployment befinden sich hochgeladene Dateien im Verzeichnis `media` innerhalb Ihres Deployment-Verzeichnisses auf dem Host. Sichern Sie diesen Pfad mit Ihrem üblichen Dateisystem-Backup. Wenn Sie ihn auf einen separaten Speicher verschoben haben, sichern Sie dieses Dateisystem und nicht den Mount-Punkt.

Unter Kubernetes wird das media-Volume entsprechend dem von Ihnen konfigurierten Storage-Backend bereitgestellt, und wo die Daten physisch liegen, bestimmt, wie Sie sie schützen:

| Storage-Backend | Wo die Daten liegen | Wie Sie sie schützen |
| --- | --- | --- |
| `efs` | Ein Amazon-EFS-Dateisystem | AWS Backup |
| `filestore` | Eine Google-Filestore-Instanz | Filestore-Backups |
| `gcsfuse` | Ein Cloud-Storage-Bucket | Bucket-Versionierung oder eine geplante Kopie in einen anderen Bucket |
| `nfs` | Ihr NFS-Server | Was auch immer diesen Server schützt |
| `pvc` | Ein Volume aus Ihrer Storage-Class | Ein CSI-Volume-Snapshot, sofern Ihr Treiber dies unterstützt |

Das Chart stellt das Volume bereit, schützt aber nicht dessen Inhalt. Es enthält keinen eingebauten Snapshot-Zeitplan, das Backup muss also von der Plattform oder von Ihrem eigenen Tooling kommen.

## Konfiguration und Schlüssel

Sichern Sie bei Compose Ihr Verzeichnis `customizations`, Ihr Verzeichnis `certs` sowie die gespeicherte Konfiguration und die Umgebungswerte der CLI. `config print` und `environment print` zeigen Ihnen, was jeweils gesetzt ist.

Sichern Sie bei Kubernetes Ihre Values-Dateien und den Inhalt der Secrets, auf die Ihr Release verweist.

Bewahren Sie in beiden Fällen den Credential Encryption Key und den Secret Key an einem dauerhaften, getrennten Ort auf, in einem Secret-Manager und nicht zusammen mit dem Backup. Wer sowohl die Datenbank als auch den Credential Key besitzt, kann die Anmeldedaten für jedes von Ihnen verbundene Tool lesen. Beide sollten daher nicht gemeinsam aufbewahrt werden.

## Was kein Backup ist

Das Chart annotiert seine Persistent Volume Claims so, dass sie ein `helm uninstall` überstehen, was standardmäßig aktiviert ist. Das ist ein Schutz vor einer versehentlichen Deinstallation, kein Backup. Es hilft weder bei Beschädigungen noch bei einer Löschung innerhalb der Anwendung noch bei einem missglückten Upgrade, denn in jedem dieser Fälle bleibt das Volume erhalten und der Schaden befindet sich darauf.

Snapshots, die nur im selben Konto oder Projekt wie das Deployment aufbewahrt werden, sind ähnlich schwächer, als sie erscheinen. Was auch immer das Deployment löschen kann, kann in der Regel auch diese löschen.

## Bestätigen, dass ein Backup wiederherstellbar ist

Ein Backup, das noch nie wiederhergestellt wurde, ist nur eine Annahme. Testen Sie es in einer Scratch-Umgebung statt direkt über die Produktivumgebung, und prüfen Sie Folgendes:

1. Melden Sie sich an und bestätigen Sie, dass Ihre Organisationen, Assets, Engagements, Tests und Befunde in der erwarteten Anzahl vorhanden sind.
2. Öffnen Sie einen Befund mit einem Anhang und laden Sie diesen herunter. Dies beweist, dass die Wiederherstellung der Medien funktioniert hat, da die Datenbank allein den Anhang zwar auflisten, ihn aber nicht bereitstellen würde.
3. Öffnen Sie eine konfigurierte Tool-Verbindung und bestätigen Sie, dass deren Anmeldedaten intakt sind. Dies beweist, dass Sie den Credential Encryption Key korrekt wiederhergestellt haben, und ist die Prüfung, die eine Lücke am ehesten aufdeckt.
4. Bestätigen Sie, dass Benutzer und Gruppen übernommen wurden. Authentifizierungseinstellungen wie SSO müssen für eine andere Umgebung meist neu konfiguriert werden. Betrachten Sie Abweichungen dort daher als erwartet und nicht als fehlgeschlagene Wiederherstellung.

Führen Sie diese Übung nach einem festen Zeitplan durch und nicht nur dann, wenn Sie sie benötigen. Eine Wiederherstellung zum ersten Mal während eines Vorfalls durchzuführen ist der Punkt, an dem Backup-Pläne meist scheitern.

## Fragen oder Support

Wenden Sie sich für Unterstützung bei der Planung von Backups für Ihr Deployment, oder wenn eine Wiederherstellung nicht wie erwartet hochfährt, an [support@defectdojo.com](mailto:support@defectdojo.com).
