---
title: Migration von Open Source zu selbst gehostetem DefectDojo Pro
description: Übertragen Sie Ihre Open-Source-DefectDojo-Datenbank und Mediendateien
  in ein selbst gehostetes DefectDojo-Pro-Deployment
draft: false
weight: 6
audience: pro
---

Diese Seite beschreibt, wie Sie die Daten aus einer Open-Source-DefectDojo-Instanz in ein selbst gehostetes DefectDojo-Pro-Deployment übertragen.

Die Beispiele verwenden Amazon Web Services, entweder mit Docker Compose auf EC2 oder Kubernetes auf EKS, und die Datenbank auf Amazon RDS für PostgreSQL. Gegen diese Kombination wurde das Verfahren validiert. Dieselbe Abfolge gilt für andere Anbieter, die verwaltetes PostgreSQL und vergleichbare Rechenleistung anbieten, sowie für On-Premise-Hardware, wobei die anbieterspezifischen Befehle entsprechend anzupassen sind.

Da Sie das Deployment selbst hosten, verbleiben Ihre Daten während der gesamten Migration in Ihrer eigenen Umgebung. Sie führen den Export und die Wiederherstellung selbst durch, und der DefectDojo-Support kann Sie bei jedem Schritt unterstützen. Wenn Ihre DefectDojo-Pro-Instanz von DefectDojo cloud-gehostet wird, statt selbst gehostet zu sein, wenden Sie sich stattdessen an [support@defectdojo.com](mailto:support@defectdojo.com), da in diesem Fall das DefectDojo-Team die Wiederherstellung für Sie durchführt.

Im Überblick: Sie exportieren die Datenbank und die Mediendateien aus der Open-Source-Instanz, stellen sie in der Datenbank und dem Speicher wieder her, den Ihr Pro-Deployment verwendet, richten Pro auf die wiederhergestellte Datenbank aus und validieren anschließend das Ergebnis.

## Bevor Sie beginnen

Bestätigen Sie Folgendes, bevor Sie irgendetwas exportieren.

Ihre Datenbank-Engine. DefectDojo unterstützt PostgreSQL. Die Unterstützung für MySQL wurde als veraltet markiert und dann [in 2.37.0 entfernt](/releases/os_upgrading/2.37/), sodass eine ältere Instanz, die noch auf MySQL läuft, vor der Migration auf PostgreSQL umgestellt werden muss. Wenden Sie sich an den Support, falls dies auf Sie zutrifft.

Wo Ihre Datenbank läuft. Dies kann ein Container aus dem Standard-Docker-Compose-Setup sein oder ein separater Dienst auf demselben Host, auf einer anderen VM oder auf einem verwalteten Dienst wie Amazon RDS oder Cloud SQL. Der Export-Befehl unterscheidet sich je nachdem, um welchen der beiden Fälle es sich handelt.

Ihre Open-Source-Version. Sie finden diese in der Fußzeile der UI oder anhand Ihrer Deployment-Tags und Image-Versionen. Alle 2.x-Releases können mit diesem Verfahren migriert werden. Wenn Sie 3.0.0, 3.0.1, 3.0.2 oder 3.0.100 verwenden, aktualisieren Sie zunächst auf [3.0.200](/releases/os_upgrading/3.0.200/) oder höher. Lesen Sie die [Hinweise zum Upgrade](/releases/os_upgrading/upgrading_guide/) für jede Version zwischen Ihrer aktuellen Version und der Zielversion.

Versionsabgleich. Ihre Open-Source-Version sollte der DefectDojo-Pro-Version, zu der Sie migrieren, entsprechen oder ihr so nah wie möglich kommen. Beim ersten Start führt Pro die Datenbankmigrationen aus, die das Schema auf den eigenen Versionsstand bringen, sodass eine große Versionslücke das Risiko einer langen oder fehlgeschlagenen Migration erhöht. Gleichen Sie die Versionen an, bevor Sie den Dump erstellen.

Ihre Zieldatenbank. Stellen Sie eine derzeit unterstützte PostgreSQL-Hauptversion bereit, 16 oder neuer, und niemals älter als die Version, auf der Ihre Open-Source-Instanz läuft, da ein Dump nicht in eine ältere Hauptversion wiederhergestellt werden kann. Platzieren Sie die RDS-Instanz auf AWS in derselben VPC wie Ihre Pro-Rechenleistung und lassen Sie eingehenden Datenverkehr auf Port 5432 vom Host aus zu, von dem aus Sie die Wiederherstellung durchführen.

Ihr Wiederherstellungs-Host. Sie benötigen einen Rechner im selben Netzwerk wie die Datenbank, auf dem die PostgreSQL-Client-Tools `pg_restore` und `psql` installiert sind. Verwenden Sie auf AWS eine EC2-Instanz in derselben VPC, idealerweise in derselben Availability Zone wie die RDS-Instanz.

Freier Speicherplatz. Der Quellserver benötigt Platz für den Datenbank-Dump und das komprimierte Medienarchiv, bevor Sie diese verschieben.

## Schritt 1: Datenbank exportieren

Die Standard-Docker-Compose-Konfiguration verwendet `defectdojo` sowohl als Datenbank-Benutzernamen als auch als Datenbanknamen. Diese können überschrieben werden, prüfen Sie daher den Wert von `DD_DATABASE_URL` in Ihrer `docker-compose.yml`- oder `.env`-Datei. Die Standard-Verbindungszeichenfolge lautet:

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

Ersetzen Sie in den folgenden Befehlen `<db_username>`, `<database_name>` und `<postgres_container_name>` durch Ihre eigenen Werte. Den Container-Namen finden Sie mit `docker ps`.

Ein komprimierter Dump im Custom-Format wird empfohlen. `pg_restore` kann ihn direkt laden, und er vermeidet die meisten Eigentümer- und Rollenprobleme, die bei einer Wiederherstellung in eine verwaltete Datenbank auftreten können.

Für ein containerisiertes PostgreSQL, dem Standard-Docker-Compose-Setup:

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Wenn die Datenbank ein Passwort erfordert, übergeben Sie es über die Umgebung:

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Für ein externes oder entferntes PostgreSQL, etwa eine separate VM, Amazon RDS oder Cloud SQL:

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Ein Klartext-SQL-Dump, den Sie durch Weglassen von `-Fc` erhalten, funktioniert ebenfalls. Er enthält häufig `CREATE ROLE`-, `ALTER ROLE`- und `CREATE DATABASE`-Anweisungen, die eine verwaltete Datenbank ablehnt, beachten Sie also in diesem Fall den Hinweis in Schritt 4.

## Schritt 2: Mediendateien exportieren

DefectDojo speichert hochgeladene Artefakte wie Screenshots, Threat Models und Risikoakzeptanz-Dokumente in einem Medienverzeichnis. Scan-Dateien, die für Import und Reimport verwendet werden, werden von Open-Source-DefectDojo nicht auf der Festplatte gespeichert, da sie nach dem Parsen verworfen werden. Das Medienverzeichnis enthält daher nur von Benutzern hochgeladene Artefakte.

Der Speicherort des Verzeichnisses hängt davon ab, wie Sie Ihr Deployment durchgeführt haben:

| Deployment method | Typical media path |
| --- | --- |
| Docker Compose | Benanntes Volume `defectdojo_media`, eingehängt unter `/app/media` |
| Bare metal | `/opt/dojo/media`, oder der in `DD_MEDIA_ROOT` festgelegte Pfad |
| Kubernetes | Persistentes Volume, eingehängt unter `/app/media` |

Komprimieren Sie das Verzeichnis in ein einzelnes Archiv. Aus einem benannten Volume:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

Aus einem Pfad auf der Festplatte:

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## Schritt 3: Dateien benennen

Fügen Sie Ihre Open-Source-Version in beide Dateinamen ein, damit bei der Wiederherstellung eindeutig ist, welche Version verwendet wird. Für eine Instanz, auf der 2.38.1 läuft:

| File | Renamed to |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

Übertragen Sie beide Dateien auf Ihren Wiederherstellungs-Host. Sie können sie direkt mit einem Tool wie `scp` kopieren, oder sie in einem privaten Objektspeicher in Ihrem eigenen Konto bereitstellen und auf den Wiederherstellungs-Host herunterladen. Auf AWS bedeutet das einen privaten S3-Bucket und `aws s3 cp`. So oder so verbleiben die Daten innerhalb Ihrer eigenen Umgebung.

## Schritt 4: Datenbank wiederherstellen

Führen Sie die Wiederherstellung von Ihrem Wiederherstellungs-Host aus, ausgerichtet auf den Datenbank-Endpunkt. Verwaltete PostgreSQL-Dienste unterscheiden sich darin, was sie hierbei unterstützen. Amazon RDS bietet keinen einstufigen Import einer Dump-Datei aus einem Bucket, daher ist ein clientseitiges `pg_restore` der unterstützte Weg.

1. Erstellen Sie die Datenbank und die Anwendungsrolle. Verbinden Sie sich als Master-Benutzer und erstellen Sie die Zieldatenbank sowie die Rolle, die der Dump erwartet. Die Standardwerte sind für beide `defectdojo`, verwenden Sie also Ihre eigenen Werte, falls Sie diese überschrieben haben.

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. Stellen Sie den Dump wieder her. Verwenden Sie bei einem Dump im Custom-Format `--no-owner` und `--no-privileges`, damit die Wiederherstellung nicht versucht, das Eigentum an Rollen zu übertragen, die auf dem Ziel nicht existieren. Eine verwaltete Datenbank gewährt keinen echten Superuser-Zugriff, sodass eine Wiederherstellung, die dies versucht, fehlschlägt.

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

Kommentieren Sie bei einem Klartext-SQL-Dump zunächst alle `CREATE ROLE`-, `ALTER ROLE`-, `CREATE DATABASE`- und `ALTER DATABASE ... OWNER`-Anweisungen aus oder entfernen Sie sie, und laden Sie ihn dann:

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

Wenn die Wiederherstellung Fehler meldet, erfassen Sie die Ausgabe und wenden Sie sich an den Support, bevor Sie weitere Inhalte aus dem Dump entfernen. Wird zu viel entfernt, kann die Datenbank in einem inkonsistenten Zustand landen, der schwerer zu diagnostizieren ist als der ursprüngliche Fehler.

## Schritt 5: Mediendateien wiederherstellen

Legen Sie den Inhalt des Medienarchivs dort ab, von wo Ihr Pro-Deployment hochgeladene Dateien liest. Die Anwendung sucht diese unter `/app/media`, was Ihr Deployment entweder über einen Bind-Mount oder ein persistentes Volume bereitstellt. Prüfen Sie in der mit Ihrer Lizenz gelieferten Installationsdokumentation, welchen Host-Pfad oder welches Volume Ihr Deployment verwendet.

Für ein Docker-Compose-Deployment, das auf einem benannten Volume basiert:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

Extrahieren Sie bei einem Kubernetes-Deployment das Archiv lokal und kopieren Sie es in den Django-Pod, der auf den unter `/app/media` eingehängten Persistent Volume Claim schreibt:

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## Schritt 6: DefectDojo Pro auf die wiederhergestellte Datenbank ausrichten

Aktualisieren Sie die Datenbankverbindung, damit Pro die soeben wiederhergestellte Datenbank verwendet, und starten Sie dann die Anwendung. Beim ersten Start führt Pro die Datenbankmigrationen aus, die das Schema von Ihrer Open-Source-Version auf die Pro-Version anheben. Je nach Größe Ihrer Datenbank und der Größe der Versionslücke kann dies eine Weile dauern, und die Anwendung steht erst nach Abschluss zur Verfügung.

Legen Sie bei Docker-Compose-Deployments die Datenbank-URL in Ihrer Deployment-Konfiguration fest und starten Sie den Stack neu. Der genaue Konfigurationsschlüssel und Befehl hängen von der Version von `dojo-compose-cli` ab, die Ihnen bereitgestellt wurde, folgen Sie daher der mit Ihrer Lizenz gelieferten Installationsdokumentation. Die Verbindungszeichenfolge hat folgende Form:

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Legen Sie bei Kubernetes-Deployments die Datenbank-URL in Ihren Helm-Values fest und deployen Sie erneut:

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Welche Pro-Funktionen für Ihr Deployment verfügbar sind, hängt von Ihrer Lizenz und der Art Ihres Deployments ab, da einige davon für eine selbst gehostete Installation nicht zutreffen. DefectDojo bestätigt Ihnen während der Migration, welcher Funktionsumfang für Sie gilt.

## Schritt 7: Daten validieren

Sobald die Anwendung mit der wiederhergestellten Datenbank läuft:

1. Melden Sie sich bei Ihrem DefectDojo-Pro-Deployment an.
2. Prüfen Sie, ob Ihre Assets, Organizations, Engagements, Tests und Findings vorhanden sind. Assets und Organizations hießen in Open Source Products und Product Types.
3. Laden Sie eine repräsentative hochgeladene Datei aus der UI herunter, zum Beispiel einen Anhang an einem Finding, Test oder Engagement, um zu bestätigen, dass die Wiederherstellung der Medien funktioniert hat.
4. Prüfen Sie, ob Benutzerkonten und Gruppen intakt sind. SSO und andere Authentifizierungseinstellungen müssen für das neue Deployment in der Regel neu konfiguriert werden.
5. Melden Sie etwaige Abweichungen Ihrem DefectDojo-Ansprechpartner.

## Die Umstellung planen

Der Dump ist eine Momentaufnahme zu einem bestimmten Zeitpunkt. Alles, was nach dessen Erstellung in der Open-Source-Instanz angelegt wird, ist daher nicht im Pro-Deployment enthalten. Um Datenverlust zu vermeiden, frieren Sie die Open-Source-Instanz für den finalen Dump und die Umstellung ein, oder führen Sie die Migration in einer ruhigen Phase durch.

Ein Probelauf lohnt sich. Migrieren Sie zunächst eine aktuelle Kopie, validieren Sie diese, und wiederholen Sie den Vorgang anschließend für die eigentliche Umstellung. Der zweite Durchlauf geht schneller und zeigt Ihnen, wie lange die Schemamigration in Schritt 6 dauern wird.

## Migrations-Checkliste

- Datenbank-Engine, Datenbankstandort und Open-Source-Version identifiziert
- Open-Source-Version an die Ziel-Pro-Version angeglichen
- Ziel-PostgreSQL bereitgestellt, erreichbar von einem Wiederherstellungs-Host mit den PostgreSQL-Client-Tools
- Datenbank exportiert, nach Möglichkeit mit einem Dump im Custom-Format
- Medienverzeichnis lokalisiert und komprimiert
- Beide Dateien mit der Open-Source-Version benannt
- Datenbank und Anwendungsrolle auf dem Ziel erstellt
- Dump wiederhergestellt, Ausgabe der Wiederherstellung auf Fehler geprüft
- Mediendateien in den Pfad oder das Volume wiederhergestellt, das Ihr Deployment verwendet
- Pro auf die wiederhergestellte Datenbank ausgerichtet und gestartet, Schemamigrationen abgeschlossen
- Daten im neuen Deployment validiert

## Fragen oder Support

DefectDojo unterstützt diese Migration von Anfang bis Ende. Wenden Sie sich bei Fragen zu jedem Schritt an Ihren Account-Repräsentanten oder an [support@defectdojo.com](mailto:support@defectdojo.com).
