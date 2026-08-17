---
title: Installation über Docker Compose
description: Installieren Sie selbst gehostetes DefectDojo Pro auf einem einzelnen
  Host mit dojo-compose-cli, mit PostgreSQL auf einem separaten Server
draft: false
weight: 15
audience: pro
---

Diese Seite behandelt die Installation von DefectDojo Pro über Docker Compose, das einfachere der beiden selbst gehosteten Modelle und die richtige Wahl, wenn Sie noch kein Kubernetes betreiben.

Das Ergebnis sind zwei Hosts. Einer führt die Anwendung und ihre unterstützenden Dienste unter Docker Compose aus, der andere PostgreSQL. Sie können stattdessen auf eine verwaltete Datenbank verweisen, statt eine eigene zu betreiben, und für die Evaluierung können Sie die Datenbank in einem Container auf dem Anwendungs-Host ausführen, auch wenn das nicht das ist, was Sie für Produktivdaten wollen.

Nahezu die gesamte Arbeit übernimmt `dojo-compose-cli`, das DefectDojo zusammen mit Ihrer Lizenz bereitstellt. Der Befehl `first-install` ist ein interaktiver Assistent, der das Deployment konfiguriert, die Images herunterlädt, alles startet und einen systemd-Dienst registriert.

## Bevor Sie beginnen

Dimensionieren Sie das Deployment zuerst. Die Hinweise zur Hardware-Dimensionierung in diesem Abschnitt decken ab, was Sie sowohl für den Anwendungs-Host als auch für die Datenbank bereitstellen sollten.

Ubuntu 24.04 LTS ist das unterstützte Betriebssystem für diese Installation. Aktualisieren Sie es vollständig, bevor Sie beginnen. Die Installation führt Befehle als root aus, daher benötigen Sie `sudo` oder eine root-Shell auf beiden Hosts.

Sie benötigen zwei Dateien von DefectDojo, die mit Ihrem Abonnement eintreffen: das `dojo-compose-cli`-Archiv und Ihre Lizenzdatei, üblicherweise `dojopro.lic` genannt. Wenden Sie sich an Ihren Kundenbetreuer oder an [support@defectdojo.com](mailto:support@defectdojo.com), falls Sie diese nicht haben.

## Datenbank einrichten

DefectDojo Pro erfordert PostgreSQL 16 oder neuer.

### Verwendung einer verwalteten Datenbank

Wenn Sie einen verwalteten PostgreSQL-Dienst nutzen, folgen Sie der Dokumentation dieses Anbieters, um die Instanz zu erstellen, und legen Sie dann Folgendes an:

- Eine Datenbank namens `dojodb`
- Einen Datenbankbenutzer namens `dojodbusr`, mit allen Rechten für `dojodb` und als deren Besitzer eingerichtet

Notieren Sie sich den Hostnamen, den Port, falls er nicht dem Standard 5432 entspricht, sowie die Zugangsdaten. Sie benötigen diese während der Installation.

### PostgreSQL selbst betreiben

Unter Ubuntu 24.04 befindet sich PostgreSQL 16 in den Standard-Repositories:

```bash
apt update
apt -y install postgresql postgresql-contrib
```

Legen Sie die Datenbanken und den Anwendungsbenutzer an. DefectDojo verwendet eine zweite Datenbank für seinen Orchestrierungsdienst, legen Sie also beide an:

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

Verwenden Sie ein alphanumerisches Passwort. Sonderzeichen müssen später URL-codiert werden, wenn das Passwort in einen Connection-String eingeht, und dabei unterläuft leicht ein Fehler.

Lassen Sie die Datenbank dann Verbindungen vom Anwendungs-Host annehmen. Setzen Sie in `/etc/postgresql/16/main/postgresql.conf` `listen_addresses` auf die eigene Adresse des Datenbankservers, oder auf `*`, wenn Sie sich nicht festlegen möchten:

```bash
listen_addresses = '<db-server-address>'
```

Und fügen Sie in `/etc/postgresql/16/main/pg_hba.conf` drei Zeilen hinzu, die den Anwendungs-Host autorisieren. Eine Beschränkung auf die Adresse des Anwendungs-Hosts ist besser, als alles zu öffnen:

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

Starten Sie neu, damit beide Änderungen wirksam werden:

```bash
systemctl restart postgresql
```

## Anwendungs-Host vorbereiten

### Ausgehende Konnektivität

In einem eingeschränkten Netzwerk benötigt der Anwendungs-Host ausgehenden Zugriff auf Folgendes. Sofern nicht anders angegeben, handelt es sich jeweils um HTTPS auf Port 443.

| Destination | Purpose | Required |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | Die DefectDojo Pro Container-Registry | Ja |
| Ihr Datenbank-Host, üblicherweise Port 5432 | Anwendung zu Datenbank | Ja |
| Die Paket-Repositories Ihrer Distribution | Betriebssystemabhängigkeiten während der Einrichtung | Ja |
| `download.docker.com` | Docker-Engine-Pakete während der Einrichtung | Ja |
| `api.first.org` | EPSS-Exploit-Vorhersagewerte | Optional |
| `www.cisa.gov` | Der KEV-Katalog bekannter ausgenutzter Schwachstellen | Optional |

Erstellen Sie die Allowlist nach Hostname statt nach Adresse. Die Registry liegt hinter einem Content Delivery Network, daher variieren ihre Adressen je nach Standort und ändern sich mit der Zeit.

Wenn der Host das Internet über einen ausgehenden Proxy erreicht, siehe [Running DefectDojo Behind a Forward HTTPS Proxy](/onprem_deployment/forward_proxy/). Hat er überhaupt keine Verbindung zum Internet, folgen Sie stattdessen dem Verfahren für die Air-Gapped-Installation in diesem Abschnitt.

### Erreichbarkeit der Datenbank prüfen

Installieren Sie die Client-Tools und stellen Sie eine Verbindung her, bevor Sie fortfahren. Ein Datenbankproblem lässt sich jetzt wesentlich leichter diagnostizieren als mitten in der Installation:

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### Docker Engine installieren

Folgen Sie den [Docker Engine installation instructions for Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Verwenden Sie Dockers eigene Dokumentation statt einer Kopie, da sich die Schritte im Laufe der Zeit ändern. Installieren Sie zusammen mit der Engine das Paket `docker-compose-plugin`, das diese Anleitung standardmäßig einschließt.

Fügen Sie dann Ihren Benutzer der Gruppe `docker` hinzu und übernehmen Sie die neue Mitgliedschaft:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## DefectDojo installieren

Kopieren Sie das CLI-Archiv und Ihre Lizenzdatei in dasselbe Verzeichnis auf dem Anwendungs-Host und entpacken Sie die CLI:

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

Führen Sie dann den Installer aus diesem Verzeichnis aus:

```bash
sudo ./dojo-compose-cli first-install
```

Der Assistent fragt Folgendes ab.

| Prompt | What it is |
| --- | --- |
| `DOJO_CLI_KEY` | Ein Verschlüsselungsschlüssel für die von der CLI auf der Festplatte gespeicherte Konfiguration. Wählen Sie ihn jetzt und bewahren Sie ihn auf, da spätere Befehle ihn benötigen. |
| DefectDojo Version | Das zu installierende Release. |
| Deploy Version | Die zu verwendenden Deployment-Dateien. Setzen Sie sie auf denselben Wert wie die Version. |
| Deploy Type | `separate-db` für eine Datenbank auf einem eigenen Host, oder `containerized-db`, um PostgreSQL in einem Container auszuführen. |
| Database Connection Type | Wählen Sie Single Line und geben Sie den gesamten Connection-String an. |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`. Sie muss mit `postgres://` statt mit `postgresql://` beginnen. |
| `DD_ALLOWED_HOSTS` | Host-Header, auf die die Anwendung reagiert. |
| `DD_SITE_URL` | Die vollständige URL, unter der Benutzer DefectDojo erreichen, zum Beispiel `https://defectdojo.internal.example.com`. |

Zwei Dinge sind bei den Eingabeaufforderungen wichtig zu wissen. Geben Sie die Datenbankverbindung als einzelne Zeile an statt Wert für Wert, da der Weg über Einzelwerte derzeit nicht nach dem Benutzernamen fragt. Und wenn das Passwort Zeichen wie `!`, `@` oder `#` enthält, codieren Sie diese im Connection-String als URL.

Der Installer lädt anschließend die Images herunter, startet den Stack, erstellt einen systemd-Dienst und gibt die generierten Admin-Zugangsdaten aus. **Speichern Sie diese Zugangsdaten, bevor Sie das Terminal schließen. Sie werden nicht erneut angezeigt.**

Sobald der Vorgang abgeschlossen ist, ist DefectDojo unter der angegebenen Site-URL verfügbar.

## Was die Installation erzeugt hat

| Item | Location |
| --- | --- |
| CLI-Binärdatei | `/usr/bin/dojo-compose-cli` |
| Anwendungsdateien, Compose-Datei, nginx-Konfiguration, Medien | `/opt/dojo/` |
| Lizenzdatei | `/etc/defectdojo/dojopro.lic` |
| Verschlüsselte CLI-Konfiguration | `/etc/defectdojo/compose.config` |
| TLS-Zertifikate | `/opt/dojo/certs/` |
| Ihre Anpassungen | `/opt/dojo/customizations/` |
| Systemd-Dienst | `/etc/systemd/system/defectdojo-compose.service` |

Außerdem werden ein Benutzer und eine Gruppe namens `dojosrv` angelegt, denen die Dateien der Anwendung gehören.

Der laufende Stack besteht aus der Django-Anwendung, einem separaten Container für Scan-Imports, nginx, einem Celery-Worker und -Scheduler, Valkey für Caching und Queueing, dem Connectors-Dienst und dem MCP-Server. `docker ps` listet sie auf.

Im Tagesgeschäft benötigen Sie diese Befehle:

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

Verwenden Sie `app restart` nach jeder Konfigurationsänderung, da dies die Container neu erstellt, sodass die neuen Werte übernommen werden.

## TLS-Zertifikat ersetzen

Die Installation liefert ein selbstsigniertes Zertifikat mit, damit die Site sofort funktioniert. Ersetzen Sie es durch Ihr eigenes, indem Sie zwei Dateien überschreiben und dabei die Namen exakt beibehalten:

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

Führen Sie danach `dojo-compose-cli app restart` aus, damit sie übernommen werden.

## Admin-Passwort zurücksetzen

Wenn Sie das generierte Passwort verlieren, setzen Sie es vom Anwendungs-Host aus zurück. DefectDojo muss dafür laufen:

```bash
dojo-compose-cli app change-password
```

## Upgrade durchführen

Sichern Sie zuerst Ihre Datenbank und lesen Sie die Release Notes für jede Version zwischen Ihrer aktuellen und Ihrer Zielversion, nicht nur für die Zielversion. Siehe die [upgrade notes](/releases/os_upgrading/upgrading_guide/).

Die CLI kann das gesamte Upgrade durchführen und fragt dabei nach der Version:

```bash
dojo-compose-cli app upgrade
```

Wenn Sie es lieber schrittweise durchführen möchten, stoppen Sie die Anwendung, legen Sie die neue Version fest, laden Sie die passenden Deployment-Dateien herunter und starten Sie anschließend neu:

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

Der Download-Schritt vergleicht die eingehende `docker-compose.yml`, die nginx-Konfiguration und `local_settings.py` mit Ihren bestehenden Dateien und weist Sie auf Unterschiede hin, damit Sie Ihre Änderungen abgleichen können. Das Hinzufügen von `--overwrite` übernimmt die neuen Versionen dieser Dateien und verwirft lokale Änderungen an ihnen, verwenden Sie es also bewusst.

Bewahren Sie Ihre eigenen Einstellungen in `/opt/dojo/customizations/local_settings.py` auf. Diese Datei gehört Ihnen und übersteht Upgrades.

## Befehlsreferenz

`dojo-compose-cli --help` listet alles auf, und jeder Unterbefehl akzeptiert ebenfalls `--help`. Die Befehle, die Sie am ehesten benötigen:

| Command | What it does |
| --- | --- |
| `first-install` | Interaktive Erstinstallation |
| `app start`, `app stop`, `app restart` | Den Stack steuern |
| `app upgrade` | Auf eine neuere Version aktualisieren |
| `app pull-images`, `app purge-images` | Die konfigurierten Images abrufen oder entfernen |
| `app change-password` | Admin-Passwort zurücksetzen, bei laufender App |
| `config print` | Die aktuelle Konfiguration anzeigen |
| `config set` | Version, Deploy-Version, Deploy-Typ oder Air-Gapped-Modus festlegen |
| `config rotate-secret` | Den Schlüssel rotieren, der die gespeicherte Konfiguration verschlüsselt |
| `environment print`, `environment add`, `environment remove` | Umgebungsvariablen verwalten |
| `deploy download` | Deployment-Dateien für die konfigurierte Version abrufen |
| `license print`, `license status`, `license update` | Ihre Lizenz prüfen und aktualisieren |
| `validate db-connection` | Den Datenbank-Connection-String prüfen |
| `validate deploy-version` | Prüfen, ob die Deployment-Dateien zur konfigurierten Version passen |
| `diagnostics collect` | Ein Diagnosepaket für eine Support-Anfrage zusammenstellen |
| `register` | Bei der Container-Registry authentifizieren |
| `update-binary` | Die CLI selbst aktualisieren |

Die meisten Befehle benötigen `DOJO_CLI_KEY`, da die Konfiguration verschlüsselt gespeichert wird. Exportieren Sie ihn für Ihre Sitzung, oder übergeben Sie ihn mit `sudo -E` an `sudo`:

```bash
export DOJO_CLI_KEY="your-key"
```

## Fragen oder Support

Wenn eine Installation nicht abgeschlossen werden kann, sammelt `dojo-compose-cli diagnostics collect` ein Berichtspaket, mit dem wir am schnellsten helfen können. Senden Sie es zusammen mit einer Beschreibung dessen, was beim Fehler gerade lief, an [support@defectdojo.com](mailto:support@defectdojo.com).
