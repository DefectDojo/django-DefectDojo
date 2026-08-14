---
title: Installation von DefectDojo Pro in einer abgeschotteten Umgebung (Air-Gapped)
description: Bereiten Sie die Installationsartefakte von DefectDojo Pro auf einem
  Host mit Internetzugang vor und übertragen Sie sie anschließend in ein abgeschottetes
  Netzwerk
draft: false
weight: 8
audience: pro
---

Diese Seite ergänzt die Installationsanleitung, die mit Ihrer DefectDojo-Pro-Lizenz geliefert wird. Sie behandelt nur das, was sich ändert, wenn der Zielhost keine Verbindung zum Internet hat. Alles andere, einschließlich der Host-Voraussetzungen und der PostgreSQL-Einrichtung, folgt der Standardanleitung.

Der Ansatz verwendet zwei Hosts. Ein Staging-Host mit normalem Internetzugang lädt die Deployment-Artefakte und Container-Images herunter. Anschließend übertragen Sie diese Artefakte mithilfe des in Ihrer Umgebung zulässigen Transferverfahrens in das abgeschottete Netzwerk und schließen die Installation auf dem Zielhost ohne Netzwerkzugriff auf DefectDojo ab.

Planen Sie ein, dass der Staging-Host später erneut erreichbar sein muss. Upgrades wiederholen denselben Transfervorgang, daher lohnt es sich, ihn zu behalten.

## Was Sie benötigen

Auf dem Staging-Host: ein Linux-Host mit Internetzugang, installiertem Docker und genügend freiem Festplattenspeicher für das Deployment-Verzeichnis sowie die komprimierten Container-Images. Die Images machen den größten Teil davon aus und liegen jeweils bei mehreren hundert Megabyte.

Auf dem abgeschotteten Host: ein installiertes und funktionierendes Docker sowie ein bereits bereitgestellter und erreichbarer PostgreSQL-Server, beides gemäß der Standardinstallationsanleitung.

Auf beiden Hosts: eine Kopie des Archivs `dojo-compose-cli` und Ihre Lizenzdatei, wie von DefectDojo bereitgestellt. Verwenden Sie CLI-Version 2.1.0 oder höher. Frühere Versionen verfügen über keinen Air-Gapped-Modus, und ohne diesen versucht die CLI bei jedem Befehl, die Container-Registry zu erreichen, und schlägt mit Namensauflösungsfehlern fehl, anstatt Ihnen mitzuteilen, was falsch ist.

## Vorbereiten der Artefakte

Führen Sie diese Schritte auf dem Staging-Host aus.

### 1. Registrieren der CLI

Installieren Sie zunächst Docker, falls noch nicht vorhanden. Distributionsspezifische Anweisungen finden Sie in der [Docker-Installationsdokumentation](https://docs.docker.com/engine/install/).

Entpacken Sie das CLI-Archiv und registrieren Sie es anschließend:

```bash
sudo ./dojo-compose-cli register
```

Die Registrierung installiert die CLI unter `/usr/bin`, erstellt die Gruppe `dojosrv`, fügt Ihren Benutzer den Gruppen `dojosrv` und `docker` hinzu, validiert die Lizenz und authentifiziert Docker gegenüber der DefectDojo-Container-Registry.

Sie werden nach einem `DOJO_CLI_KEY` gefragt, der die gespeicherte Konfiguration der CLI auf der Festplatte verschlüsselt. Setzen Sie ihn in der Umgebung, damit Sie nicht bei jedem Befehl erneut danach gefragt werden:

```bash
export DOJO_CLI_KEY="your-key"
```

Die neue Gruppenmitgliedschaft gilt nicht für Ihre aktuelle Shell. Öffnen Sie entweder eine neue Sitzung, oder übernehmen Sie die Gruppen direkt:

```bash
newgrp docker
```

Bestätigen Sie mit `id`, dass sowohl `docker` als auch `dojosrv` aufgeführt sind. Sobald sich Ihr Benutzer in der Gruppe `docker` befindet, benötigen die übrigen Befehle kein `sudo` mehr.

Wenn der Staging-Host das Internet über einen ausgehenden HTTPS-Proxy erreicht, konfigurieren Sie die Proxy-Variablen, bevor Sie irgendetwas herunterladen. Siehe [Betrieb von DefectDojo hinter einem Forward-HTTPS-Proxy](/onprem_deployment/forward_proxy/).

### 2. Festlegen der Version

Setzen Sie sowohl die Deployment-Version als auch die Anwendungsversion auf das Release, das Sie installieren möchten, und ersetzen Sie dabei `x.y.z`:

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

Verwenden Sie in beiden Befehlen dieselbe Version und behalten Sie diese für den Rest dieses Vorgangs konsistent bei. Werden bei den Deployment-Artefakten und den Images unterschiedliche Versionen gemischt, startet der Stack entweder nicht oder mit den falschen Images.

### 3. Herunterladen der Deployment-Artefakte und Images

Laden Sie das Deployment-Verzeichnis herunter:

```bash
dojo-compose-cli deploy download
```

Dadurch wird `/opt/dojo` mit der Compose-Datei, der nginx-Konfiguration, den Issue-Tracker-Vorlagen, dem Customizations-Verzeichnis und einem versionierten Unterverzeichnis für das ausgewählte Release befüllt.

Laden Sie anschließend die Container-Images herunter:

```bash
dojo-compose-cli app pull-images
```

Überprüfen Sie, was angekommen ist:

```bash
docker image ls
```

Notieren Sie sich das Repository-Präfix, das die DefectDojo-Images in dieser Ausgabe gemeinsam haben. Sie benötigen es im nächsten Schritt, und die Menge der Images unterscheidet sich je nach Release. Lesen Sie es daher aus Ihrer eigenen Ausgabe ab, anstatt eine feste Liste anzunehmen.

### 4. Erfassen der generierten Konfiguration

Die Standardinstallation generiert beim ersten Start mehrere Konfigurationswerte. Bei einer Air-Gapped-Installation legen Sie diese von Hand auf dem Zielhost fest. Erfassen Sie sie daher jetzt:

```bash
dojo-compose-cli environment print | head -n 9
```

Bewahren Sie den Anmeldedaten-Verschlüsselungsschlüssel (Credential Encryption Key) und den Secret Key auf. Beide sind generierte, zufällige 64-Zeichen-Strings, und insbesondere der Credential Key muss mit dem übereinstimmen, der bei der Verschlüsselung der Anmeldedaten verwendet wurde. Notieren Sie ihn daher genau und bewahren Sie ihn als Geheimnis auf. Die uwsgi- und celery-Werte in derselben Ausgabe sind als Ausgangspunkte für den Zielhost hilfreich.

Behandeln Sie diese Ausgabe als vertraulich. Sie enthält die Schlüssel, die die gespeicherten Anmeldedaten für Ihr Deployment schützen.

### 5. Alles verpacken

Erstellen Sie ein Verzeichnis für den Transfer und verwenden Sie die Version im Namen, damit der Inhalt später eindeutig ist:

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

Archivieren Sie das Deployment-Verzeichnis unter Beibehaltung der Berechtigungen:

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

Sichern Sie die Container-Images. Dieses Skript verwendet das in Schritt 3 notierte Repository-Präfix, sichert jedes passende Image und komprimiert es:

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

Machen Sie es ausführbar und führen Sie es mit Ihrem Präfix aus:

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

Prüfen Sie, ob für jedes Image aus Schritt 3 eine Datei erzeugt wurde, und packen Sie anschließend das Verzeichnis:

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

Übertragen Sie `artifacts-x.y.z.tar.gz` mit Ihrem üblichen Transferverfahren in das abgeschottete Netzwerk, zusammen mit dem CLI-Archiv und Ihrer Lizenzdatei, falls diese sich dort noch nicht befinden.

## Installation auf dem abgeschotteten Host

### 6. Installieren der CLI und Aktivieren des Air-Gapped-Modus

Entpacken Sie das CLI-Archiv und legen Sie die Lizenz dort ab, wo die CLI sie erwartet:

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

Aktivieren Sie den Air-Gapped-Modus. Dies ist der erste CLI-Befehl, den Sie auf diesem Host ausführen. Er installiert die CLI unter `/usr/bin`, validiert die Lizenz aus der Datei und verschlüsselt dabei die gespeicherte Konfiguration:

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

Bestätigen Sie, dass die Änderung wirksam wurde:

```bash
dojo-compose-cli config print
```

Die Ausgabe enthält `Air Gapped Deploy`, gesetzt auf true. Setzen Sie auch hier `DOJO_CLI_KEY` in der Umgebung, damit spätere Befehle nicht erneut danach fragen.

Führen Sie `register` nicht auf diesem Host aus. Die Registrierung dient der Authentifizierung gegenüber der Container-Registry, die per Definition nicht erreichbar ist. Im Air-Gapped-Modus verweigert die CLI diesen Befehl, anstatt ihn zu versuchen. Dasselbe gilt für die anderen Befehle, die die Registry erreichen:

| Befehl | Verhalten im Air-Gapped-Modus |
| --- | --- |
| `register` | Verweigert. Registry-Authentifizierung ist nicht verfügbar. |
| `deploy download` | Verweigert. Führen Sie ihn stattdessen auf dem Staging-Host aus. |
| `app pull-images` | Verweigert. Führen Sie ihn stattdessen auf dem Staging-Host aus. |
| `app upgrade` | Verweigert. Siehe den Abschnitt „Upgrade“ unten. |
| `app start`, `app stop`, `app restart` | Verfügbar. Diese kontaktieren die Registry nicht. |

Jeder verweigerte Befehl beendet sich mit einer Meldung, die den Air-Gapped-Modus nennt. Eine Verweigerung an dieser Stelle bedeutet also, dass die CLI wie vorgesehen funktioniert, und ist kein zu diagnostizierender Fehler.

Übernehmen Sie Ihre neue Gruppenmitgliedschaft, bevor Sie fortfahren:

```bash
newgrp docker
```

### 7. Wiederherstellen des Deployment-Verzeichnisses

Entpacken Sie das Transferpaket und verschieben Sie anschließend das Deployment-Archiv an den richtigen Ort:

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

Durch die Einrichtung der CLI kann ein nahezu leeres `/opt/dojo` entstanden sein, das nur die Lizenz enthält. Falls vorhanden, entfernen Sie es zuerst, damit sich das Archiv nicht damit vermischt:

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

Entpacken Sie das eigentliche Deployment-Verzeichnis und korrigieren Sie anschließend die Besitzrechte und die Berechtigungen für media:

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. Manuelles Festlegen der Konfiguration

Eine Air-Gapped-Installation verwendet nicht die interaktive Ersteinrichtung. Legen Sie daher die Werte fest, die sonst automatisch generiert würden. Verwenden Sie die in Schritt 4 erfassten Schlüssel:

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

Setzen Sie die Version passend zu den übertragenen Artefakten:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

Legen Sie die Site-URL und die zulässigen Hosts fest. Die Site-URL muss die Adresse sein, die innerhalb Ihres Netzwerks zu diesem Host aufgelöst wird:

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

Legen Sie die Datenbankverbindung fest, unter Verwendung des zuvor bereitgestellten PostgreSQL-Servers:

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. Laden der Container-Images

Dieses Skript lädt jede Image-Datei im Images-Verzeichnis:

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

Führen Sie es aus dem entpackten Artefakte-Verzeichnis heraus aus:

```bash
chmod u+x load-images.bash
./load-images.bash
```

Bestätigen Sie anschließend mit `docker image ls`, dass alle Images in der erwarteten Version geladen wurden.

### 10. Starten des Stacks

Starten Sie den Stack mit der CLI. Dies funktioniert im Air-Gapped-Modus, da die CLI die von Ihnen festgelegte Konfiguration liest und die lokale Compose-Datei ausführt, ohne die Registry zu kontaktieren:

```bash
dojo-compose-cli app start
```

`app stop` und `app restart` stehen auf dieselbe Weise zur Verfügung. Verwenden Sie `app restart`, nachdem Sie einen Umgebungswert geändert haben, da dadurch die Container neu erstellt werden, sodass die neuen Werte übernommen werden.

Zwei Dinge sollten Sie prüfen, wenn der Stack nicht startet. Der Befehl benötigt das vorhandene Deployment-Verzeichnis. Bestätigen Sie daher, dass `/opt/dojo/docker-compose.yml` aus Schritt 7 vorhanden ist. Außerdem bestimmt die konfigurierte Version die Image-Tags, sie muss also mit den in Schritt 9 geladenen Images übereinstimmen.

DefectDojo ist anschließend unter der als Site-URL festgelegten Adresse erreichbar.

## Upgrade eines abgeschotteten Deployments

`app upgrade` lädt Daten von der Container-Registry herunter und gehört daher zu den Befehlen, die der Air-Gapped-Modus verweigert. Upgrades folgen demselben Weg wie die Installation, anstatt über einen einzelnen Befehl gesteuert zu werden.

Legen Sie auf dem Staging-Host die neue Version fest und wiederholen Sie dafür die Schritte 3 bis 5. Übertragen Sie das neue Paket, laden Sie die neuen Images, und setzen Sie anschließend auf dem abgeschotteten Host die Version auf die neue Version und starten Sie neu:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

Zwei Dinge führen häufig zu Verwirrung. Ein Neustart ohne Änderung der konfigurierten Version bringt den Stack wieder mit den bereits vorhandenen Images hoch, da die Version die Image-Tags bestimmt. Außerdem kann sich die Menge der Images zwischen Releases ändern. Vergleichen Sie daher, was Sie geladen haben, mit dem, was der Pull der neuen Version ergeben hat, anstatt anzunehmen, dass die vorherige Liste weiterhin gilt.

Ihr bestehendes Deployment-Verzeichnis übernimmt die Compose-Datei oder die nginx-Konfiguration der neuen Version nicht von selbst. Stellen Sie daher den neuen Inhalt von `/opt/dojo` wie in Schritt 7 wieder her, wobei Sie Ihre eigenen Customizations, Zertifikate und media beibehalten.

Sichern Sie Ihre Datenbank vor jedem Upgrade und lesen Sie die [Upgrade-Hinweise](/releases/os_upgrading/upgrading_guide/) für jede Version zwischen Ihrer aktuellen und Ihrer Zielversion. Wenn Sie mehrere Releases zurückliegen, wenden Sie sich vor Beginn an den Support.

## Funktionen, die ausgehenden Zugriff benötigen

Ein abgeschottetes Deployment läuft ohne jegliche ausgehende Konnektivität, aber Funktionen, die externe Dienste erreichen, können im getrennten Zustand nicht funktionieren. Dies betrifft die Connectors und Integrators, die Daten von cloudgehosteten Tools abrufen, Issue-Tracker-Integrationen wie Jira, ausgehende Benachrichtigungen an Dienste wie Slack und Microsoft Teams sowie Schwachstellen-Anreicherungsdaten, die normalerweise nach einem Zeitplan abgerufen werden.

Diese werden pro Deployment konfiguriert, anstatt standardmäßig aktiviert zu sein, sodass eine Air-Gapped-Installation durch ihr Fehlen nicht beeinträchtigt wird. Wenn Sie eine solche Funktion aktivieren, ist mit Namensauflösungs- oder Verbindungsfehlern zu rechnen, bis das Deployment über einen Weg zu diesem Dienst verfügt. Wenn der ausgehende Pfad zwar existiert, aber über einen Proxy verläuft, siehe [Betrieb von DefectDojo hinter einem Forward-HTTPS-Proxy](/onprem_deployment/forward_proxy/).

### EPSS- und KEV-Daten von einem internen Mirror

Die EPSS- und KEV-Anreicherung ist eine Ausnahme, deren Einrichtung sich lohnt, da sie keinen Weg zum öffentlichen Internet benötigt. Beide werden im Tuner unter Finding Enrichment konfiguriert, und jede verfügt über einen eigenen Aktivierungsschalter und eine eigene Lookup-URL. Die URL-Felder verweisen standardmäßig auf die öffentlichen Quellen, Sie können sie jedoch auf eine Kopie umleiten, die innerhalb Ihres eigenen Netzwerks gehostet wird.

Der Mirror muss dieselben Dateien im selben Format wie die öffentlichen Quellen bereitstellen. Die Lookups rufen eine bestimmte Datei von der angegebenen URL ab, anstatt zu erkennen, was dort vorhanden ist. Ein Mirror, der die Daten umpackt oder neu organisiert, funktioniert daher nicht. Aktualisieren Sie Ihre Kopien nach einem für Sie passenden Zeitplan, da das Deployment nur liest, was Ihr Mirror bereitstellt.

## Fragen oder Support

Wenden Sie sich bei Fragen zu einer Air-Gapped-Installation oder einem Upgrade an Ihren Account-Repräsentanten oder an [support@defectdojo.com](mailto:support@defectdojo.com).
