---
title: Speicherplatz für hochgeladene Dateien hinzufügen
description: Erweitern Sie den verfügbaren Speicherplatz für hochgeladene Dateien
  in einer Docker-Compose-Bereitstellung, ohne die Bereitstellung selbst zu verändern
draft: false
weight: 11
audience: pro
---

Hochgeladene Dateien befinden sich im media-Verzeichnis auf dem Host, und bei einer Docker-Compose-Bereitstellung entspricht der dafür verfügbare Speicherplatz dem, was auf der Festplatte der VM noch frei ist. Große Uploads wie SBOMs können diese Festplatte füllen. Diese Seite beschreibt, wie Sie den Speicherplatz erweitern, ohne die Bereitstellung selbst zu verändern.

## Warum das auf Betriebssystemebene funktioniert

Die Docker-Compose-Bereitstellung bindet das media-Verzeichnis des Hosts per Bind-Mount in die Container ein, die es benötigen – sowohl die Anwendungscontainer als auch das nginx, das hochgeladene Dateien wieder an die Benutzer ausliefert. Die Container lesen und schreiben einen Pfad auf dem Host, sodass sie das jeweilige Dateisystem verwenden, das an diesem Pfad eingehängt ist. Das Einhängen zusätzlicher Kapazität dort ist für die Anwendung transparent.

Deshalb handelt es sich bei dem hier beschriebenen Vorgehen um eine Änderung auf Betriebssystemebene und nicht um eine Änderung der Bereitstellung. Wenn Sie die mit Ihrem Release ausgelieferte Compose-Datei unverändert lassen, bleibt Ihre Installation konsistent mit anderen On-Premise-Bereitstellungen, und Sie verlieren die Änderung nicht, wenn ein Upgrade diese Datei ersetzt.

## Blockspeicher, die naheliegende Option

Das Einhängen eines zusätzlichen Blockgeräts ist unter Linux die übliche Methode, um mit einer vollen Festplatte umzugehen, und die Option, die zuerst in Betracht gezogen werden sollte. Ein NAS- oder SAN-Volume funktioniert dafür ebenso wie der Blockspeicher eines Cloud-Anbieters, etwa ein Amazon-EBS-Volume.

Die Trennung von Anwendungsspeicher und Betriebssystemfestplatte ist generell eine gute Praxis, sodass Ihnen zwei sinnvolle Möglichkeiten offenstehen. Hängen Sie das Gerät im media-Verzeichnis ein, um Uploads eine eigene Kapazität zu geben, oder hängen Sie es eine Ebene höher im Bereitstellungsverzeichnis ein, sodass alle Anwendungsdaten auf einem von der VM getrennten Dateisystem liegen.

## Objektspeicher, mit Einschränkungen

Uploads mit Objektspeicher wie Amazon S3 zu unterlegen ist machbar und beseitigt die Kapazitätsgrenze vollständig, passt aber weniger natürlich als ein Blockgerät. Bedenken Sie Folgendes, bevor Sie sich dafür entscheiden.

Objektspeicher ist kein Dateisystem. S3 unterstützt weder wahlfreie Schreibzugriffe noch das Anhängen an eine bestehende Datei oder Dateisperren. Eine FUSE-Schicht überdeckt diese Lücken, emuliert aber eine Semantik, die der zugrunde liegende Speicher nicht besitzt.

Die Latenz ist höher als bei einem Blockgerät. Das wirkt sich auf Uploads aus, und da nginx hochgeladene Dateien aus demselben Verzeichnis ausliefert, betrifft es auch Downloads.

Es entstehen zusätzliche Netzwerkabhängigkeiten. Je nachdem, wo die VM in Ihrem Netzwerk platziert ist, kann das Erreichen des Buckets zusätzliche Netzwerkwege erfordern, und dieser Pfad muss nun verfügbar sein, damit Uploads funktionieren.

Neustarts erfordern Sorgfalt. Der Bucket muss beim Booten eingehängt werden, wodurch eine zeitliche Abhängigkeit zwischen dem Abschluss des Einhängens und dem Start von DefectDojo entsteht. Je nach Latenz kann dies zu einem hängenden Neustart oder einem Start führen, bei dem der Mount noch nicht bereit ist.

Die Berechtigungen müssen zusammenpassen. Die IAM-Berechtigungen des Buckets müssen mit den Dateisystemberechtigungen übereinstimmen, die die Anwendung zum Schreiben von Uploads benötigt.

### Tools zum Einhängen von Objektspeicher

Üblicherweise werden drei Tools verwendet, um S3 unter Linux als Dateisystem einzuhängen.

`rclone mount` ist stabil, wird aktiv gepflegt und bietet Caching-Modi für virtuelle Dateisysteme, die Lese- und Schreibpufferung gut handhaben. Von den dreien ist dies dasjenige, das wir empfehlen würden, wenn Sie diesen Weg gehen.

`goofys` ist auf Geschwindigkeit optimiert. Es erreicht dies, indem es Dateierstellungen und Schreibvorgänge asynchron durchführt und Operationen ignoriert, die S3 nicht nativ unterstützt, wie wahlfreie Schreibzugriffe und Dateisperren.

`s3fs-fuse` ist von den dreien am POSIX-kompatibelsten und unterstützt Dinge wie das Ändern von Eigentümer und Berechtigungen, aber die Nachbildung eines echten Dateisystems macht es deutlich langsamer als goofys.

## Verschieben des media-Verzeichnisses auf ein neues Dateisystem

Dies erfordert eine Ausfallzeit, da die Anwendung während des Kopierens keine Uploads schreiben darf.

1. Beenden Sie DefectDojo mit `dojo-compose-cli app stop`, damit sich während der Verschiebung nichts unter Ihnen ändert.
2. Benennen Sie das bestehende media-Verzeichnis um, um es als Rollback-Punkt zu behalten, indem Sie beispielsweise `media` innerhalb Ihres Bereitstellungsverzeichnisses in `old-media` umbenennen.
3. Erstellen Sie am ursprünglichen media-Pfad ein leeres Verzeichnis, das als Mount-Punkt dient.
4. Binden Sie das neue Dateisystem ein. Die genauen Schritte hängen davon ab, wofür Sie sich oben entschieden haben, laufen aber auf drei Dinge hinaus: den Speicher für Linux verfügbar machen, was bei Objektspeicher bedeutet, den Bucket und dessen Berechtigungen anzulegen; ihn am media-Pfad einhängen; und dafür sorgen, dass der Mount einen Neustart übersteht, in der Regel über einen `/etc/fstab`-Eintrag oder das Äquivalent für Ihr Tool.
5. Kopieren Sie die alten Inhalte hinüber und erhalten Sie dabei Eigentümer und Berechtigungen. `rsync -Pav` vom alten in das neue Verzeichnis erledigt dies und zeigt den Fortschritt an, was nützlich ist, wenn viel zu verschieben ist.
6. Bestätigen Sie, dass die Dateien angekommen sind. Bei Objektspeicher ist die Überprüfung des Buckets in der Konsole Ihres Anbieters der schnellste Weg, um sicherzustellen, dass der Mount tatsächlich dorthin schreibt, wo Sie es erwarten.
7. Starten Sie DefectDojo mit `dojo-compose-cli app start` und laden Sie eine Testdatei hoch. Falls der Upload fehlschlägt, zeigen die Container-Logs den Grund an, wobei Berechtigungen die übliche Ursache sind.

Behalten Sie das alte Verzeichnis, bis der Test-Upload erfolgreich war und Sie bestätigt haben, dass die daraus migrierten Dateien in der Benutzeroberfläche lesbar sind. Es ist Ihr Weg zurück, falls sich das neue Dateisystem nicht wie erwartet verhält.

## Support-Umfang

Dies sind allgemeine Empfehlungen. Das Hinzufügen von Speicherplatz zu einer VM ist eine Aufgabe des Betriebssystems, und die Details Ihrer gewählten Methode, insbesondere ein per FUSE eingehängter Objektspeicher, liegen außerhalb des Umfangs des On-Premise-Supports. Der Ansatz ist bewusst so gestaltet, dass Ihre Bereitstellung mit jeder anderen On-Premise-Installation konsistent bleibt, die von uns ausgelieferte Compose-Datei unverändert bleibt und das Kapazitätsproblem dort gelöst wird, wo es hingehört: auf der Betriebssystemebene.

Wenn Sie die Optionen für Ihre Umgebung abwägen, wenden Sie sich an [support@defectdojo.com](mailto:support@defectdojo.com), damit wir die Kompromisse besprechen können, bevor Sie sich für eine Option entscheiden.
