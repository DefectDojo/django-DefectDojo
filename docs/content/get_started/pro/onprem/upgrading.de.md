---
title: Upgrade von DefectDojo Pro (On-Premise)
description: Unterstütztes Upgrade-Verfahren für selbst gehostete DefectDojo-Pro-Bereitstellungen
  mit dem Helm-Chart
draft: false
weight: 7
audience: pro
---

Diese Seite beschreibt das unterstützte Upgrade-Verfahren für selbst gehostete DefectDojo-Pro-Bereitstellungen, die das DefectDojo-Pro-Helm-Chart verwenden.

## Alles als eine Einheit aktualisieren

Jedes DefectDojo-Pro-Release besteht aus einer Helm-Chart-Version, Container-Image-Versionen und den Pro-Settings-Dateien. Diese werden gemeinsam gebaut und getestet und müssen auch gemeinsam als eine Einheit aktualisiert werden.

Das Aktualisieren nur der Image-Tags wird nicht unterstützt und führt dazu, dass Ihre Bereitstellung nicht mehr funktioniert.

## Settings-Dateien und Upgrades

DefectDojo Pro liefert mit jedem Release eine `pro_settings.py`-Datei aus, und diese Datei ändert sich mit nahezu jeder Version. Übernehmen Sie beim Upgrade keine Kopie von `pro_settings.py` aus der vorherigen Version, und patchen Sie keine ältere Kopie von Hand. Die Anwendung muss immer die `pro_settings.py` ausführen, die zu ihrer Version passt.

Bringen Sie Ihre eigenen Anpassungen in `local_settings.py` unter, niemals in `pro_settings.py`. Ihre `local_settings.py` bleibt bei Upgrades erhalten.

Das Helm-Chart liefert und mountet die passende `pro_settings.py` sowie Ihre `local_settings.py` automatisch. Wenn Sie mit dem Chart aktualisieren, müssen Sie nichts von Hand kopieren oder migrieren.

## Unterstütztes Upgrade-Verfahren

1. Lesen Sie die Release Notes für jede Version zwischen Ihrer aktuellen Version und Ihrer Zielversion, nicht nur für die Zielversion selbst. Siehe das [DefectDojo Pro Changelog](/releases/pro/changelog/) und die versionsspezifischen [Upgrade-Hinweise](/releases/os_upgrading/upgrading_guide/).
2. Sichern Sie Ihre Datenbank.
3. Aktualisieren Sie auf das Helm-Chart-Release, das zu Ihrer Ziel-Anwendungsversion passt, und verwenden Sie dabei Ihre vorhandenen Values-Dateien weiter. Ändern Sie Image-Tags nicht unabhängig von der Chart-Version.

Wenn Sie Fragen zum Upgrade Ihrer On-Premise-Bereitstellung haben, wenden Sie sich an [support@defectdojo.com](mailto:support@defectdojo.com).
