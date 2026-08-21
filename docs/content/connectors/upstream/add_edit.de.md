---
title: Upstream-Connectors hinzufügen oder bearbeiten
description: Mit einem unterstützten Sicherheitstool verbinden
aliases:
- /de/import_data/pro/connectors/add_edit_connectors/
- /de/en/connecting_your_tools/connectors/add_edit_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Hinweis: Upstream-Connectors sind eine reine DefectDojo-Pro-Funktion.</span>

Das Vorgehen zum Hinzufügen und Konfigurieren eines Upstream-Connectors ist unabhängig vom Tool, das Sie verbinden möchten, ähnlich. Bei bestimmten Tools müssen Sie jedoch möglicherweise API-Schlüssel erstellen oder zusätzliche Schritte durchführen.

Bevor Sie beginnen, empfehlen wir Ihnen, unsere [tool-spezifische Referenz](../../toolreference/upstream/) zu Rate zu ziehen, um die API-Ressourcen für das Tool zu finden, das Sie verbinden möchten.

1. Falls noch nicht geschehen, wechseln Sie zunächst in DefectDojo **zur Pro UI**.
2. Öffnen Sie im Menü auf der linken Seite die Gruppe **Connectors** unter der Überschrift **Import** und klicken Sie auf **Upstream Connectors**.
​
![image](images/add_edit_connectors.png)

3. Wählen Sie unter **Available Connectors** einen neuen Connector aus, den Sie zu DefectDojo hinzufügen möchten, und klicken Sie auf die Schaltfläche **Add Configuration** auf der Kachel des Tools. Mit dem Feld **Search Connectors** können Sie jeden Abschnitt nach Tool-Namen filtern, mit dem Umschalter **All / Asset / Finding** in der Kopfzeile der Seite nach Connector-Typ.
​
Sie können auch einen bestehenden Connector unter der Überschrift **Configured Connectors** bearbeiten. Klicken Sie für den zu bearbeitenden konfigurierten Connector auf **Manage Configuration \> Edit Configuration**.
​
![image](images/add_edit_connectors_2.png)

4. Sie benötigen eine erreichbare **Location URL** für das Tool sowie einen API-**Secret**-Schlüssel. Wo sich der API-Schlüssel befindet, hängt vom jeweiligen Tool ab, das Sie konfigurieren möchten. Weitere Details finden Sie in unserer [tool-spezifischen Referenz](../../toolreference/upstream/).
​
5. Vergeben Sie ein **Label** für diese Verbindung, damit Sie sie in DefectDojo leichter identifizieren können.
​
6. Planen Sie die automatische Discovery und Synchronisierung des Connectors über die Zeitpläne **Discovery Configuration** und **Synchronization Configuration**. Diese können später geändert werden.
​
7. Wählen Sie, ob Sie **Enable Auto-Mapping** aktivieren möchten. Enable Auto-Mapping erstellt ein neues Produkt in DefectDojo, um die Daten dieses Connectors zu speichern. Auto-Mapping kann jederzeit ein- oder ausgeschaltet werden.
​
8. Klicken Sie auf **Submit.**

![image](images/add_edit_connectors_3.png)

## Nächste Schritte

* Nachdem Sie nun einen Connector hinzugefügt haben, können Sie durch Ausführen einer [Discover](../manage_operations/#discover-operations)-Operation bestätigen, dass alles korrekt eingerichtet ist.
