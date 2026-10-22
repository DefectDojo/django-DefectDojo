---
title: Asset-Hierarchie
description: DefectDojo Pro – Überarbeitung der Produkthierarchie
audience: pro
weight: 1
aliases:
- /de/en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
- /de/asset_modelling/pro_hierarchy/assets_organizations
---

DefectDojo Pro erweitert die Objektklassen Produkt/Produkttyp, um mehr Flexibilität im Datenmodell zu bieten.

## Aktivieren der Hierarchie-Funktion

Die beiden folgenden Teile sind voneinander unabhängig und werden über unterschiedliche Mechanismen gesteuert.

### Asset-Hierarchie

**Asset-Hierarchie** ermöglicht übergeordnete/untergeordnete Beziehungen zwischen Assets. Die Hierarchie wird über die Registerkarte **Produkt** in der Navigation angezeigt und verwaltet.

Asset-Hierarchie ist allgemein verfügbar und für jede Instanz, ob Cloud oder On-Premise, standardmäßig aktiviert. Es muss nichts aktiviert werden, und die Funktion wird auf der Seite „Feature Flags" nicht mehr aufgeführt.

### Bezeichnungsänderungen (optional)

**Bezeichnungsänderungen** benennen in der gesamten UI „Produkttyp" in „Organisation" und „Produkt" in „Asset" um. Dies ist ein separater Schritt von der Aktivierung der Hierarchie und kann gleichzeitig oder später durchgeführt werden.

Bezeichnungsänderungen sind ab Version 3.0 standardmäßig aktiviert. Es gibt zwei Steuerungen, die unterschiedliche Teile der Anwendung abdecken:

* **Pro-UI** (die Standard-UI): Ein Superuser schaltet „Organization / Asset Relabeling" unter **Settings > Feature Flags** um, sowohl auf Cloud- als auch auf On-Premise-Instanzen. Die neuen Bezeichnungen erscheinen beim nächsten Laden der Seite. Siehe [Feature Flags](/admin/feature_flags/pro__feature_flags/).
* **Klassische UI-Seiten und generierte Berichte**: Deren Bezeichnungen und URLs stammen aus der Deployment-Einstellung `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`, die beim Start von DefectDojo gelesen wird. Setzen Sie sie On-Premise und starten Sie DefectDojo neu. Bei [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) senden Sie eine E-Mail an [support@defectdojo.com](mailto:support@defectdojo.com) mit Ihrer Instanz-URL.

Beide sind standardmäßig aktiviert, und der Feature-Flags-Wert wurde ursprünglich aus der Deployment-Einstellung übernommen, sodass beide übereinstimmen, sofern Sie nicht eine davon ändern. Halten Sie sie synchron, wenn Sie sowohl die klassische UI als auch die Pro-UI verwenden.

Beachten Sie, dass Bezeichnungsänderungen rein kosmetisch sind: API-Endpunkte und Feldnamen bleiben unverändert, sodass bestehende Automatisierungen weiterhin funktionieren.

## Wesentliche Änderungen

* **Produkttypen** wurden in „Organizations" umbenannt, und **Produkte** wurden in „Assets" umbenannt. Ab Version 3.0 ist diese Umbenennung standardmäßig aktiviert. Siehe [Bezeichnungsänderungen](#label-changes-optional) für die Steuerungen, mit denen sie deaktiviert wird.
* **Assets** können jetzt untereinander übergeordnete/untergeordnete Beziehungen haben, um Organisationskomponenten weiter zu unterteilen.

### Organisationen

Wie bei Produkttypen sollten **Organisationen** als übergeordnete Kategorie verstanden werden. Sie können diese verwenden, um die Kernsoftwareanwendungen, Abteilungen oder Geschäftsfunktionen Ihres Unternehmens zu trennen.

Sie könnten zum Beispiel eine Organisation für mehrere Repository-Gruppierungen anlegen: „Core Application", „Infrastructure", „DevOps", „Analytics", „SDK" könnten jeweils mehrere Code-Repositories enthalten.

Bedenken Sie, dass es für Berichtszwecke einfacher ist, mehrere Organisationen zu einem einzigen Dokument zusammenzufassen, als eine einzelne Organisation in separate Dokumente zu unterteilen. Wir empfehlen daher, Organisationen auf einer möglichst granularen Ebene einzurichten, wie es für die Berichte Ihres Teams sinnvoll ist. Es besteht zum Beispiel keine Notwendigkeit, eine große Geschäftseinheit als Organisation abzubilden, wenn Sie hauptsächlich über einzelne Abteilungen innerhalb dieser Einheit berichten möchten.

### Assets

Assets sollen Unterteilungen Ihrer Organisationen darstellen. Im Gegensatz zu Produkten können Assets jedoch verschachtelt werden und untereinander übergeordnete/untergeordnete Beziehungen haben.

## Beispiele für die Asset-Verschachtelung

### Branch-Darstellung auf Asset-Ebene

Entwicklungs- und Feature-Branches können auf verschiedene Weise dargestellt werden; separate Engagements oder Tests sind bestehende Möglichkeiten, um den Unterschied zwischen Ihren Produktions-, Dev- und anderen Feature-Branches abzubilden.

Sie können diese auch mithilfe verschachtelter Assets abbilden. Betrachten Sie den folgenden Asset-Baum:

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

In dieser Umgebung könnte jeder Branch (`prod`, `dev`, `feature a`, `feature b`) eigene Engagements und Tests haben, die von den anderen Assets isoliert sind, sodass sie nicht gegeneinander dedupliziert werden. Dieser Aufbau kann auch die Navigation erleichtern, da Asset-Namen direkt dem Pfad in Git entsprechen können.

### Mono-Repo: Separate Komponenten

Wenn Sie ein einzelnes Repository für Ihren gesamten Code verwenden, aber unterschiedliche Teams zu Verzeichnissen innerhalb dieses Repositorys beitragen, können Sie Ihre Asset-Verschachtelung so einrichten, dass sie diese Struktur abbildet.

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

In diesem Diagramm könnte jedes Element unter „Core Application" als separates Asset erfasst werden, mit eigener Geschäftskritikalität (siehe: [Priorität & Risiko](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines)), eigenem RBAC sowie zugehörigen Engagements und Tests. Sie könnten weiterhin auf dem übergeordneten Asset testen und Ergebnisse speichern (zum Beispiel `webapp-backend`), aber auch isolierte Tests auf einem bestimmten untergeordneten Asset durchführen (zum Beispiel `database`).

### Pen-Tests: Isoliertes RBAC

Wenn Sie Pen-Test-Ergebnisse innerhalb eines einzelnen Assets speichern möchten, aber nicht möchten, dass Tester Asset-Daten einsehen können, können Sie für jede Testgruppe untergeordnete Assets erstellen, in die diese ihre Ergebnisse hochladen.

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

Entscheidend ist, dass ein Benutzer, dem RBAC-Zugriff auf ein einzelnes untergeordnetes Asset gewährt wird (z. B. `Pen Test Group A`), dadurch keine Befunde aus anderen untergeordneten Assets (z. B. `Pen Test Group B`) einsehen kann und auch keine Befunde im übergeordneten Asset (`webapp-frontend`) einsehen kann.

Das übergeordnete Asset könnte Engagements enthalten, die CI/CD-Ergebnisse, internes Testing, historische Daten oder andere Befunddaten darstellen, die Dritte nicht entdecken können sollen. Das Erstellen eines untergeordneten Assets für bestimmte Testergebnisse ermöglicht es Ihrem internen Team, über diese Ergebnisse in Kombination mit dem Zustand des übergeordneten Assets zu berichten.

## Assets visualisieren – Hierarchie

Sie können die Struktur der Assets in DefectDojo visualisieren und Beziehungen über die Option „Asset-Hierarchie" im Menü ändern.

![image](images/asset_hierarchy.png)

Beim Öffnen der Asset-Hierarchie wird eine filterbare Tabelle aller Ihrer Assets angezeigt. Die Auswahl eines oder mehrerer Assets aus dieser Tabelle rendert ein Hierarchiediagramm.

![image](images/asset_hierarchy_diagram.png)

### Diagrammnavigation

Mit den Symbolen oben links im Hierarchiediagramm können Sie hinein- und herauszoomen. Durch Klicken und Ziehen in diesem Diagramm können Sie darin scrollen.

Jedes Asset wird in diesem Diagramm als einzelner Knoten dargestellt, der zu Anzeigezwecken verschoben werden kann.

Assets werden über beschriftete Pfade miteinander verbunden, die die Art der Beziehung zwischen den einzelnen Knoten darstellen. Derzeit wird nur die Beschriftung `parent` unterstützt.

### Asset-Knoten erkunden

Mit jedem Asset-Knoten kann durch Klicken auf die blauen Schaltflächen interagiert werden. Diese Schaltflächen erscheinen nur, wenn ein Asset-Knoten ausgewählt ist (durch Klicken auf den Knoten).

![image](images/asset_hierarchy_node.png)

* 👁️ (Augensymbol) führt Sie direkt zur entsprechenden Asset-Ansicht (früher als Produktansicht bekannt).
* ✏️ (Stiftsymbol) öffnet ein modales Fenster mit dem Formular „Asset bearbeiten" (früher als Formular „Produkt bearbeiten" bekannt)
* ➕ (Plussymbol) ermöglicht es Ihnen, diesem Asset ein neues untergeordnetes Asset hinzuzufügen. Das Asset muss im Diagramm nicht aktuell sichtbar sein, muss aber Teil derselben Organisation sein.
* ✥ (Vier-Pfeile-Symbol) ermöglicht es Ihnen, das übergeordnete Asset des aktuell ausgewählten Assets zu ändern.
* 🗑️ (Papierkorbsymbol) ermöglicht es Ihnen, die übergeordnete Beziehung eines Assets zu entfernen. Dieses Symbol erscheint nur, wenn ein Asset bereits ein übergeordnetes Asset hat.

Wenn Ihr Diagramm ein Asset mit nicht ausgewählten übergeordneten Assets anzeigt, können Sie auf die Schaltfläche „Load More" klicken, um das Diagramm mit dem übergeordneten Asset (sowie dessen untergeordneten Assets) zu füllen.

![image](images/assets_loadmore.png)

## Notizen

* Beachten Sie, dass sich die Deduplizierungsbereiche nicht geändert haben; Assets deduplizieren Befunde nur innerhalb ihrer selbst und berücksichtigen keine Befunde in anderen Assets, unabhängig von übergeordneten/untergeordneten Beziehungen.
* Die RBAC-Bereiche haben sich in diesem System nicht geändert; jedes Asset gilt weiterhin als eigenständiges Objekt für die Zuweisung von Berechtigungen. Es wurde keine neue RBAC-Vererbung geschaffen.
  * Wenn einem Benutzer Zugriff auf eine gesamte Organisation gewährt wird, erhält dieser Benutzer weiterhin Zugriff auf alle in dieser Organisation enthaltenen Assets (wie bei Produkttypen).
  * Wenn einem Benutzer Zugriff auf ein einzelnes Asset gewährt wird, erhält dieser Benutzer dadurch keinen Zugriff auf zugehörige übergeordnete oder untergeordnete Assets und auch keinen Zugriff auf die Organisation.
* Es gibt keine Begrenzung für die Anzahl der erstellbaren übergeordneten/untergeordneten Beziehungen. Theoretisch könnten Sie die gesamte Verzeichnisstruktur eines Repositorys mit separaten Assets abbilden, wenn Sie dies wünschten.
* Zyklische Beziehungen sind nicht zulässig: Übergeordnete Assets können nicht gleichzeitig untergeordnete Assets ihrer eigenen untergeordneten Assets sein.
