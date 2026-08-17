---
title: Feature Flags
description: Aktivieren und deaktivieren Sie optionale DefectDojo Pro-Funktionen über
  die DefectDojo-Benutzeroberfläche
weight: 1
audience: pro
---

Mit Feature Flags können Sie optionale DefectDojo Pro-Funktionen für Ihre eigene Instanz aktivieren und deaktivieren – Funktionen, die zuvor nur durch Kontaktaufnahme mit dem DefectDojo Support aktiviert werden konnten, lassen sich jetzt selbst über die Benutzeroberfläche verwalten.

Die Seite „Feature Flags" ist nur für **Superuser** sichtbar. Andere Benutzer, einschließlich Global Owners, sehen sie nicht.

## Öffnen der Seite „Feature Flags"

Gehen Sie in der linken Seitenleiste zu **Settings > Feature Flags**.

Die Seite listet jede optionale Funktion mit folgenden Angaben auf:

* **Name** — die Funktion, mit einem **BETA**-Tag, solange sie sich noch in der Beta-Phase befindet
* **Description** — was die Funktion tut
* **Documentation link** — wo es Dokumentation zu dieser Funktion gibt
* **Toggle** — ob die Funktion derzeit aktiviert ist

Verwenden Sie das Suchfeld, um die Liste nach Funktionsname oder Beschreibung zu filtern.

### Funktionen, die nicht aufgeführt werden

Die Seite listet die Funktionen auf, die Sie sich aktiv entscheiden können zu übernehmen. Zwei Arten von Funktionen fehlen darin.

**Immer aktiviert.** Sobald eine Funktion die allgemeine Verfügbarkeit erreicht, ist sie für jede Instanz aktiviert und wird nicht mehr aufgeführt, da es keine Entscheidung mehr zu treffen gibt:

* **Downstream Connectors** — siehe [Downstream Connectors](/connectors/downstream/about/)
* **Universal Parser** — siehe [Universal Parser](/import_data/pro/specialized_import/universal_parser/)
* **Asset Hierarchy** — siehe [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **Appearance** und **Feature Flags** — die beiden gleichnamigen Settings-Seiten

Für Ihre Instanz ändert sich nichts, wenn eine dieser Funktionen bereits aktiviert war. War eine deaktiviert, ist sie jetzt aktiviert: Diese Funktionen sind Teil von DefectDojo Pro und nicht mehr optional. Wenden Sie sich an den [DefectDojo Support](mailto:support@defectdojo.com), falls dies für Ihre Instanz ein Problem darstellt.

**Auf Anfrage von DefectDojo aktiviert.** Einige Funktionen hängen von einer Infrastruktur ab, die pro Instanz bereitgestellt wird, und werden daher von DefectDojo aktiviert statt über diese Seite:

* **Scheduling Service** — siehe [Scheduling Rules](/automation/rules_engine/scheduling/)

Wenden Sie sich an den [DefectDojo Support](mailto:support@defectdojo.com), um eine dieser Funktionen aktivieren zu lassen. Ist sie für Ihre Instanz bereits aktiviert, bleibt sie es.

## Eine Funktion aktivieren oder deaktivieren

1. Suchen Sie die Funktion in der Liste.
2. Klicken Sie auf ihren Toggle.
3. Die Änderung wird sofort wirksam. Andere Benutzer erhalten die Änderung beim nächsten Laden der Seite.

Bei manchen Funktionen erscheint vor der Änderung ein Bestätigungsdialog. Dies geschieht, wenn eine Funktion aktiviert wird, die mit einem Warnhinweis versehen ist (zum Beispiel weil ein Neustart erforderlich ist oder bestehende Daten betroffen sein können), oder die sich nicht mehr deaktivieren lässt.

Eine Funktion zu deaktivieren ist normalerweise einfach die Umkehrung ihrer Aktivierung. Die Ausnahmen werden unter [Wenn ein Toggle gesperrt ist](#when-a-toggle-is-locked) beschrieben.

### Organization / Asset Relabeling

**Organization / Asset Relabeling** benennt „Product Type" in „Organization" und „Product" in „Asset" um. Die Funktion ist standardmäßig aktiviert und wird wie jede andere Funktion über diese Seite umgeschaltet, aber es lohnt sich zu wissen, welche Teile von DefectDojo sie betrifft:

* Die **Pro UI** folgt diesem Toggle. Die neuen Bezeichnungen erscheinen beim nächsten Laden der Seite.
* Die Seiten der **Classic UI**, ihre URLs und generierte Berichte übernehmen ihre Benennung von der Deployment-Einstellung `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` (ebenfalls standardmäßig aktiviert), die beim Start von DefectDojo gelesen wird. Dieser Toggle ändert sie nicht, und auch ein Neustart bewirkt keine Änderung.

Der gespeicherte Toggle wurde ursprünglich aus dieser Deployment-Einstellung übernommen, daher stimmen beide überein, bis Sie eine der beiden ändern. Wenn Sie die Umbenennung hier deaktivieren und außerdem die Classic UI verwenden, setzen Sie `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False` in Ihrem Deployment und starten Sie neu, damit beide Oberflächen übereinstimmen. Wenden Sie sich bei [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) an den [DefectDojo Support](mailto:support@defectdojo.com), um die Deployment-Einstellung ändern zu lassen.

Die Funktion trägt aus diesem Grund auf der Seite „Feature Flags" das Tag **Restart Recommended**: Die außerhalb der Pro UI verwendete Benennung wird beim Start des Prozesses festgelegt. Die Umbenennung ist in jedem Fall rein kosmetisch. Datenbankmodelle, Feldnamen und API-Endpunkte bleiben unverändert, sodass bestehende Automatisierungen weiterhin funktionieren. Siehe [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/).

## Wenn ein Toggle gesperrt ist

Eine Funktion, die Sie nicht ändern können, wird mit einem Schloss-Badge angezeigt, das den Grund erklärt:

| Badge | Bedeutung | Was zu tun ist |
| --- | --- | --- |
| **Managed by DefectDojo** | DefectDojo hat diese Funktion zentral für Ihre Instanz festgelegt. Ihre Einstellung kann dies nicht überschreiben. | Wenden Sie sich an den [DefectDojo Support](mailto:support@defectdojo.com), wenn Sie eine Änderung benötigen. |
| **Unavailable on This Deployment** | Die Funktion wird für Ihren Installationstyp nicht angeboten. Siehe [Verfügbarkeit von Funktionen](#feature-availability) unten. | Nichts. Die Funktion ist für Ihre Instanz nicht relevant. |
| **Cannot Be Disabled** | Die Funktion ist bereits aktiviert und lässt sich nur in eine Richtung schalten. Es gibt keine Möglichkeit, sie rückgängig zu machen. | Nichts. Das ist so vorgesehen. |
| **Managed by deployment** | Die Funktion wird durch Ihre Deployment-Konfiguration gesteuert und nicht über diese Seite. | Siehe [DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise) unten. |

## DefectDojo Pro (Cloud)

Bei [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) genügt **Settings > Feature Flags**. Schalten Sie eine Funktion ein, und sie ist sofort aktiv.

Zwei Dinge werden von DefectDojo statt von Ihnen verwaltet:

* **Managed by DefectDojo** — die Funktion ist zentral festgelegt. Wenden Sie sich an den [DefectDojo Support](mailto:support@defectdojo.com), um sie ändern zu lassen.
* **Managed by deployment** — die Funktion ist Teil davon, wie Ihre Instanz bereitgestellt wird. Wenden Sie sich auch hierfür an den Support, da Cloud-Instanzen Kunden keine Deployment-Konfiguration zugänglich machen.

Cloud-Instanzen haben außerdem Zugriff auf Funktionen, die On-Premise nicht angeboten werden. Siehe [Verfügbarkeit von Funktionen](#feature-availability).

## DefectDojo Pro (On-Premise)

Bei [DefectDojo Pro (On-Premise)](/get_started/pro/onprem/) funktionieren die meisten Funktionen genau wie in der Cloud: Öffnen Sie **Settings > Feature Flags** und schalten Sie sie um.

Eine kleine Anzahl von Funktionen wird stattdessen aus Ihrer Deployment-Konfiguration gelesen. Sie ändern, wie die Anwendung startet, und können daher nicht zur Laufzeit umgeschaltet werden. Diese erscheinen auf der Seite schreibgeschützt, mit der Kennzeichnung **Managed by deployment**, und nennen die Umgebungsvariable, die sie steuert, zum Beispiel `DD_V3_FEATURE_LOCATIONS` für [Locations](/asset_modelling/locations/pro__locations_overview/).

Da diese Funktionen einen Neustart erfordern und sich einige davon nach der Aktivierung nicht mehr rückgängig machen lassen, prüfen Sie vor einer Änderung die jeweilige Dokumentation der Funktion. Mehrere lassen sich am besten mit Unterstützung des [DefectDojo Support](mailto:support@defectdojo.com) aktivieren.

So ändern Sie eine dieser Funktionen:

1. Setzen Sie die Umgebungsvariable in Ihrem DefectDojo-Deployment. Die Seite zeigt Ihnen an, welche Variable zu setzen ist.
2. Starten Sie DefectDojo neu, damit der neue Wert beim Start gelesen wird.
3. Laden Sie die Seite „Feature Flags" neu, um den neuen Status zu bestätigen.

Da diese Werte beim Start gelesen werden, ist eine Änderung über die Benutzeroberfläche nicht möglich, und ein Umschalten in Ihrer Umgebung ohne Neustart hat keine Wirkung.

Funktionen, die nur in der Cloud angeboten werden, erscheinen auf einer On-Premise-Instanz als **Unavailable on This Deployment**. Das ist so vorgesehen und kein Lizenzproblem.

## Verfügbarkeit von Funktionen

Die meisten Funktionen sind für beide Installationstypen verfügbar. Die Ausnahmen sind:

| Feature | Availability | How it is controlled |
| --- | --- | --- |
| Request a New Connector | Nur [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) | Seite „Feature Flags". Wird On-Premise als **Unavailable on This Deployment** angezeigt. |
| Locations | Beide | Seite „Feature Flags". Beachten Sie, dass sich Locations nach der Aktivierung nicht mehr deaktivieren lässt. Siehe [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Beide | Seite „Feature Flags" für die Pro UI; die Classic UI, ihre URLs und generierte Berichte folgen der Deployment-Einstellung `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`. Siehe [oben](#organization--asset-relabeling). |

Jede andere optionale Funktion wird sowohl in der Cloud als auch On-Premise direkt über die Seite „Feature Flags" umgeschaltet.

## Feature Flags außerhalb der Benutzeroberfläche auslesen

Sie müssen die Seite „Feature Flags" nicht öffnen, um herauszufinden, welche Funktionen aktiviert sind — der Status der Flags lässt sich auch programmgesteuert auslesen, was nützlich ist, wenn eine Automatisierung prüfen muss, ob eine Funktion verfügbar ist, bevor sie sich darauf verlässt.

```
GET /api/v2/defectdojo_information/feature_flags/
```

Dies liefert ein JSON-Array mit einem Objekt pro Feature Flag. Neben `key`, `title` und `description` des Flags meldet jedes Objekt die Werte, die eine Automatisierung meist benötigt: `effective` (ob die Funktion für diese Instanz tatsächlich aktiviert ist), `default`, `application_value` (die eigene Einstellung der Instanz oder `null`, falls nicht gesetzt), `editable` sowie `locked_reason`, falls sich ein Flag nicht ändern lässt. Aus dem Produkt entfernte Flags werden nicht aufgeführt.

Jeder **authentifizierte** Benutzer kann dies auslesen — eine Superuser-Rolle ist nicht erforderlich. Das genaue Antwortschema für Ihre Version finden Sie in der interaktiven API-Dokumentation Ihrer Instanz unter `/api/v2/oa3/swagger-ui/`, die aus dem laufenden Build generiert wird. Siehe auch die [API v2-Dokumentation](/automation/api/api-v2-docs/).

Dieselbe schreibgeschützte Auflistung wird außerdem auf der `/api/mcp/`-Oberfläche der Instanz veröffentlicht, unter `/api/mcp/defectdojo_information/feature_flags/`.

Dieser Endpunkt ist **schreibgeschützt (read-only)**. Eine Funktion zu aktivieren oder zu deaktivieren erfolgt weiterhin über die Seite „Feature Flags" oder — bei den oben genannten deployment-konfigurierten Funktionen — in Ihren Deployment-Einstellungen.

## Häufig gestellte Fragen

**Eine gewünschte Funktion steht nicht in der Liste.**
Die Liste zeigt nur optionale Funktionen. Funktionen, die immer aktiviert sind, erscheinen nicht. Falls Sie eine fehlende Funktion erwartet haben, prüfen Sie, ob Ihre Lizenz sie enthält, und wenden Sie sich dann an den [DefectDojo Support](mailto:support@defectdojo.com).

**Ich habe eine Funktion aktiviert, sehe sie aber nicht.**
Laden Sie die Seite neu — Menüeinträge und Routen werden beim Laden der Seite ausgewertet, sodass eine neu aktivierte Funktion erst beim nächsten Laden erscheint und nicht sofort in der aktuellen Ansicht.

**Ändert ein Upgrade meine Einstellungen?**
Nein. Ein Upgrade behält die aktivierten und die deaktivierten Funktionen bei.
