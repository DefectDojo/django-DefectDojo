---
title: Peer-Review und Beanspruchung
description: Fordern Sie ein Review von bestimmten Personen an, beanspruchen Sie ein
  Review, damit andere sehen, dass es bearbeitet wird, und steuern Sie, wer angefragt
  werden darf
audience: pro
weight: 4
---

Mit Peer-Review können Sie jemanden bitten, sich einen Befund anzusehen, bevor er abgeschlossen wird. In der Benutzeroberfläche von DefectDojo Pro kann ein Review außerdem **beansprucht** werden, sodass bei mehreren berechtigten Personen für alle sichtbar ist, wer sich darum kümmert.

## Ein Review anfordern

Öffnen Sie einen Befund und wählen Sie im Befund-Menü **Request Review**, oder wählen Sie mehrere Befunde in einer Liste aus und verwenden Sie den [Bulk-Editor](../pro__bulk_edit_findings/).

Sie können ein Review von namentlich genannten Benutzern und Gruppen anfordern oder **Allow Eligible Reviewers** aktivieren, um alle für dieses Asset berechtigten Personen anzufragen.

Durch die Anforderung eines Reviews wird der Befund auf **Under Review** gesetzt, und die Reviewer werden benachrichtigt.

## Ein Review beanspruchen

Wenn ein Review von mehreren Personen angefordert wurde, kann es jede von ihnen übernehmen:

* Verwenden Sie beim Befund **Claim Review** im Befund-Menü oder die Schaltfläche im Review-Banner.
* Der Befund zeigt dann an, wer das Review hält: am Befund selbst, als Spalte **Claimed By** in Befundlisten und in der Warteschlange [My Work](/metrics_reports/dashboards/pro__my_work/) der jeweiligen Person.

Sobald ein Review beansprucht wurde:

* Nur die Person, die es hält, die Person, die es angefordert hat, oder ein Superuser kann **Clear Review** verwenden. Anderen berechtigten Reviewern wird stattdessen mitgeteilt, wer es hält.
* Der Inhaber kann es mit **Release Review** wieder freigeben; dadurch kehrt es in den Pool zurück, ohne das Review zu beenden.

Beanspruchen zwei Personen gleichzeitig, ist eine davon erfolgreich, und der anderen wird mitgeteilt, wer gewonnen hat — das Review kann immer nur von einer Person gehalten werden.

Beanspruchungen kümmern sich in einigen Fällen selbst um Dinge, die Sie sonst manuell erledigen müssten:

* Wird das Review abgeschlossen (Clear Review), wird die Beanspruchung als **completed** markiert.
* Wird der Inhaber aus der Reviewer-Liste entfernt oder der Befund geschlossen oder wiedereröffnet, wird die Beanspruchung **freigegeben** (released).
* Ein Hintergrundjob gibt Beanspruchungen frei, deren Inhaber kein angeforderter Reviewer mehr ist.

Completed und released werden getrennt erfasst, sodass sich ein abgebrochenes Review von einem abgeschlossenen unterscheiden lässt.

Das Beanspruchen wird über das [Feature-Flag](/admin/feature_flags/pro__feature_flags/) **Review Claiming** gesteuert, das standardmäßig aktiviert ist.

## Steuern, wer um ein Review gebeten werden kann

„Alle berechtigten Reviewer" bedeutet alle, die für dieses Asset über die Berechtigung **Review Findings** verfügen — nicht alle, die den Befund bearbeiten können.

Das ist wichtig, wenn Sie eine breite Sichtbarkeit, aber einen kleinen Kreis an Reviewern wünschen. Da **Review Findings** eine eigene Berechtigung ist, können Sie:

1. Eine Rolle erstellen — zum Beispiel „Security Reviewer" —, die **Review Findings** gewährt.
2. Sie den wenigen Personen zuweisen, die tatsächlich angefragt werden sollen.
3. **Review Findings** aus Ihren umfassenderen Rollen entfernen, ohne deren Zugriff auf Befunde sonst zu verändern.

Wie Sie eine Rolle erstellen, erfahren Sie unter [Custom RBAC Roles](/admin/user_management/pro__custom_rbac_roles/).

Beim Upgrade erhält jede Rolle, die Befunde bereits bearbeiten konnte, zusätzlich die Berechtigung **Review Findings**, sodass „alle berechtigten Reviewer" so lange genau das bedeutet wie zuvor, bis Sie das bewusst ändern.

## Einen Befund einer Person zuweisen

Beim Review wird jemand gebeten, sich etwas *anzusehen*. Eine Zuweisung macht jemanden *verantwortlich* und versetzt den Befund nicht in den Review-Status.

**Assignees** steht im Bearbeitungsformular des Befunds neben **Owners**. Owners ist eine Gruppe — das Team, in dessen Warteschlange der Befund gehört —, während Assignees einzelne Personen sind.

* Weisen Sie über das Bearbeitungsformular des Befunds zu, oder weisen Sie mehreren Befunden gleichzeitig über den Bulk-Editor zu.
* Im Bulk-Editor werden Assignees zu den bereits Zugewiesenen **hinzugefügt**. Aktivieren Sie **Replace existing assignees**, damit Ihre Auswahl die vollständige Liste bildet — dadurch wird jede nicht ausgewählte Person entfernt, im Extremfall alle, wenn Sie niemanden auswählen.
* Befundlisten enthalten eine Spalte **Assignees** und einen Assignee-Filter, und Berichte können ebenfalls eine Spalte **Assignees** enthalten.
* Die Zuweisungen jeder Person erscheinen in deren Warteschlange [My Work](/metrics_reports/dashboards/pro__my_work/).

Sie können einen Befund nur einer Person zuweisen, die ihn bereits sehen kann. Eine Zuweisung gewährt keinen Zugriff.

Die [Rules Engine](/automation/rules_engine/) kann Assignees automatisch setzen: Wählen Sie **Set Users** und das Feld **assignees**.

Die Zuweisung wird über das [Feature-Flag](/admin/feature_flags/pro__feature_flags/) **Work Assignment** gesteuert.
