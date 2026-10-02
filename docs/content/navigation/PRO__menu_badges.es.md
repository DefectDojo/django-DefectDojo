---
title: Insignias del menú
description: Qué significan las etiquetas BETA, NEW, LEGACY y DEPRECATED en la barra
  lateral de DefectDojo Pro, y qué le pide hacer cada una
weight: 7
audience: pro
---

Las entradas de la barra lateral de DefectDojo Pro pueden llevar una pequeña etiqueta de color. Cada una responde a una pregunta distinta sobre la función junto a la que aparece, y dos de ellas son enlaces.

| Insignia | Color | Significa | Qué le pide |
| --- | --- | --- | --- |
| `NEW` | Verde | Publicado recientemente | Nada — está ahí para que note la función |
| `BETA` | Naranja | Funcional, aún en proceso de finalización; el comportamiento puede cambiar entre versiones | Pruébela, y espere algunas asperezas |
| `LEGACY` | Rojo | Reemplazada por una función más nueva, sin fecha de eliminación anunciada | Prefiera el reemplazo para trabajo nuevo |
| `DEPRECATED` | Rojo | Programada para eliminarse en una versión determinada | Migre antes de esa versión |

![The LEGACY badge on the Jira menu entry](images/menu_badge_legacy.png)

## LEGACY y DEPRECATED no son lo mismo

La distinción es deliberada, porque los dos estados requieren respuestas diferentes.

**`DEPRECATED`** significa que se ha anunciado una eliminación. Al pasar el cursor sobre la insignia se indica en qué versión desaparecerá, y al hacer clic se abre el aviso de obsolescencia:

> \<Feature\> is deprecated and will be removed by \<release\>. Click for the deprecation notice.

**`LEGACY`** significa que la función ha sido reemplazada, pero no se ha programado ninguna eliminación. Deliberadamente no hay ninguna fecha en el texto emergente, porque inventar una sería peor que no decir nada. En su lugar, nombra el reemplazo y enlaza a su documentación:

> \<Feature\> is superseded by \<replacement\> and will not receive new development. Click for its documentation.

Una función `LEGACY` sigue funcionando y sigue recibiendo correcciones. Simplemente no ganará nuevas capacidades, por lo que cualquier cosa que construya ahora es mejor construirla sobre el reemplazo.

Ambas insignias son enlaces, porque un texto emergente se cierra en el momento en que el puntero lo abandona y, por lo tanto, no puede contener un enlace en el que se pueda hacer clic. Al hacer clic en cualquiera de las insignias se abre su aviso en una pestaña nueva; no navega hacia la entrada del menú subyacente.

## Qué lleva actualmente una insignia

**`LEGACY`**

* **Connect > Jira** — la integración original de Jira por producto, reemplazada por el conector descendente para Jira. Consulte [Pro Integrations](/connectors/downstream/about/).

**`DEPRECATED`**

* **Settings > Configuration > Tool Types**
* **Settings > Configuration > Tool Configurations**

Ambas se eliminan en **3.5.0**, junto con los parsers basados en API (pull) que existen para configurarlas. Las [notas de actualización de 3.2](/releases/os_upgrading/3.2/) explican a qué migrar y para cuándo.

![DEPRECATED badges under Settings > Configuration](images/menu_badge_deprecated.png)

Cuando una etiqueta y su insignia no caben una junto a la otra en la barra lateral, la insignia pasa a su propia línea debajo de la etiqueta en lugar de truncarse.

## Relacionado

* [Notas de actualización de 3.2](/releases/os_upgrading/3.2/) — las obsolescencias actuales y su versión de eliminación
* [Feature Flags](/admin/feature_flags/pro__feature_flags/) — activar y desactivar funciones opcionales, incluidas las beta
