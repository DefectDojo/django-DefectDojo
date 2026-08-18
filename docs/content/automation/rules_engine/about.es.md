---
title: Automatización de Rules Engine
description: Cómo trabajar con la automatización de Rules Engine
weight: 1
audience: pro
aliases:
- /es/en/customize_dojo/rules_engine
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine es una función exclusiva de DefectDojo Pro.</span>

El Rules Engine de DefectDojo permite crear flujos de trabajo personalizados y acciones masivas para gestionar Hallazgos y otros objetos.  Rules Engine permite crear acciones automatizadas que se activan cuando un objeto coincide con una Regla.

Solo se puede acceder a Rules Engine a través de la [interfaz Pro](/get_started/about/ui_pro_vs_os/).

**¿Busca el editor de grafos?** [Rules Engine 2.0](/automation/rules_engine_2/about/) construye la automatización como grafos visuales de nodos, y añade ramificaciones, acciones salientes como tickets y mensajes, rastros por ejecución y un libro de entregas. Ambos motores funcionan en paralelo, y las reglas existentes se pueden [convertir](/automation/rules_engine_2/converting_from_rules_engine/) de uno a otro.

## Enabling Rules Engine

Rules Engine está en Beta y está desactivado de forma predeterminada. Un superusuario puede activarlo desde **Settings > Feature Flags**, tanto en instancias Cloud como On-Premise. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Actualmente, las Reglas solo se pueden crear para Hallazgos, aunque en el futuro se admitirán más tipos de objetos.

Las Reglas se pueden activar manualmente desde la página **All Rules**, o programarse para ejecutarse automáticamente de forma recurrente.  Cuando una regla se activa, se aplica a todos los Hallazgos existentes que coincidan con las condiciones de filtro establecidas.

## Possible Rule Actions
Cada Regla puede aplicar uno o más de estos cambios a un Hallazgo cuando se activa correctamente (es decir, cuando coincide con las condiciones de Filtro establecidas).

### Field Modifications
* **Set a field** en un Hallazgo, incluyendo Título, Descripción, Severidad, Vector CVSSv3, Activo, Verificado, Riesgo aceptado, Falso positivo, Mitigado
* **Añadir o anteponer texto** al Título o la Descripción de un Hallazgo
* **Set Priority** — anula el valor de Prioridad calculado en un Hallazgo (anula el cálculo automático de prioridad)
* **Set Risk** — anula el nivel de Riesgo calculado en un Hallazgo (anula el cálculo automático de riesgo)
* **Sumar, restar, multiplicar o dividir** el valor de Prioridad de un Hallazgo por un número dado

### Assignments & Ownership
* **Set a User to Review** un Hallazgo
* **Assign a Group as Owners** de un Hallazgo
* **Set a Mitigation Policy** en un Hallazgo — asigna una Política de Mitigación preconfigurada al Hallazgo
* **Add to Risk Acceptance** — añade un Hallazgo a un registro de Aceptación de riesgo existente (establece risk_accepted=True, active=False, y gestiona la integración con Jira y los estados de los endpoints)

### Tags, Notes & Alerts
* **Add Tags** a un Hallazgo
* **Add a Note** a un Hallazgo
* **Create an Alert** en DefectDojo con texto personalizado

### Filter conditions
Las Reglas se activan automáticamente cuando un Hallazgo cumple condiciones de Filtro específicas. Para más información sobre los Filtros que se pueden usar para crear Acciones de Regla, consulte la página [Filter Index](/navigation/pro__filter_index).

## Creating a New Rule
Inicie este proceso desde la página New Rule.  En la [interfaz Pro](/get_started/about/ui_pro_vs_os/), en **Manage Category**, expanda el menú desplegable **Rules Engine** y haga clic en **+ New Rule**.

![image](images/rules_engine_1.png)

### Step 1: Label your Rule
Introduzca una Etiqueta como identificador de la nueva regla y haga clic en Next.

![image](images/rules_engine_2.png)

### Step 2: Set trigger conditions with a Filter
Verá una tabla All Findings.  Con la tabla All Findings, establezca las condiciones de Filtro para filtrar el conjunto de Hallazgos a los que quiere que se aplique su regla.  Para más información sobre cómo aplicar Filtros a una tabla, consulte [nuestra guía de la interfaz Pro](/get_started/about/ui_pro_vs_os/#navigational-changes).

La tabla mostrará una vista previa de la lista de Hallazgos existentes que ha filtrado.

Por ejemplo, en esta captura de pantalla estamos filtrando todos los Hallazgos que están en 'Product One'.  Una vez que aplicamos este filtro (haciendo clic fuera del menú Filters), se añadirá a nuestra lista de Filtros aplicables.

![image](images/rules_engine_3.png)

En la captura de pantalla anterior, se tomarán acciones sobre todos los Hallazgos que estén en el Producto 'Product One'.

Una vez que tenga el conjunto de Filtros que quiere aplicar, haga clic en el botón Next.

### Step 3: Set the Rule Actions
En el menú desplegable **Action**, seleccione la Acción que quiere aplicar a un Hallazgo que coincida con todos los filtros del Paso 2.  Se pueden aplicar varias Acciones.

Puede establecer Valores Condicionales adicionales que permiten tomar acciones adicionales si se cumplen ciertos criterios.

![image](images/rules_engine_4.png)


Por ejemplo, en la captura de pantalla anterior tenemos 4 Acciones de Regla establecidas.  Dos de estas acciones son Condicionales.

Todos los Hallazgos que coincidan con las condiciones de filtro activarán estas Acciones No Condicionales:

* El Hallazgo se asignará al grupo de usuarios 'Group 1'
* El Hallazgo se etiquetará con `all_group_1`

Cualquier Hallazgo que coincida con las condiciones de filtro, además de estas condiciones **adicionales**, activará estas Acciones Condicionales, sumadas a las dos Acciones No Condicionales indicadas arriba:

* **si el Hallazgo tiene Severidad Crítica**, se etiquetará con `critical_group_1`.
* **si el Hallazgo tiene Severidad Alta**, se etiquetará con `high_group_1`.

### Step 4 - Preview your Rule

La vista previa de la Regla (Rule Preview) muestra todos los Hallazgos que esta regla cambiará una vez que se ejecute, junto con una vista previa de las Acciones tomadas.  Confirme que está conforme con los cambios propuestos y haga clic en Submit para guardar su regla.

Si considera que esta regla no se aplicó correctamente, puede seleccionar el botón Back y volver a cualquiera de los pasos anteriores.

![image](images/rules_engine_5.png)

Por ejemplo, en la captura de pantalla anterior tenemos una lista de Hallazgos que se verán afectados por la Regla una vez que se ejecute.  Podemos ver que se aplicarán nuevas Etiquetas y Propietarios a cada uno de estos Hallazgos, en las columnas de la derecha de la lista de Hallazgos.

Se le pedirá de nuevo que confirme que quiere crear su Regla.  Tenga en cuenta que la **Regla no se aplicará de inmediato**, y debe activarse manualmente.

## Running a Rule
Desde la página All Rules, puede seleccionar una Regla que desee ejecutar.  Haga clic en el título de la regla para verla con más detalle.

![image](images/rules_engine_6.png)

En esta página puede ver información detallada sobre esta regla en **Metadata**, incluida información sobre cuándo se activó la regla por última vez.  También puede ver una vista previa de los Hallazgos que se verán afectados por una nueva ejecución de esta Regla, debajo de **Rule Preview**.

Para ejecutar la Regla, haga clic en el botón verde Run Rule.  Una vez que confirme que quiere ejecutar la regla, aparecerá un mensaje indicando que la regla está en cola para ejecutarse en segundo plano.

Una vez que la Regla haya terminado de ejecutarse correctamente, el número de Items Changed se actualizará en la sección Rule Metadata de la descripción de la Regla.

## Rule Metadata Reference
* **Rule For**: los objetos regidos por la Regla.
* **Rule Name**: el nombre de la Regla.
* **Filters**: el número de Filtros aplicados por esta Regla.
* **Actions**: el número de Acciones tomadas por esta Regla.
* **Owner**: el Usuario que creó esta Regla.
* **Status**: el informe de Estado de la última vez que se ejecutó esta Regla.
    'E' = 'Error', 'R' = 'Running', 'S' = 'Success'.
* **Last Run**: la marca de tiempo de la última vez que se ejecutó esta Regla.
* **Items Changed:** el número de objetos que se cambiaron en la última ejecución de la regla.
* **Items Skipped:** el número de objetos que se omitieron en la última ejecución de la regla.  Si un objeto filtrado ya coincide con el 'resultado' de una Acción de Regla aplicada a él (por ejemplo, si ya tiene las Etiquetas que aplicaría una Acción de Regla), el objeto simplemente se omitirá.
