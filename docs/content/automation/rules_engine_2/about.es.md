---
title: Acerca de Rules Engine 2.0
description: Qué es Rules Engine 2.0, cómo activarlo y los conceptos en los que se
  basa
weight: 1
audience: pro
aliases:
- /es/automation/rules_engine_v2/about/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 es una función exclusiva de DefectDojo Pro.</span>

Rules Engine 2.0 es un generador visual de automatizaciones. En lugar de un filtro más una lista plana de acciones, una regla es un **grafo**: un nodo disparador que decide cuándo se activa la regla, y cualquier cantidad de nodos de lógica, de Hallazgos y de salida conectados entre sí para determinar qué ocurre a continuación.

Solo se puede acceder a Rules Engine 2.0 a través de la [interfaz de Pro](/get_started/about/ui_pro_vs_os/).

## Qué aporta respecto a Rules Engine

El [Rules Engine](/automation/rules_engine/about/) original aplica una lista ordenada de acciones a cada Hallazgo que coincide con un filtro. Rules Engine 2.0 conserva esa capacidad y añade cuatro cosas:

* **Ramificación.** Un nodo **Si / Filtro** dirige los elementos por una rama verdadera y una rama falsa, de modo que una regla puede tratar los Hallazgos Críticos de forma distinta al resto sin tener que dividirse en dos reglas.
* **Salida.** Una regla puede salir de DefectDojo: abrir un issue de JIRA o un ticket en un sistema externo, publicar en Slack o Microsoft Teams, enviar un correo electrónico, llamar a un webhook, generar una alerta dentro de la aplicación o generar un informe.
* **Trazabilidad.** Cada ejecución se registra nodo por nodo como una [Ejecución](../runs/), y cada envío saliente se registra como una [Entrega](../deliveries/) que indica exactamente qué se envió, adónde fue y cómo terminó.
* **Un modo de simulación.** Una regla puede registrar con precisión lo que enviaría sin enviar realmente nada, que es la forma de probarla de manera segura antes de que llegue al mundo exterior.

Ambos motores funcionan en paralelo. Activar Rules Engine 2.0 no desactiva ni convierte las reglas existentes, y existe un [conversor](../converting_from_rules_engine/) para cuando se quiera migrarlas.

## Activación de Rules Engine 2.0

Rules Engine 2.0 está en Beta y viene desactivado de forma predeterminada. Un superusuario lo activa desde **Settings > Feature Flags**, tanto en instancias Cloud como On-Premise. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Una vez activado el indicador, aparece una sección **Rules Engine 2.0** en la barra lateral con tres páginas:

| Página | Para qué sirve |
|------|----------------|
| **All Rules** | La lista de reglas. Desde aquí se crean, editan, activan, ejecutan y eliminan reglas. |
| **Runs** | Todas las ejecuciones, con su traza por nodo. |
| **Deliveries** | El registro de todo lo que las reglas han enviado hacia el exterior. |

### Permisos

El acceso está gobernado por dos permisos de rol global, compartidos con el Rules Engine original:

* **Rule View** es necesario para ver la sección de la barra lateral y todo lo que contiene.
* **Rule Edit** es necesario para crear, modificar, ejecutar, eliminar, convertir, tomar posesión y volver a ejecutar reglas.

Rule Edit se acerca a un permiso administrativo. Un autor de reglas puede llegar a cualquier Hallazgo que el propietario de su regla pueda ver, y puede dirigir la salida hacia sistemas externos, así que debe otorgarse con criterio.

## Los conceptos

### Reglas y grafos

Una regla es un nombre, una descripción, un propietario, un modo, un interruptor de activación y un grafo. El grafo es un conjunto de **nodos** y las **aristas** entre ellos. Debe contener exactamente un nodo disparador y no debe contener ningún ciclo. Todo lo demás depende de usted, incluida la posibilidad de dejar un nodo sin conectar, lo que simplemente significa que se ejecuta sin nada sobre lo que trabajar.

Las reglas nuevas siempre se crean **desactivadas**, de modo que activar una es un acto deliberado.

### Elementos

Lo que viaja por las aristas de un grafo es un **elemento**: una instantánea JSON de un Hallazgo junto con el contexto que lo rodea.

```json
{
  "finding":      { "id": 1234, "title": "...", "severity": "High", "...": "..." },
  "test":         { "id": 12, "title": "...", "scan_type": "..." },
  "engagement":   { "id": 5,  "name": "..." },
  "product":      { "id": 3,  "name": "..." },
  "product_type": { "id": 1,  "name": "..." },
  "ctx":          { "trigger": "finding.created", "depth": 0, "source": "app" }
}
```

Las condiciones y las plantillas de mensajes se escriben contra las rutas de esa estructura, por ejemplo `finding.severity` o `product.name`. La lista completa de campos está en [Creación de reglas](../building_rules/).

### Propietario

Toda regla se ejecuta **como su propietario**. Ve exactamente los Hallazgos que ese usuario puede ver, mediante la misma autorización usada en el resto del producto. Vale la pena conocer dos consecuencias:

* Restringir el acceso del propietario de una regla restringe la regla.
* Una regla cuyo propietario tiene la cuenta eliminada no tiene propietario, por lo que no coincide con nada y no hace nada. Asigne un nuevo propietario, o use **Tomar posesión** en la lista de reglas, para recuperarla.

### Modo: Simulación o En vivo

El modo se establece por regla, no por nodo.

* **Simulación** (el valor predeterminado) ejecuta todo el grafo de verdad, incluida cada edición de Hallazgo, pero los nodos de salida registran lo que *habrían* enviado y se detienen ahí. Nada sale de DefectDojo.
* **En vivo** realiza los envíos.

Los envíos simulados también aparecen en el registro de Entregas, marcados como `simulated`, con su payload completo. Esa es la forma prevista de revisar una regla antes de dejarla salir al exterior.

El modo se aplica deliberadamente a toda la regla. Un grafo donde algunos envíos son reales y otros no lo son es más difícil de razonar que dos reglas separadas.

### Ejecuciones

Una ejecución de una regla es una [Ejecución](../runs/). Una ejecución registra el evento que la activó, su estado, su traza por nodo y cualquier error. Una regla solo puede tener una ejecución en curso a la vez, de modo que una regla ocupada se pone en cola en lugar de competir consigo misma.

### Entregas

Cada efecto secundario saliente es una fila en el registro de [Entregas](../deliveries/), escrita **antes** de que ocurra cualquier llamada de red. La fila contiene el payload, el destino resuelto, el estado, el número de reintentos y lo que haya respondido el destino. Las omisiones también se registran, de modo que "la regla no hizo nada" y "la regla no hizo nada porque el Hallazgo ya tenía un ticket" son distinguibles.

### Procedencia

Cada cambio que una regla hace a un Hallazgo se atribuye de vuelta a la regla, la ejecución y el nodo que lo realizó. Esa cronología es visible en el propio Hallazgo, de modo que se puede responder "¿por qué cambió este Hallazgo?" sin leer las definiciones de las reglas.

### Escala

Una regla procesa todo lo que coincide con su alcance. No hay límite en cuántos Hallazgos puede manejar una ejecución: los procesa en bloques para que la memoria se mantenga acotada en lugar de la cobertura. Solo la vista previa tiene un límite, y lo indica cuando lo aplica.

### Retención

Las ejecuciones y las entregas se conservan durante 180 días de forma predeterminada, y luego se depuran. El producto muestra la ventana y la fecha en la que se eliminará un registro determinado en lugar de dejarlo implícito, y ambas ventanas son configurables. Consulte [Configuración](../configuration/#retention).

## Próximos pasos

* [Creación de reglas](../building_rules/) cubre el editor, los disparadores, el alcance, las condiciones y las plantillas.
* [Referencia de nodos](../node_reference/) documenta los 25 nodos.
* [Ejecuciones](../runs/) cubre la ejecución, las trazas, el encadenamiento y los límites.
* [Entregas](../deliveries/) cubre los canales, los estados, los reintentos y la repetición de envíos.
* [Migración desde Rules Engine](../converting_from_rules_engine/) cubre la migración de reglas existentes.
* [Configuración](../configuration/) cubre los ajustes a nivel de despliegue.
