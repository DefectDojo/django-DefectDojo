---
title: Migración desde Rules Engine
description: Migrar reglas existentes de Rules Engine a grafos de Rules Engine 2.0
weight: 6
audience: pro
aliases:
- /es/automation/rules_engine_v2/converting_from_rules_engine/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Rules Engine 2.0 es una función exclusiva de DefectDojo Pro.</span>

Ambos motores funcionan en paralelo. Activar Rules Engine 2.0 no cambia nada de las reglas existentes del [Rules Engine](/automation/rules_engine/about/), y no hay ningún plazo para migrarlas.

Cuando llegue el momento de migrarlas, existe un conversor. Traduce una regla de Rules Engine (un filtro más una lista ordenada de acciones) en un grafo equivalente de Rules Engine 2.0.

## Qué garantiza el conversor

**Una regla se convierte por completo o no se convierte en absoluto.** Cada conversión informa de dos tipos de resultado:

* Los **problemas** significan que la regla no se escribió. No se guarda nada parcial.
* Las **advertencias** significan que la regla se convirtió, pero algo en ella cambió de lugar y conviene revisarlo.

Nada se aproxima en silencio. Todo el valor del conversor está en que se puede confiar en una regla que se convirtió sin comentarios, y revisar a mano una que no lo hizo.

**Las reglas convertidas siempre se crean desactivadas.** Ambos motores están en funcionamiento, y que dos reglas hagan lo mismo con los mismos Hallazgos es el único resultado que un conversor nunca debe producir por su cuenta. Revise cada regla convertida y actívela de forma deliberada.

**Una regla se convierte una sola vez.** Cada regla convertida recuerda de qué regla proviene, de modo que ejecutar el conversor dos veces omite lo que ya se hizo en lugar de crear duplicados. Use la opción de sobrescritura para reemplazar deliberadamente un grafo convertido previamente.

## Ejecución del conversor

### Desde la interfaz

La lista de reglas ofrece una acción de conversión, que informa por regla qué se convirtió, qué se omitió y qué falló.

### Desde la línea de comandos

```bash
python manage.py convert_rules_to_v2
```

| Opción | Efecto |
|--------|--------|
| `--dry-run` | Imprime el grafo que produciría cada regla y no escribe nada. |
| `--rule-ids 1,2,3` | Convierte solo estas reglas. Convierte todas las reglas cuando se omite. |
| `--overwrite` | Reemplaza el grafo de una regla ya convertida y aumenta su versión, en lugar de omitirla. |
| `--activate-schedules` | También copia cada programación a su regla convertida. Desactivado de forma predeterminada. |
| `--drop-invalid-filters` | Descarta los filtros de alcance que el conjunto de filtros ya no reconoce y avisa, en lugar de hacer fallar la regla. |
| `--json` | Imprime el informe como JSON en lugar de texto. |

El comando termina con un código distinto de cero solo cuando una regla no se convierte. Las omisiones se informan, pero no son fallos.

Empiece con `--dry-run` sobre el conjunto completo para ver a qué se enfrenta, y luego convierta de verdad.

## Qué produce la conversión

| Concepto de Rules Engine | Se convierte en |
|----------------------|---------|
| El filtro de la regla | El **Alcance** del nodo disparador. |
| Una regla con una programación | Un disparador **Según una programación**. |
| Una regla sin programación | Un disparador **Ejecución manual**. |
| Cada acción, en orden | Un nodo, encadenado en el mismo orden. |
| Una acción protegida por una condición | Un nodo **Si / Filtro** delante de ese nodo. |

El vocabulario de filtros se comparte entre ambos motores, de modo que un alcance se convierte sin traducción. Eso es deliberado: es el mismo conjunto de filtros, con una sola implementación.

Los grafos convertidos se validan de la misma manera que un grafo construido a mano, incluida la configuración por nodo y los valores permitidos de cada lista desplegable. Una regla que contenga un valor de severidad o de riesgo que el producto ya haya dejado atrás se detecta en la conversión y no en tiempo de ejecución.

## Qué no se traslada

Cuatro cosas para las que hay que planificar. El conversor las informa como notas en cada ejecución.

* **El historial de ejecuciones permanece donde está.** El historial de ejecuciones existente, y sus registros afectados y omitidos, permanecen en la interfaz de Rules Engine. No se copian.
* **Las programaciones no se activan de forma predeterminada.** Una regla activada por programación se convierte, pero su programación no se copia a menos que se pase `--activate-schedules`. Esto mantiene la propiedad exclusiva de las programaciones activas en el motor original mientras ambos están en funcionamiento, de modo que una regla convertida no puede empezar a dispararse sin que se note. Cuando sí se copia una programación, la copia recibe un nombre distinto para no colisionar con la original.
* **El modelo de concurrencia es diferente.** Rules Engine tiene un único bloqueo de ejecución para toda la instancia. Rules Engine 2.0 serializa por regla, de modo que reglas distintas se ejecutan de forma concurrente. Un conjunto de reglas que antes se turnaban ahora se solaparán.
* **Una acción no tiene equivalente.** Una acción de "establecer falso positivo en falso" no se puede expresar como un nodo de Rules Engine 2.0 y debe convertirse a mano.

Una regla sin propietario asignado se convierte, con una advertencia. Recuerde que una regla sin propietario no ve ningún Hallazgo, así que asigne uno antes de activarla.

## Un orden sugerido

1. Active Rules Engine 2.0 y deje sus reglas existentes en funcionamiento.
2. Ejecute el conversor con `--dry-run` y lea el informe.
3. Convierta. Todo queda desactivado.
4. Abra cada regla convertida, revise el grafo y deje el modo en **Simulación**.
5. Active la regla convertida y déjela ejecutarse junto a la original durante un tiempo. Simulación significa que cambia los Hallazgos pero no envía nada, así que compare sus ejecuciones con lo que hacía la original.
6. Cuando esté satisfecho, desactive la regla original y cambie la convertida a **En vivo**.
7. Copie la programación al final, una vez que ya no se esté ejecutando la regla antigua.

El paso 5 es el que vale la pena no saltarse. Que ambos motores editen los mismos Hallazgos está bien para observarlo, pero usted quiere ser quien decida cuándo empiezan los envíos.
