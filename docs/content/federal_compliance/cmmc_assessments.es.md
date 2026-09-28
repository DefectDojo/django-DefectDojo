---
title: Evaluaciones de CMMC Nivel 2
description: Calificar una autoevaluación contra NIST 800-171 Rev 2
weight: 5
audience: pro
---

La pestaña Compliance puede calificar una autoevaluación de CMMC Nivel 2 contra NIST 800-171 Rev 2, usando los pesos de puntos de la Metodología de Evaluación del DoD.

![Un scorecard de evaluación de CMMC Nivel 2](images/05-cmmc-scorecard.png)

**Beta: trate el puntaje como una estimación.** Mientras esta función esté en beta, los pesos de puntos incluidos y el puntaje de SPRS resultante son de carácter informativo y están pendientes de validación. Confirme cualquier puntaje contra la Metodología de Evaluación oficial NIST SP 800-171 del DoD antes de basarse en él para el envío de una evaluación o para un fin contractual.

## Registro de resultados

Registre un resultado para cada uno de los 110 requisitos:

* **Cumplido**
* **No cumplido**
* **No aplicable**
* **Planificado** (en el POA&M)

![El flujo de trabajo de requisitos](images/06-cmmc-requirements.png)

### Crédito parcial

Algunos requisitos tienen una condición parcial documentada que la metodología puntúa con una deducción reducida en lugar del peso completo. Donde existe una, la columna **Partial Credit** permite registrarla, y el requisito deduce los puntos reducidos en su lugar. `3.13.11` es el ejemplo: se emplea cifrado, pero no validado según FIPS, y deduce 3 en lugar de 5.

Los requisitos sin una condición parcial documentada siempre deducen su peso completo.

## Qué calcula la evaluación

### Puntaje de SPRS

110 menos la deducción de cada requisito que no esté cumplido o que solo esté planificado. Los pesos son de 1, 3 o 5 puntos, por lo que los puntajes van de 110 hasta -203.

El requisito 3.12.4 (el requisito del System Security Plan) puntúa como no aplicable, según la metodología.

### Si es posible un estado condicional

CMMC permite la certificación condicional con un puntaje de al menos **88** (80 por ciento), siempre que cada brecha abierta sea elegible para un POA&M.

La metodología excluye por completo a ciertos requisitos de los POA&M. Entre los requisitos con un peso mayor a un punto, solo **3.13.11** (criptografía validada según FIPS) puede diferirse.

### El plazo de cierre

Una evaluación condicional tiene **180 días** para cerrar sus ítems de POA&M. La evaluación pasa a estado vencido si el plazo se cumple sin cerrarlos.

## Estados

Los estados pasan de **en curso** a **condicional** o **final**. Las evaluaciones condicionales muestran los días restantes de su plazo de cierre.

Las evaluaciones están bajo el historial de auditoría: cada cambio registra quién, qué y cuándo.
