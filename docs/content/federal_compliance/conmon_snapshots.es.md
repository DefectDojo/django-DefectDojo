---
title: Instantáneas de ConMon
description: Entregables mensuales en Excel y OSCAL de FedRAMP, y el servicio opcional
  de validación de OSCAL
weight: 3
audience: pro
---

En la pestaña **Snapshots**, **Generate Snapshot** produce los entregables de un período de reporte. Una instantánea **congela el libro mayor** en ese momento: las ediciones posteriores nunca modifican un entregable que ya generó.

![Instantáneas de ConMon generadas](images/04-poam-snapshots.png)

Cada fila muestra el período, su estado, la cantidad de ítems abiertos y atrasados, cuándo se completó, y enlaces de descarga para ambos artefactos.

## Qué genera una instantánea

Cada instantánea produce dos artefactos:

* El **libro de Excel oficial de POA&M de FedRAMP** (versión de plantilla 3.0), con los ítems abiertos, cerrados y de configuración en sus hojas correspondientes.
* Un documento **OSCAL plan-of-action-and-milestones**, fijado a OSCAL 1.0.4 — la versión que aceptan las reglas de validación vigentes de FedRAMP.

### Qué contiene la salida de OSCAL

El documento OSCAL usa el namespace de extensión de FedRAMP para los campos que buscan las herramientas de FedRAMP: los ID de POA&M, los ID de controles afectados, los estados de desviación, la dependencia de proveedor y el seguimiento de KEV.

Cada riesgo incluye:

* Facetas de probabilidad e impacto — iniciales, y ajustadas cuando se aprobó un ajuste de riesgo.
* La corrección recomendada y la remediación planificada, como respuestas separadas.
* Un registro de riesgo que documenta la detección y la última revisión de estado.

Los documentos se verifican contra el esquema oficial de NIST en el momento de la generación.

## Métricas mes a mes

Las instantáneas también calculan los números que necesita un paquete de ConMon: qué apareció, qué se resolvió, qué está atrasado y el conteo de abiertos por calificación de riesgo.

## Servicio de validación de OSCAL

Para una verificación más estricta, un despliegue puede ejecutar el **servicio de validación de OSCAL** incluido — un pequeño contenedor que envuelve la herramienta `oscal-cli` mantenida por FedRAMP.

| Validator service | What happens at generation |
| --- | --- |
| No configurado | Los documentos se validan contra el esquema JSON de NIST. La verificación más profunda se marca como **skipped**. |
| Configurado | Los documentos se validan adicionalmente mediante `oscal-cli`, y los resultados se guardan junto con la instantánea. |

Para habilitarlo, configure `DD_OSCAL_VALIDATOR_URL`, o active `oscalValidator` en el Helm chart.

**Mantenga accesible la URL de `import-ssp`.** `oscal-cli` resuelve el href de `import-ssp` durante la validación. Si su Perfil de cumplimiento indica una URL de SSP de OSCAL que el contenedor validador no puede alcanzar, la validación se aborta en lugar de omitir ese paso. Haga que la URL sea accesible desde el validador, o bien déjela sin establecer.

## Inmutabilidad

Las instantáneas y sus artefactos son inmutables por diseño. Regenerar un período produce una nueva instantánea; nunca reescribe una existente.
