---
title: Plazos de remediación
description: Los ajustes predefinidos de SLA de FedRAMP Rev 5 y FedRAMP VDR
weight: 4
audience: pro
---

La función incluye dos configuraciones de SLA predefinidas. Asigne cualquiera de ellas a sus productos desde la configuración de SLA, o copie una y ajústela.

## FedRAMP Rev 5

| Severity | Due within |
| --- | --- |
| Crítica | 30 días desde la detección |
| Alta | 30 días desde la detección |
| Moderada | 90 días |
| Baja | 180 días |

Los plazos se aplican de forma obligatoria, y un hallazgo incluido en el catálogo CISA KEV nunca se programa más allá de su fecha límite de CISA.

## FedRAMP VDR

Las mismas ventanas base, ajustadas de forma más estricta según la explotabilidad y la exposición:

| Condition | Due within |
| --- | --- |
| Explotable de forma creíble **y** accesible desde internet | 4 días |
| Solo explotable de forma creíble | 14 días |
| Solo accesible desde internet | 30 días |
| Ninguna de las anteriores | Las ventanas de FedRAMP Rev 5 indicadas arriba |

**Explotable de forma creíble** significa que el hallazgo está incluido en KEV, o que su puntuación EPSS es igual o superior a su umbral. **Accesible desde internet** se indica mediante una etiqueta del hallazgo — `internet-reachable` de forma predeterminada.

Todos los umbrales, nombres de etiquetas y cantidades de días se pueden editar en la configuración de SLA.

**FedRAMP VDR pasa a ser obligatorio el 7 de diciembre de 2026.** El estándar de Detección y Respuesta de Vulnerabilidades (Vulnerability Detection and Response) de FedRAMP se vuelve obligatorio para los proveedores de servicios en la nube a partir de esa fecha. Se recomienda adoptar el ajuste predefinido de VDR con anticipación.

## Relación con el registro

Los plazos de SLA determinan las fechas de finalización programadas de los elementos de POA&M, y determinan qué elementos se consideran atrasados en las métricas mensuales de una instantánea (snapshot). También determinan qué incluye una política de elementos de análisis **solo vencidos** — consulte [Compliance Profile](../compliance_profile).

Para saber cómo funcionan la prioridad y los SLA fuera de un contexto federal, consulte [Assign Priority, Risk and SLAs](/asset_modelling/pro_hierarchy/priority_sla/).
