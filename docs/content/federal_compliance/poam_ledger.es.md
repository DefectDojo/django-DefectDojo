---
title: El libro mayor de POA&M
description: Cómo se crean los ítems de POA&M a partir de los hallazgos, y las convenciones
  que sigue el libro mayor
weight: 2
audience: pro
---

Los ítems de POA&M se crean y actualizan automáticamente a partir de los hallazgos. La sincronización se ejecuta poco después de las importaciones y los cambios en los hallazgos, y un barrido nocturno detecta todo lo que se haya escapado. También puede agregar ítems manualmente, para debilidades que ningún escáner reporta.

![El libro mayor de POA&M](images/02-poam-items.png)

## Convenciones del libro mayor

El libro mayor sigue las convenciones de FedRAMP:

* **Numeración estable.** Cada ítem conserva un número de secuencia dentro de su sistema, y los números nunca se reutilizan.
* **Los hallazgos agrupados se consolidan.** El mismo CVE en muchos hosts se convierte en un solo ítem, con cada activo afectado listado en él.
* **Los hallazgos de configuración pueden consolidarse bajo CM-6**, en lugar de inundar el libro mayor con un ítem por cada regla de benchmark. En la captura de pantalla anterior, `V-4` es ese ítem consolidado.
* **Los ítems cerrados nunca se reabren.** Si la misma debilidad reaparece, el libro mayor abre un nuevo ítem que hace referencia al anterior, de modo que su historial de remediación permanece intacto.

## Editar un ítem

El lápiz en cualquier fila abre el ítem para editarlo.

![Edición de un ítem de POA&M](images/03-poam-item-detail.png)

Desde aquí se define el punto de contacto, los recursos necesarios y el plan de remediación, y se registra cualquier desviación.

### Desviaciones

Las desviaciones se registran como tres estados separados en cada ítem:

| Deviation | Values |
| --- | --- |
| False Positive | No, Pending, or Yes |
| Risk Adjustment | No, Pending, or Yes |
| Operational Requirement | No, Pending, or Yes |

Cada una incluye una **Deviation Rationale** compartida. Un ajuste de riesgo también registra la **Adjusted Risk Rating** junto con la original, y ambas aparecen en los entregables generados.

### Dependencias de proveedores

Los ítems pueden tener un indicador de **Vendor Dependency** y el nombre del **Vendor Product**, para debilidades que no puede remediar directamente. La fecha de su último seguimiento con el proveedor se registra junto con el ítem.

## Seguimiento de KEV

Los ítems vinculados a una Vulnerabilidad Explotada Conocida (KEV) de CISA llevan la fecha límite de KEV. Esa fecha también limita el plazo de remediación — consulte [Plazos de remediación](../remediation_slas).

## Hitos

Los hitos incluyen una descripción con fechas programadas y de finalización, y aparecen tanto en la salida de Excel como en la de OSCAL. Se gestionan mediante la API de cumplimiento en lugar del formulario del ítem.

## Agregar un ítem manualmente

Agregue un ítem para una debilidad que ningún escáner reporta. Los ítems creados manualmente se comportan como los sincronizados: toman el siguiente número de secuencia, aceptan desviaciones e hitos, y aparecen en la siguiente instantánea.

## Auditabilidad

Los ítems de POA&M, los hitos y las desviaciones están todos bajo el historial de auditoría. Cada cambio registra quién, qué y cuándo.
