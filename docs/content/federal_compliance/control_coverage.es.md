---
title: Cobertura de controles
description: Qué controles de 800-53 prueban sus escáneres, y las debilidades abiertas
  por control
weight: 6
audience: pro
---

La vista de cobertura de controles responde una pregunta simple: ¿qué controles de 800-53 prueban realmente mis escáneres, y dónde están las debilidades abiertas por control?

![El mapa de calor de cobertura de controles](images/07-control-coverage.png)

## De dónde provienen los mapeos

Muchos escáneres ya emiten referencias de control, y DefectDojo las extrae automáticamente en mapeos de control. Entre otros:

* **Prowler** escribe listas de controles NIST 800-53 en las referencias de los hallazgos.
* Los plugins de **Tenable** incluyen referencias cruzadas de 800-53.
* Los perfiles de **InSpec** y **MITRE SAF** etiquetan sus verificaciones con identificadores `nist`.

La extracción se basa en el catálogo importado, de modo que un identificador que el catálogo no reconoce nunca produce un mapeo.

Los hallazgos que no tienen referencias de control propias se atribuyen a los controles de escaneo predeterminados del Perfil de cumplimiento — consulte [Perfil de cumplimiento](../compliance_profile).

### Completar retroactivamente los hallazgos existentes

La extracción se ejecuta a medida que llegan los hallazgos. Para mapear hallazgos que ya se habían importado antes de habilitar la función, complételos retroactivamente:

```
manage.py extract_control_mappings --product <id>
```

Use `--all` para escanear todos los hallazgos activos en lugar de un solo producto. El comando reporta cuántos mapeos creó, y no modifica los mapeos manuales ni los suprimidos.

## Corregir un mapeo

Los mapeos que crea o corrige manualmente siempre prevalecen sobre los extraídos, y un mapeo que elimina permanece eliminado — las reimportaciones no lo revivirán.

## Qué muestra la vista

* Un **mapa de calor por familia de controles**.
* Por control, los **hallazgos abiertos mapeados a él**.

Los controles provienen de los catálogos incluidos: NIST 800-53 Rev 5 y NIST 800-171 Rev 2, ambos importados al iniciar.

**La cobertura es de carácter informativo mientras la función esté en beta.** La cobertura de controles refleja lo que reportan sus escáneres y lo que reconocen los catálogos incluidos. No constituye una certificación de que un control esté implementado o sea efectivo. Confirme la cobertura contra su System Security Plan antes de basarse en ella para una evaluación.

## Auditabilidad

Los mapeos de control están bajo el historial de auditoría. Cada cambio registra quién, qué y cuándo.
