---
title: Cumplimiento federal
description: Entregables de POA&M y ConMon de FedRAMP, evaluaciones de CMMC Nivel
  2 y cobertura de controles NIST 800-53
summary: ''
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
audience: pro
exclude_search: true
---

DefectDojo Pro puede encargarse del lado de gestión de vulnerabilidades de un programa de cumplimiento federal. Mantiene un Plan de Acción e Hitos (POA&M) al estilo FedRAMP para cada sistema, produce mensualmente los entregables de Monitoreo Continuo (ConMon) en los formatos oficiales Excel y OSCAL, califica autoevaluaciones de CMMC Nivel 2, y muestra qué controles de NIST 800-53 ejercitan realmente sus escáneres.

Todo lo descrito en esta sección se encuentra en la pestaña **Compliance** de un Activo.

## Habilitar la función

Federal Compliance se distribuye detrás del feature flag **Compliance**, que está en beta y desactivado de forma predeterminada. Un administrador lo activa desde el menú de feature flags; consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/). Una vez habilitado, aparece una pestaña Compliance en cada Activo.

## Beta: confirme los resultados antes de basarse en ellos

**Esta función está en beta.** Las declaraciones de control de NIST 800-171 y 800-53 incluidas, los pesos de puntos de SPRS del DoD y las reglas de elegibilidad para POA&M se proporcionan para ayudarlo a hacer seguimiento y estimar su postura, y están pendientes de validación independiente contra los documentos fuente oficiales.

Los puntajes de SPRS, los resultados de elegibilidad condicional y la cobertura de controles son **de carácter informativo**. Confírmelos con la Metodología de Evaluación oficial NIST SP 800-171 del DoD y con la guía vigente de FedRAMP antes de basarse en ellos para una certificación, el envío de una evaluación o cualquier fin contractual.

## En esta sección

| Page | What it covers |
| --- | --- |
| [Perfil de cumplimiento](compliance_profile) | Registrar un Activo como sistema y establecer los datos que aparecen en cada entregable |
| [El libro mayor de POA&M](poam_ledger) | Cómo se crean los ítems de POA&M a partir de los hallazgos, y las convenciones que sigue el libro mayor |
| [Instantáneas de ConMon](conmon_snapshots) | Entregables mensuales en Excel y OSCAL de FedRAMP, y el servicio opcional de validación de OSCAL |
| [Plazos de remediación](remediation_slas) | Los presets de SLA de FedRAMP Rev 5 y FedRAMP VDR |
| [Evaluaciones de CMMC Nivel 2](cmmc_assessments) | Calificar una autoevaluación contra NIST 800-171 Rev 2 |
| [Cobertura de controles](control_coverage) | Qué controles de 800-53 prueban sus escáneres, y las debilidades abiertas por control |
