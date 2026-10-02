---
title: Perfil de cumplimiento
description: Registrar un Activo como sistema y establecer los datos que aparecen
  en cada entregable
weight: 1
audience: pro
---

El Perfil de cumplimiento registra un Activo como sistema y contiene los datos que aparecen en cada entregable que produce. Abra el Activo que representa el límite de su sistema, vaya a la pestaña **Compliance** y luego a **Profile**.

![El formulario de Perfil de cumplimiento](images/01-compliance-profile.png)

## Campos del perfil

| Field | What it does |
| --- | --- |
| **Enabled** | Activa el seguimiento de cumplimiento para este producto. |
| **Automatic Sync** | Mantiene los ítems de POA&M sincronizados con los hallazgos. |
| **POA&M ID Prefix** | Numeración de ítems. Obligatorio. Los ítems se numeran `V-1`, `V-2`, y así sucesivamente de forma predeterminada. |
| **Impact Level** | LI-SaaS, Low, Moderate o High. |
| **Cloud Service Provider** | El nombre del CSP, tal como debe aparecer en los datos de portada del POA&M. |
| **System / Offering Name** | El nombre del sistema, tal como debe aparecer en los datos de portada del POA&M. |
| **FedRAMP System Identifier** | El identificador de su sistema, por ejemplo `F00000042`. |
| **Default Point of Contact** | El POC que se aplica a los ítems que no tienen uno propio. |
| **Scan Item Policy** | Incluir todos los ítems abiertos, o solo los ítems de escaneo vencidos. |
| **OSCAL SSP Reference** | Opcional. Cuando se establece, los POA&M de OSCAL generados lo referencian mediante `import-ssp`. |

### Elegir una política de ítems de escaneo

Solo vencidos es el mínimo exigido por ConMon de FedRAMP. **Include all open items** es la opción más conservadora, y es la predeterminada.

## Guardar y sincronizar

**Save Compliance Profile** registra el Activo. El libro mayor de POA&M luego se completa a partir de los hallazgos existentes del Activo, y el resto de la pestaña Compliance queda disponible.

Con **Automatic Sync** activada, el libro mayor se mantiene actualizado por sí solo — consulte [El libro mayor de POA&M](../poam_ledger). **Sync POA&M Now** ejecuta una sincronización de inmediato, lo cual es útil justo después de cambiar el perfil o importar un nuevo escaneo.

## Configuraciones disponibles solo mediante la API

Dos configuraciones del perfil no están en el formulario y se establecen mediante la API de cumplimiento:

* **Default scan controls** — los controles atribuidos a los hallazgos de escáneres que no tienen un mapeo de control propio. `RA-5` es la opción habitual para los resultados de escaneo de vulnerabilidades. Los hallazgos que *sí* tienen sus propias referencias de control se mapean a partir de esas en su lugar; consulte [Cobertura de controles](../control_coverage).
* **Configuration test types** — los tipos de test cuyos hallazgos se tratan como ítems de configuración, lo cual impulsa la consolidación de CM-6 en el libro mayor.

## Auditabilidad

Los perfiles de cumplimiento están bajo el historial de auditoría: cada cambio registra quién cambió qué, y cuándo.
