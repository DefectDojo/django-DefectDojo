---
title: Compatibilidad de versiones de CVSS
description: Qué versiones de CVSS almacena, muestra y acepta DefectDojo en los Hallazgos
weight: 1
---

DefectDojo admite metadatos de CVSS en los Hallazgos, incluido el estándar CVSS 4.0. Esta página describe qué versiones de CVSS se almacenan de extremo a extremo, dónde puede ingresarlas o verlas, y qué esperar en cuanto a la cobertura por parte de los parsers.

## Qué almacena DefectDojo

Los Hallazgos pueden llevar los siguientes datos de CVSS:

| Versión | Vector almacenado | Puntuación almacenada | Generador de vectores y calculadora en la UI |
| --- | --- | --- | --- |
| **CVSS v4.0** | ✅ | ✅ | ✅ (UI de Pro) |
| **CVSS v3 (v3.0 / v3.1)** | ✅ | ✅ | ✅ (UI de Pro) |
| **CVSS v2** | Se almacena de forma implícita a través del campo **Severity** del Hallazgo; no se almacena un campo de vector v2 independiente | N/A | N/A |

Cada Hallazgo tiene campos dedicados `cvssv3` / `cvssv3_score` y `cvssv4` / `cvssv4_score` en el modelo subyacente. Estos son accesibles tanto a través de la API como de la UI.

## Dónde ingresar datos de CVSS manualmente

Tanto CVSSv3 como CVSSv4 se pueden ingresar manualmente en un Hallazgo:

- **Formulario Edit Finding** — pegue una cadena de vector CVSS completa en el campo correspondiente. Al guardar, DefectDojo analiza el vector y calcula la puntuación automáticamente.
- **Generador de vectores (UI de Pro)** — haga clic en el botón 🛠️ junto a la entrada de CVSSv3 o CVSSv4 en el formulario Edit Finding para abrir el generador de vectores. Construya el vector de forma interactiva y luego haga clic en el botón de la calculadora para obtener una puntuación a partir del vector resultante.

> Las cadenas de vector CVSSv4 y el generador de vectores se agregaron a la UI de Pro en la v2.50.3 (22 de septiembre de 2025), y el botón explícito de la calculadora junto a él llegó en la v2.51.1 (14 de octubre de 2025).

## Configuración de visualización

La vista de Hallazgo respeta dos configuraciones del sistema que controlan si los datos de CVSSv3 y CVSSv4 se muestran a los usuarios:

- **Enable CVSS 3 Display** — muestra los vectores y las puntuaciones de CVSSv3 en los Hallazgos.
- **Enable CVSS 4 Display** — muestra los vectores y las puntuaciones de CVSSv4 en los Hallazgos.

Ambas se pueden configurar de forma independiente en System Settings. Si las dos están habilitadas, ambas versiones se muestran una junto a la otra en los Hallazgos que llevan ambos datos.

## Cobertura de parsers y herramientas

DefectDojo puede almacenar datos de CVSSv4 en cualquier Hallazgo, pero **si un parser determinado completa o no los campos de CVSSv4 depende de la herramienta de origen**:

- Si la herramienta de origen emite vectores o puntuaciones de CVSSv4 en su formato de exportación, el parser normalmente mapeará esos campos.
- Si la herramienta solo emite datos de CVSSv2 o CVSSv3, el parser no sintetizará un vector v4: no existe una conversión integrada de v3 a v4.
- Algunos parsers más antiguos pueden todavía no mapear los campos de CVSSv4 aunque la herramienta de origen los emita. Si encuentra un parser que omite los campos de CVSSv4 de una herramienta que sí los emite, informe el problema.

Mientras tanto, dos vías le dan cobertura completa de CVSSv4 sin importar el soporte del parser:

1. **[Generic Findings Import](/supported_tools/parsers/generic_findings_import/)** — acepta columnas `CVSSV4` (vector) y `CVSSV4_score` en CSV, y claves `cvssv4` / `cvssv4_score` en JSON.
2. **[Universal Parser](/import_data/pro/specialized_import/universal_parser/)** (Pro) — admite los vectores de CVSSv4 como campo asignable (agregado en la v2.57.0, 7 de abril de 2026). Úselo cuando su herramienta emita JSON o CSV con nombres de campo personalizados que los parsers integrados no mapean.

La entrada manual en el formulario Edit Finding sigue disponible como alternativa universal para cualquier herramienta o informe que no incorpore CVSSv4 automáticamente.
