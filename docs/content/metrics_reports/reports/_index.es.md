---
title: Generador de informes
description: Métricas de rendimiento e información
summary: ''
date: 2026-01-20 17:33:00+00:00
lastmod: 2026-01-20 17:33:00+00:00
draft: false
weight: 2
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

El Generador de informes le permite convertir los datos de DefectDojo en informes pulidos y compartibles (resúmenes ejecutivos, instantáneas de cumplimiento, paquetes POA&M, detalle de ingeniería y mucho más) para audiencias dentro y fuera de su equipo de seguridad.

## Código abierto frente a DefectDojo Pro

Cómo cree informes depende de la edición que utilice:

| | Código abierto | DefectDojo Pro |
|---|---|---|
| **Crear un informe** | Sí: se ensambla a partir de widgets | Sí: se compone a partir de Bloques reutilizables |
| **Ejecutar y obtener el resultado** | Sí (HTML, imprimir a PDF) | Sí (PDF o HTML guardado) |
| **Guardar Temas/Bloques/Plantillas reutilizables** | No: hay que reconstruir cada vez | Sí |
| **Historial persistente de informes generados** | No | Sí: listar, descargar, volver a ejecutar |
| **Automatización con API REST + LLM** | — | Sí: creación → ejecución → descarga completas |

En resumen: **código abierto** le permite crear un informe, ejecutarlo y exportar el resultado, pero no guarda plantillas ni conserva un historial de informes. **DefectDojo Pro** convierte la generación de informes en bloques de construcción reutilizables y personalizables con su marca, que puede manejar desde la interfaz, la API REST o un LLM.

## Próximos pasos

**DefectDojo Pro**

- **[Generador de informes](report-builder/)** — conceptos (Temas, Bloques, Plantillas, Informes generados) y un recorrido completo por la interfaz.
- **[Automatización de informes con la API](report-builder-api/)** — cree, ejecute, sondee y descargue informes mediante la API REST, con un script completo.
- **[Creación de informes con un LLM](report-builder-llm/)** — deje que un LLM diseñe, cree, ejecute y descargue informes por usted.

**Código abierto**

- **[Uso del Generador de informes](using-the-report-builder/)** — cree, ejecute y exporte un informe con el generador basado en widgets.
