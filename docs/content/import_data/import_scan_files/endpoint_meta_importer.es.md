---
title: Endpoint Meta Importer
description: Aplique etiquetas y campos personalizados a endpoints de forma masiva
  mediante un CSV
weight: 4
audience: opensource
---

El **Endpoint Meta Importer** le permite aplicar etiquetas y campos personalizados a grandes cantidades de endpoints a la vez mediante un archivo CSV. Esto es particularmente útil para organizaciones que ejecutan un escaneo de infraestructura intensivo, donde los endpoints necesitan metadatos flexibles para filtrar, ordenar y generar informes.

## Formato del CSV

El archivo CSV debe tener una columna `hostname` (obligatoria), además de cualquier cantidad de columnas adicionales que representen las etiquetas o los campos personalizados que desea aplicar. Cada nombre de columna adicional se convierte en la clave de la etiqueta/campo, y el valor de su fila se convierte en el valor de la etiqueta/campo.

**Ejemplo:**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

Esto aplicaría los siguientes metadatos:

| Endpoint | Tags / Custom Fields |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## Requisitos

- La columna `hostname` es **obligatoria**. Se utiliza para encontrar endpoints existentes con un host coincidente, o para crear nuevos endpoints si no se encuentra ninguna coincidencia.
- Todos los demás nombres de columna se tratan como claves de etiqueta/campo personalizado.
- Los valores se almacenan en formato `key:value`.

## Uso del Endpoint Meta Importer

El Endpoint Meta Importer está disponible en la pestaña **Endpoints** al ver un Producto. Cargue allí su archivo CSV para aplicar los metadatos a sus endpoints de forma masiva.
