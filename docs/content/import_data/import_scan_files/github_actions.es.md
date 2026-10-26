---
title: Importar desde GitHub Actions
description: Importe resultados de escaneo desde un flujo de trabajo de GitHub Actions
  con la acción oficial de DefectDojo
weight: 3
---

La [acción oficial de DefectDojo](https://github.com/DefectDojo/defectdojo-action) importa un informe de escaneo a DefectDojo desde un flujo de trabajo de GitHub Actions. Funciona con DefectDojo Pro y con la edición de código abierto, y lee todos los formatos de informe que admite DefectDojo, incluido SARIF.

Cada ejecución reimporta en el mismo Test, de modo que los Hallazgos que el escáner ya no informa se cierran y cada Hallazgo conserva su historial. La acción registra en el Test la compilación, la rama, el commit y el repositorio, y puede hacer fallar el paso del flujo de trabajo cuando siguen activos Hallazgos de una severidad determinada.

## Antes de empezar

1. Cree una clave de API v2 para un usuario que pueda importar en el Activo (y crearlo, si permite que la acción cree Activos). La clave se encuentra en **API v2 Token** en el menú de usuario.
2. En el repositorio de GitHub, agregue la clave como un secreto llamado `DEFECTDOJO_API_TOKEN` en **Settings > Secrets and variables > Actions**.

## Agregar la acción a un flujo de trabajo

Ejecute su escáner y luego pase su informe a la acción:

```yaml
permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` es el nombre del formato de informe tal como lo enumera DefectDojo, por ejemplo `SARIF`, `Trivy Scan` o `Semgrep JSON Report`. Consulte [Herramientas compatibles](/supported_tools/) para ver todos los nombres.

## Dónde se guardan los Hallazgos

Si no los establece, la acción usa nombres tomados del repositorio y crea los que aún no existen:

| Objeto de DefectDojo | Valor predeterminado | Entrada |
| --- | --- | --- |
| Organización (Tipo de producto) | Propietario del repositorio | `organization-name` o `product-type-name` |
| Activo (Producto) | Nombre del repositorio | `asset-name` o `product-name` |
| Compromiso (Engagement) | Nombre de la rama | `engagement-name` |
| Test | Tipo de escaneo | `test-title` |

Cuando un Compromiso recibe varios informes del mismo tipo de escaneo, asigne a cada uno su propio `test-title` para que cada reimportación encuentre su propio Test.

### Ramas, pull requests y etiquetas

Cada rama tiene su propio Compromiso, por lo que el escaneo de un pull request nunca cierra ni reabre Hallazgos de la rama predeterminada. Los pull requests usan su rama de origen, las etiquetas usan el nombre de la etiqueta y la cola de fusión usa un Compromiso por cada rama base.

Los Compromisos que la acción crea para cualquier rama distinta de la predeterminada deduplican solo dentro de sí mismos (**Deduplicación solo dentro de este compromiso**). Sin esto, un Hallazgo visto por primera vez en una rama marcaría como duplicado la copia de la rama predeterminada. Los Compromisos de las ramas permanecen en DefectDojo después de fusionar la rama, así que ejecute la importación solo en la rama predeterminada si desea mantenerlos fuera de los recuentos del Activo.

## Hacer fallar la compilación

Establezca `fail-on` en `low`, `medium`, `high` o `critical` para que el paso falle cuando el Test tenga Hallazgos activos de esa severidad o superior después de la importación. Los duplicados no cuentan. El resumen del trabajo muestra los recuentos por severidad y un enlace al Test.

## Funciones de Pro

En DefectDojo Pro, la acción también puede:

- Enviar los nuevos Hallazgos a los Connectors configurados para el Activo (`push-to-connector: true`).
- Importar informes grandes en segundo plano (`background-import: true`). La acción espera a que el Test termine de procesarse antes de informar los recuentos o aplicar `fail-on`.
- Advertir cuando un Activo fue renombrado o movido, para que pueda actualizar los nombres en el flujo de trabajo.

En la edición de código abierto, estas entradas se omiten con una advertencia y la importación se ejecuta de todos modos. Establezca `strict: true` para que el paso falle en su lugar.

## Pull requests desde forks

GitHub no entrega secretos a los flujos de trabajo que se ejecutan en pull requests desde forks, por lo que la acción no puede autenticarse allí. Ejecute la importación en `push`, o en pull requests desde ramas del mismo repositorio. No use `pull_request_target` para sortear esta limitación: se ejecuta con sus secretos mientras descarga código que usted no controla.

## Todas las entradas y salidas

El [README de la acción](https://github.com/DefectDojo/defectdojo-action#inputs) enumera todas las entradas y salidas. La mayoría de las entradas coinciden con un campo del endpoint **/reimport** descrito en [Importar desde la API](/import_data/import_scan_files/api_pipeline_modelling/).
