---
title: Importar desde GitHub Actions
description: Importe los resultados de un escaneo desde un flujo de trabajo de GitHub
  Actions con la acción oficial de DefectDojo
weight: 3
---

La [acción de DefectDojo](https://github.com/DefectDojo/defectdojo-action) oficial importa un informe de escaneo en DefectDojo desde un flujo de trabajo de GitHub Actions. Funciona con DefectDojo Pro y con la edición Open Source, y lee todos los formatos de informe que DefectDojo admite, incluido SARIF.

Cada ejecución reimporta en el mismo Test, de modo que los Hallazgos que el escáner ya no informa se cierran y cada Hallazgo conserva su historial. La acción registra la compilación, la rama, el commit y el repositorio en el Test, y puede hacer fallar el paso del flujo de trabajo cuando siguen activos Hallazgos con una severidad determinada.

## Antes de comenzar

1. Cree una clave de API v2 para un usuario que pueda importar en el Asset (y crearlo, si permite que la acción cree Assets). La clave se encuentra en **API v2 Token** en el menú de usuario (**API v2 Key** en la interfaz de Open Source).
2. En el repositorio de GitHub, agregue la clave como un secreto llamado `DEFECTDOJO_API_TOKEN` en **Settings > Secrets and variables > Actions**.

## Agregar la acción a un flujo de trabajo

Ejecute su escáner y luego pase su informe a la acción:

```yaml
name: Security scan
on:
  push:
    branches: [main]
  pull_request:

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

`scan-type` es el nombre del formato de informe tal como DefectDojo lo muestra, por ejemplo `SARIF`, `Trivy Scan` o `Semgrep JSON Report`. Consulte [Herramientas compatibles](/supported_tools/) para ver todos los nombres.

## Adónde van los Hallazgos

Si no los define, la acción usa nombres tomados del repositorio y crea los que aún no existen:

| Objeto de DefectDojo | Valor predeterminado | Entrada |
| --- | --- | --- |
| Organización (Tipo de producto) | Propietario del repositorio | `organization-name` o `product-type-name` |
| Asset (Producto) | Nombre del repositorio | `asset-name` o `product-name` |
| Compromiso | Nombre de la rama | `engagement-name` |
| Test | Tipo de escaneo | `test-title` |

Cuando un Compromiso recibe varios informes del mismo tipo de escaneo, asigne a cada uno su propio `test-title` para que cada reimportación encuentre su propio Test.

### Ramas, pull requests y etiquetas

Cada rama obtiene su propio Compromiso, por lo que el escaneo de un pull request nunca cierra ni reabre Hallazgos de la rama predeterminada. Los pull requests usan su rama de origen, las etiquetas usan el nombre de la etiqueta, y la cola de fusión usa un Compromiso por rama base.

Los Compromisos que la acción crea para cualquier rama distinta de la predeterminada deduplican solo dentro de sí mismos (**Deduplicación solo dentro de este compromiso**). Sin eso, un Hallazgo visto por primera vez en una rama marcaría como duplicado la copia de la rama predeterminada. Si usted define `engagement-name` o `deduplication-on-engagement`, esto se desactiva, de modo que un Compromiso al que usted ponga nombre deduplica en todo el Asset como de costumbre. Los Compromisos de rama permanecen en DefectDojo después de fusionar la rama, así que ejecute la importación solo en la rama predeterminada si desea mantenerlos fuera de los recuentos del Asset.

## Hacer fallar la compilación

Configure `fail-on` en `low`, `medium`, `high` o `critical` para que el paso falle cuando el Test tenga Hallazgos activos con esa severidad o una superior después de la importación. Los duplicados no cuentan. El resumen del trabajo muestra los recuentos por severidad y un enlace al Test.

## Funciones de Pro

En DefectDojo Pro, la acción también puede:

- Enviar los nuevos Hallazgos a los Connectors configurados para el Asset (`push-to-connector: true`).
- Importar informes grandes en segundo plano (`background-import: true`). La acción espera hasta que el Test termine de procesarse antes de informar los recuentos o aplicar `fail-on`.
- Advertir cuando un Asset fue renombrado o movido, para que pueda actualizar los nombres en el flujo de trabajo.

En la edición Open Source, `push-to-connector` y `background-import` se omiten con una advertencia, y la importación se ejecuta de todos modos. Configure `strict: true` para que el paso falle en su lugar.

## Pull requests desde forks

GitHub no entrega secretos a los flujos de trabajo que se ejecutan en pull requests desde forks, por lo que la acción no puede autenticarse allí y el paso falla. Ejecute la importación en `push`, o sáltela en los pull requests desde forks:

```yaml
      - name: Import into DefectDojo
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: DefectDojo/defectdojo-action@v1
```

No use `pull_request_target` para sortear esto: se ejecuta con sus secretos mientras descarga código que usted no controla.

## Todas las entradas y salidas

El [README de la acción](https://github.com/DefectDojo/defectdojo-action#inputs) enumera todas las entradas y salidas. La mayoría de las entradas se corresponden con un campo del endpoint **/reimport** descrito en [Importar desde la API](/import_data/import_scan_files/api_pipeline_modelling/).
