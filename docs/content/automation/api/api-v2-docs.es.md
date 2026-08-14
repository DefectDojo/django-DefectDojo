---
title: API v2 de DefectDojo
description: La API de DefectDojo le permite automatizar tareas, por ejemplo, subir
  informes de escaneo en pipelines de CI/CD.
draft: false
weight: 2
aliases:
- /es/en/api/api-v2-docs
---

La API de DefectDojo está creada con [Django Rest
Framework](http://www.django-rest-framework.org/). La documentación de
cada endpoint está disponible en cada instalación de DefectDojo en
[`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) y se puede acceder a ella eligiendo el enlace API v2
Docs en el menú desplegable de usuario del encabezado.

![image](images/api_v2_1.png)

La documentación se genera con [drf-spectacular](https://drf-spectacular.readthedocs.io/) en [`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/), y es
interactiva. En la parte superior de la documentación de la API v2 hay un enlace que genera una especificación OpenAPI v3.

Para interactuar con la documentación, se necesita un valor de encabezado Authorization
válido. Visite la vista `/api/key-v2` para generar su
API Key (`Token <api_key>`) y copie el valor de encabezado proporcionado.

![image](images/api_v2_2.png)

Cada sección le permite realizar llamadas a la API y ver la Request
URL, el Response Body, el Response Code y los Response Headers.

![image](images/api_v2_3.png)

Si ha iniciado sesión en la interfaz web de Defect Dojo, no necesita proporcionar el token de autorización.

## Authentication

La API utiliza autenticación por encabezado con clave de API. El formato del
encabezado debe ser: :

    Authorization: Token <api.key>

Por ejemplo: :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Alternative authentication method

Si utiliza [un método de autenticación alternativo](/admin/sso/) para los usuarios, es posible que desee deshabilitar los tokens de API de DefectDojo, ya que podrían eludir su esquema de autenticación. \
Los tokens de API de DefectDojo se pueden deshabilitar especificando la variable de entorno `DD_API_TOKENS_ENABLED` en `False`.
O bien, únicamente el endpoint `api/v2/api-token-auth/` se puede deshabilitar configurando `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` en `False`.

## Sample Code

A continuación se muestran algunos ejemplos sencillos en python y los resultados que producen contra
el endpoint `/users`: :

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

Este código devolverá la lista de todos los usuarios definidos en DefectDojo.
El objeto json resultante se ve así : :

{{< highlight json >}}
    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "username": "saurabh.paz"
        }
    ]
{{< /highlight >}}

Aquí tiene otro ejemplo contra el endpoint `/users`; esta
vez filtraremos los resultados para incluir solo los usuarios cuyo nombre de
usuario incluya `jay`:

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

El objeto json resultante es: :

{{< highlight json >}}
[
    {
        "first_name": "Jay",
        "id": 22,
        "last_login": "2015-10-28T08:05:51.925743",
        "last_name": "Paz",
        "username": "jay7958"
    },
    {
        "first_name": "",
        "id": 31,
        "last_login": "2015-10-13T11:44:32.533035",
        "last_name": "",
        "username": "jay.paz"
    }
]
{{< /highlight >}}

Consulte [la documentación de Django Rest Framework sobre cómo interactuar con una
API](https://www.django-rest-framework.org/) para ver
ejemplos y consejos adicionales.

## Manually calling the API

Se pueden usar herramientas como Postman para probar la API.

Ejemplo para importar un resultado de escaneo:

-   Verbo: POST
-   URI: <http://localhost:8080/api/v2/import-scan/>
-   Pestaña Headers:

    agregue el encabezado de autenticación
    :   -   Clave: Authorization
        -   Valor: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   Pestaña Body

    -   seleccione "form-data", haga clic en "bulk edit". Ejemplo para un escaneo ZAP:

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    close_old_findings:false

-   Pestaña Body

       -   Haga clic en la edición "Key-value"
       -   Agregue un parámetro "file" de tipo "file". Esto activará
            el envío de datos de formulario multi-part para transmitir el contenido del archivo
       -   Busque el archivo para subirlo

-   Haga clic en enviar

## Clients / API Wrappers

| Wrapper                      | Estado                   | Notas |
| -----------------------------| ------------------------| ------------------------|
| [Wrapper específico para python](https://github.com/DefectDojo/defectdojo_api)      | funcional (2021-01-21)    | Wrapper de API que incluye scripts para la subida continua en CI/CD. Va un poco por detrás de las últimas funciones de la API, ya que planeamos renovar el wrapper de la API |
| [Wrapper de python para OpenAPI](https://github.com/alles-klar/defectdojo-api-v2-client)       | | solo es una prueba de concepto con la que descubrimos que la especificación OpenAPI aún no es perfecta |
| [Biblioteca Java](https://github.com/secureCodeBox/defectdojo-client-java)                 | funcional (2021-08-30)    | Creada por las amables personas de [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox) |
| [Imagen que usa la biblioteca Java](https://github.com/SDA-SE/defectdojo-client) | funcional (2021-08-30)    | |
| [Biblioteca .Net/C#](https://www.nuget.org/packages/DefectDojo.Api/)              | funcional (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | funcional (2021-08-24)    | dd-import no es directamente un wrapper de API. Ofrece algunas funciones de conveniencia para facilitar la importación de hallazgos y datos de lenguaje desde pipelines de CI/CD. |

Algunos de los wrappers de API contienen bastante lógica para facilitar el escaneo y la importación en entornos de CI/CD. Estamos en proceso de simplificar esto haciendo que la API de DefectDojo sea más inteligente (de modo que los wrappers de API o los scripts puedan ser más simples).

## API Notes

### Import / Reimport

**Reimportar** es en realidad la forma más fácil de empezar, ya que creará todas las entidades sobre la marcha si es necesario y detectará automáticamente si se trata de una primera carga o de una recarga.

## Import
La importación a través de la API se realiza mediante el endpoint [import-scan](https://demo.defectdojo.org/api/v2/doc/).

Como se describe en [Jerarquía de producto](/asset_modelling/os_hierarchy/product_hierarchy/), el Test se crea dentro de un Compromiso, dentro de un Producto, dentro de un Tipo de producto.

Una importación se puede realizar especificando los nombres de estas entidades en la solicitud a la API:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
}
```

Cuando `auto_create_context` es `True`, el producto, el compromiso y el entorno se crearán si es necesario. Asegúrese de que su usuario tenga los [permisos](/admin/user_management/about_perms_and_roles/) suficientes para hacerlo.

Una forma clásica de importar un escaneo es especificando en su lugar el ID del compromiso:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "engagement": 123,
}
```

## Reimport
La reimportación a través de la API se realiza mediante el endpoint [reimport-scan](https://demo.defectdojo.org/api/v2/doc/).

Una reimportación se puede realizar especificando los nombres de estas entidades en la solicitud a la API:


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
    "do_not_reactivate": False,
}
```

Cuando `auto_create_context` es `True`, el Tipo de producto, el Producto y el Compromiso se crearán si aún no existen. Asegúrese de que su usuario tenga los [permisos](/admin/user_management/about_perms_and_roles/) suficientes para crear un Producto/Tipo de producto.

Cuando `do_not_reactivate` es `True`, la importación/reimportación ignorará los hallazgos activos subidos y no reactivará los hallazgos previamente cerrados, aunque seguirá creando nuevos hallazgos si los hay. Se agregará una nota al hallazgo explicando que no se reactivó por ese motivo.

Una reimportación seleccionará automáticamente el test más reciente dentro del compromiso proporcionado que cumpla con el `scan_type` indicado y (opcionalmente) el `test_title` indicado.

Si no se encuentra ningún Test existente, el endpoint de reimportación usará la función de importación para importar el informe proporcionado a un nuevo Test. Esto significa que un script (de CI/CD) que use la API no necesita saber si ya existe un Test, ni si se trata de la primera carga para este Producto / Compromiso.

Una forma clásica de reimportar un escaneo es especificando en su lugar el ID del test:

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test": 123,
}
```

## Generating Reports

DefectDojo puede generar un informe de hallazgos a través de la API en formato **JSON**, **HTML**, **CSV** o **Excel**.

Un informe se genera con una solicitud `POST` a una acción `generate_report/`. El endpoint de hallazgos genera informes de toda su instancia, y la mayoría de los demás objetos exponen una acción por objeto:

| Endpoint | Alcance |
|---|---|
| `POST /api/v2/findings/generate_report/` | Cada hallazgo que tenga permiso para ver |
| `POST /api/v2/products/{id}/generate_report/` | Un producto |
| `POST /api/v2/engagements/{id}/generate_report/` | Un compromiso |
| `POST /api/v2/tests/{id}/generate_report/` | Un test |
| `POST /api/v2/product_types/{id}/generate_report/` | Un tipo de producto |
| `POST /api/v2/endpoints/{id}/generate_report/` | Un endpoint |

Los alias de objetos Pro exponen la misma acción: `/api/v2/assets/{id}/generate_report/`, `/api/v2/organizations/{id}/generate_report/`, y `/api/v2/location/{id}/generate_report/`.

### Request options

Todos los campos son opcionales: enviar un cuerpo vacío (`{}`) devuelve un informe JSON.

| Campo | Tipo | Valor predeterminado | Descripción |
|---|---|---|---|
| `report_type` | string | `JSON` | Uno de `JSON`, `HTML`, `CSV`, `Excel`. |
| `include_finding_notes` | boolean | `false` | Incluye las notas de cada hallazgo. |
| `include_finding_images` | boolean | `false` | Incluye las imágenes adjuntas a los hallazgos. |
| `include_executive_summary` | boolean | `false` | Incluye una sección de resumen ejecutivo. |
| `include_table_of_contents` | boolean | `false` | Incluye una tabla de contenidos. |

Un `report_type` no admitido (por ejemplo `PDF`) devuelve `400 Bad Request` con un error en el campo `report_type`.

### Example

Genere un informe CSV de todos los hallazgos que puede ver, y guárdelo en un archivo:

```bash
curl -X POST \
  -H "Authorization: Token <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "CSV"}' \
  https://<your-instance>/api/v2/findings/generate_report/ \
  -o findings.csv
```

### Response formats

| `report_type` | Tipo de contenido | Respuesta |
|---|---|---|
| `JSON` (predeterminado) | `application/json` | Cuerpo del informe en la respuesta |
| `HTML` | `text/html` | Página del informe renderizada |
| `CSV` | `text/csv` | Archivo adjunto |
| `Excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | Archivo adjunto `.xlsx` |

CSV y Excel se devuelven como archivos adjuntos con un encabezado `Content-Disposition`, en lugar de como un cuerpo JSON. El nombre del archivo se deriva del objeto a partir del cual se generó el informe; por ejemplo `product_1_findings.csv` o `test_42_findings.xlsx`. El endpoint `/findings/generate_report/` no está limitado a un solo objeto, por lo que sus descargas se llaman `findings.csv` y `findings.xlsx`.

### Notes and limitations

* Las opciones `include_*` solo afectan a los informes **JSON** y **HTML**. Las exportaciones **CSV** y **Excel** siempre contienen las filas de hallazgos.
* La generación de informes requiere permiso de **view** sobre los objetos implicados, y un informe solo contiene los hallazgos que usted está autorizado a ver.
* **Los filtros de parámetros de consulta estándar no se aplican a esta acción.** A diferencia de `GET /api/v2/findings/`, la acción `generate_report/` no aplica los filtros de hallazgos, por lo que una solicitud como `POST /api/v2/findings/generate_report/?severity=High` seguirá informando sobre todos los hallazgos que puede ver. Para acotar un informe, genérelo en su lugar desde un producto, compromiso o test específico.

## Asynchronous Deletion Behavior

Las eliminaciones en DefectDojo (tanto por la API como por la interfaz) se procesan de forma **asíncrona** mediante workers en segundo plano de Celery. Cuando elimina un Compromiso, un Test u otro objeto, la API o la interfaz devuelven inmediatamente una respuesta de éxito, pero la eliminación real se ejecuta en segundo plano.

Esto significa que:
- Los objetos pueden seguir apareciendo en las consultas durante un tiempo después de que se confirme la eliminación.
- Las eliminaciones en cascada (por ejemplo, eliminar un Compromiso también elimina sus Tests y Hallazgos) se procesan como una cadena de tareas en segundo plano. Los objetos hijos se eliminan en orden de dependencia: primero los Hallazgos, luego los Tests y después los Compromisos.
- En Compromisos grandes con muchos Hallazgos, este proceso puede tardar varios minutos en completarse.

No es necesario crear scripts personalizados para eliminar objetos en orden de dependencia. Una única solicitud `DELETE` sobre un Compromiso se propagará automáticamente en cascada a todos los objetos hijos. Simplemente deje tiempo para que se completen las tareas en segundo plano.

## API Pagination Limits

DefectDojo Pro impone un tamaño de página máximo de **250** resultados por solicitud a la API. Configurar `limit` por encima de 250 puede provocar errores HTTP 502 debido a tiempos de espera agotados en la consulta.

Las instancias de DefectDojo Open Source también pueden experimentar tiempos de espera agotados con tamaños de página muy grandes, según el tamaño del conjunto de datos y los recursos del servidor.

Para conjuntos de resultados grandes, use paginación con un tamaño de página de 50-250 y agregue breves demoras entre las solicitudes paginadas para evitar saturar el pool de workers.

## Large-Scale Import Best Practices

Al importar resultados de escaneo a gran escala (por ejemplo, pipelines de SBOM con miles de componentes), tenga en cuenta lo siguiente:

- **Use `background_import=true`** para payloads grandes. Las importaciones síncronas ocupan un worker de uwsgi durante toda la importación, lo que puede degradar el rendimiento para todos los usuarios.
- **Procure payloads de menos de 1 MB por importación** siempre que sea posible. Divida los SBOM grandes en archivos más pequeños por producto o grupo de componentes.
- **Agregue demoras entre llamadas consecutivas a la API** para evitar agotar el pool de workers, lo que provoca errores HTTP 502.
- **Use Reimport** (`/api/v2/reimport-scan/`) para escaneos recurrentes, de modo que se actualicen los hallazgos existentes en lugar de crear duplicados.

## Background import responses (API: `background_import`)

Una importación en segundo plano devuelve una respuesta tan pronto como se ha analizado el informe
subido, antes de que se haya escrito ningún hallazgo. Por lo tanto, su respuesta describe un trabajo
*programado*, y tiene una forma distinta a la de una importación síncrona. Esto aplica a `/api/v2/import-scan/` y
`/api/v2/reimport-scan/` siempre que `background_import` sea `true`, o siempre que el ajuste de
sistema `api_async_import` lo active para todas las importaciones.

Una respuesta en segundo plano contiene:

- `background_import` — `true`. Este es el campo sobre el que decidir el flujo.
- `status` — el estado del ciclo de vida del test en el momento en que se produjo la respuesta:
  `Processing`, `Post Processing - Deduplication`,
  `Post Processing - False Positive History`, `Processed` o `Failed`.
- `findings_parsed` — cuántos hallazgos se leyeron del informe. Es un recuento de
  análisis, no un recuento de creación: la deduplicación y las opciones de importación que
  proporcionó determinan cuántos hallazgos se escriben realmente.
- `test_id` (y `engagement_id`, `product_id`, `product_type_id`) — los identificadores a
  consultar.
- `message` — la misma información que `status` y `findings_parsed`, en forma de texto. Prefiera
  los campos estructurados.

**No** contiene `statistics`, ni tampoco contiene `deduplication_complete`.
Estas claves están ausentes en lugar de ser cero, porque en ese momento no se ha
creado ningún hallazgo, y reportar ceros describiría incorrectamente la importación. Un cliente que
lea `response["statistics"]` de forma incondicional fallará en una importación en segundo plano; lea
primero `background_import`, o use `statistics` solo en la ruta síncrona.

Para seguir una importación en segundo plano hasta su finalización, consulte el test:

```
POST /api/v2/import-scan/        (background_import=true)  -> test_id, status, findings_parsed
GET  /api/v2/tests/{test_id}/                              -> status, processing
```

Repita la solicitud `GET` hasta que `status` sea `Processed` (la importación finalizó, y los
recuentos de hallazgos del test ya son significativos) o `Failed` (la importación no se
completó). Mientras la importación se ejecuta, `processing` es `true` y `status` indica en qué
fase se encuentra. Deje unos segundos entre cada consulta; un informe grande puede pasar
varios minutos en el posprocesamiento.

Una importación síncrona (`background_import` omitido o `false`) no cambia: devuelve una
respuesta una vez que se han escrito los hallazgos, incluye `statistics`, y no incluye `status`
ni `findings_parsed`.

## Using the Scan Completion Date (API: `scan_date`) field

DefectDojo ofrece una gran variedad de informes de escáner compatibles, pero no todos contienen la
información más importante para un usuario. El campo `scan_date` es una función inteligente y flexible que
permite a los usuarios establecer la fecha de finalización de un informe de escaneo dado, y que esta se propague
a todos los hallazgos importados. Este campo **no** es obligatorio, pero el valor predeterminado para
este campo es la fecha de importación (el momento en que se procesa la solicitud y se devuelve una respuesta exitosa).

Estos son los casos de uso para este campo:

1. El informe **no** establece la fecha, y `scan_date` **no** se establece en la importación
    - La fecha del hallazgo será el valor predeterminado de `scan_date`
2. El informe **establece** la fecha, y `scan_date` **no** se establece en la importación
    - La fecha del hallazgo será la que establezca el informe
3. El informe **no** establece la fecha, y `scan_date` **se establece** en la importación
    - La fecha del hallazgo será la que el usuario haya establecido para `scan_date`
4. El informe **establece** la fecha, y `scan_date` **se establece** en la importación
    - La fecha del hallazgo será la que el usuario haya establecido para `scan_date`
