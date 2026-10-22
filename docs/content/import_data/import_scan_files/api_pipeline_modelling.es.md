---
title: Importar desde la API
description: ''
aliases:
- /es/en/connecting_your_tools/import_scan_files/api_pipeline_modelling
---

La API de DefectDojo permite crear soluciones de canalización robustas que ingieren automáticamente nuevos escaneos en su instancia. Una automatización de este tipo puede adoptar varias formas:

* Una importación diaria que escanea su entorno todos los días y luego importa los resultados del escaneo a DefectDojo (similar a nuestra función de **Connectors**)
* Una canalización de CI/CD que escanea el código nuevo a medida que se implementa, e importa los resultados a DefectDojo como una acción desencadenada

Estas canalizaciones pueden crearse llamando directamente a nuestro endpoint de la API **/reimport** con un archivo de escaneo adjunto, de una forma muy similar a nuestro **Formulario de importación de escaneo**.

## La API de DefectDojo

La API de DefectDojo está documentada dentro de la propia aplicación mediante el framework OpenAPI. Puede acceder a esta documentación desde el Menú de usuario en la esquina superior derecha, en **'API v2 OpenAPI3'**.

\- La documentación puede utilizarse para probar llamadas a la API con distintos parámetros, y lo hace utilizando el Token de API de su propio usuario.

Si necesita acceder a un token de API para un script u otra integración, puede encontrar esa información en la opción **API v2 Token** del mismo menú.

![image](images/api_pipeline_modelling.png)

### Consideraciones generales sobre la API

* Aunque nuestra documentación de OpenAPI detalla los parámetros que pueden usarse con cada endpoint, se asume que el lector tiene un buen entendimiento de los conceptos clave de DefectDojo (Jerarquía de productos, Hallazgos, Deduplicación, etc.).
* Los usuarios que desean una integración de importación funcional pero que están menos familiarizados con DefectDojo en general deberían considerar nuestro **Universal Importer**.
* La API de DefectDojo a veces puede crear objetos de datos no deseados, particularmente si se usa 'Auto-Create Context' en el endpoint **/import** o **/reimport**.
* Afortunadamente, es muy difícil eliminar datos accidentalmente mediante la API. La mayoría de los objetos solo pueden eliminarse mediante una llamada **DELETE** dedicada al endpoint correspondiente.

### Notas específicas sobre los endpoints /import y /reimport

El endpoint **/reimport** puede utilizarse tanto para una Importación inicial como para una "Reimportación" que extiende un Test con Hallazgos adicionales. No es necesario crear primero un Test con **/import** antes de poder usar el endpoint **/reimport**. Siempre que 'Auto Create Context' esté habilitado, el endpoint /reimport puede crear un nuevo Test, Compromiso, Producto o Tipo de producto. En casi todos los casos, puede usar exclusivamente el endpoint **/reimport** al agregar datos mediante la API.

Sin embargo, el endpoint **/import** puede utilizarse en su lugar para una canalización en la que siempre desee almacenar cada resultado de escaneo en un objeto Test independiente, en lugar de usar **/reimport** para gestionar la diferencia dentro de un único objeto Test. Ambas opciones son aceptables, y el endpoint que elija dependerá de su estructura de informes, o de si necesita inspeccionar una ejecución aislada de una canalización.

### Uso del campo de fecha de finalización del escaneo (API: `scan_date`)

DefectDojo ofrece una gran variedad de informes de escáneres compatibles, pero no todos contienen la información más importante para un usuario. El campo `scan_date` es una función inteligente y flexible que permite a los usuarios establecer la fecha de finalización de un informe de escaneo determinado, y que esta se propague a todos los hallazgos importados.

Este campo **no** es obligatorio, pero su valor predeterminado es la fecha de importación (el momento en que se procesa la solicitud y se devuelve una respuesta exitosa).

Estos son los casos de uso para este campo, y los resultados aplicados al Test:

1. Si el informe **no** establece la fecha, y `scan_date` **no** se establece en la importación
    - La fecha del Hallazgo será el valor predeterminado de `scan_date`
2. Si el informe **establece** la fecha, y `scan_date` **no** se establece en la importación
    - La fecha del Hallazgo será la que establezca el informe
3. Si el informe **no** establece la fecha, y `scan_date` **se establece** en la importación
    - La fecha del Hallazgo será la que el usuario haya establecido para `scan_date`
4. Si el informe **establece** la fecha, y `scan_date` **se establece** en la importación
    - La fecha del Hallazgo será la que el usuario haya establecido para `scan_date`
