---
title: Contribuir con parsers
description: Cómo contribuir con parsers
draft: false
weight: 1
audience: opensource
aliases:
- /es/en/open_source/contributing/how-to-write-a-parser
---

Todos los comandos asumen que se encuentra en la raíz del repositorio clonado de django-DefectDojo.

## Requisitos previos

- Ha bifurcado (forked) https://github.com/DefectDojo/django-DefectDojo y lo ha clonado localmente.
- Cambie a la rama `dev` y asegúrese de estar al día con los últimos cambios.
- Se recomienda crear una rama dedicada para su desarrollo, como `git checkout -b parser-name`.

Lo más sencillo es usar la implementación con docker compose, ya que tiene capacidad de recarga en caliente (hot-reload) para uWSGI.
Configure su entorno para usar el entorno dev:

`$ docker/setEnv.sh dev`

Consulte [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) para más detalles.

### Imágenes Docker

Querrá construir sus imágenes docker localmente, y eventualmente pasar el `uid` de su usuario local para poder escribir en la imagen (útil para los archivos de migración de la base de datos). Suponiendo que el `uid` de su usuario es `1000`, entonces:

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## ¿Qué archivos necesita modificar?

| File                                          | Purpose
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | Archivo vacío para la inicialización de la clase
|`dojo/tools/<parser_dir>/parser.py`            | Lo esencial. Aquí es donde escribe su parser real. El nombre de la clase debe ser el nombre del módulo Python sin guiones bajos más `Parser`. **Ejemplo:** Cuando el nombre del módulo Python es `dependency_check`, el nombre de la clase debe ser `DependencyCheckParser`
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | Archivos de ejemplo que contienen datos representativos para las pruebas unitarias. El conjunto mínimo.
|`unittests/tools/test_<parser_name>_parser.py` | Pruebas unitarias del parser.
|`dojo/settings/settings.dist.py`               | Si desea usar un algoritmo de deduplicación moderno basado en hashcode
|`docs/content/supported_tools/<file/api>/<parser_file>.md` | Documentación, qué tipo de formato de archivo se requiere y cómo obtenerlo


## Contrato de la fábrica (Factory)

Los parsers se cargan dinámicamente mediante un patrón de fábrica (factory). Para que su parser se cargue y funcione correctamente, debe implementar el contrato.

1. su parser **DEBE** estar en un submódulo del módulo `dojo.tools`
   - ej.: módulo `dojo.tools.my_tool.parser`
2. su parser **DEBE** ser una clase dentro de ese submódulo.
   - ej.: `dojo.tools.my_tool.parser.MyToolParser`
3. El nombre de esta clase **DEBE** ser el nombre del módulo Python sin guiones bajos y con el sufijo `Parser`.
   - ej.: `dojo.tools.my_tool.parser.MyToolParser`
4. Esta clase **DEBE** tener un constructor vacío o no tener constructor
5. Esta clase **DEBE** implementar 4 métodos:
   1. `def get_scan_types(self)` Esta función devuelve una lista de todos los *scan_type* admitidos por su parser. Estos identificadores se usan internamente. Su parser puede admitir más de un *scan_type*. Por ejemplo, algunos parsers usan un identificador distinto para modificar el comportamiento del parser (agregar, filtrar, etc...)
   2. `def get_label_for_scan_types(self, scan_type):` Esta función devuelve una cadena usada para mostrar texto en la interfaz de usuario (etiqueta corta)
   3. `def get_description_for_scan_types(self, scan_type):` Esta función devuelve una cadena usada para mostrar texto en la interfaz de usuario (descripción larga)
   4. `def get_findings(self, file, test)` Esta función devuelve una lista de hallazgos
6. Si su parser tiene más de 1 scan_type (para el modo detallado) **DEBE** implementar el método `def set_mode(self, mode)`
7. La instancia del parser se reutiliza en todas las importaciones realizadas para este scan_type, así que no almacene ningún dato a nivel de clase

Ejemplo:

```Python

class MyToolParser(object):
    def get_scan_types(self):
        return ["My Tool Scan", "My Tool Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        if scan_type == "My Tool Scan":
            return "My Tool XML Scan aggregated by ..."
        else:
            return "My Tool XML Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_findings(self, file, test):
        <...>

```

## Parsers de API

DefectDojo tiene un número limitado de parsers de API. Aunque no eliminaremos estos conectores, añadir conectores de API ha resultado problemático y, por lo tanto, no podemos aceptar nuevos parsers/conectores de API de la comunidad en este momento por razones de mantenibilidad. Para mantener un conector de API de alta calidad, es necesario contar con una licencia de la herramienta. Obtener esa licencia requiere una asociación con el autor o el proveedor. Estamos cerca de anunciar un nuevo programa para ayudar a resolver esto y traer conectores de API a DefectDojo.

## Generador de plantillas

Use el parser de [template](https://github.com/DefectDojo/cookiecutter-scanner-parser) para generar rápidamente los archivos necesarios. Para empezar, necesitará instalar [cookiecutter](https://github.com/cookiecutter/cookiecutter).

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

Luego genere su parser de escáner desde la raíz de django-DefectDojo:

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

Lea [more](https://github.com/DefectDojo/cookiecutter-scanner-parser) sobre las variables de configuración de la plantilla.

## Aspectos a los que prestar atención

Aquí tiene una lista de consideraciones que harán que el parser sea robusto tanto para los casos comunes como para los casos límite.

### No analice las URL manualmente

Usamos 2 módulos para gestionar los endpoints:
 - `hyperlink`
 - `dojo.models` con una clase específica para gestionar el procesamiento de URL para crear endpoints `Endpoint`.

Todos los parsers existentes usan el mismo código para analizar la URL y crear endpoints.
Usar `Endpoint.from_uri()` es la mejor forma de crear endpoints.
Si realmente necesita analizar una URL, use el módulo `hyperlink`.

Buen ejemplo:

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

Muy mal ejemplo:

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### Use las bibliotecas adecuadas para analizar la información
Varios formatos de archivo se gestionan mediante bibliotecas. Para mantener DefectDojo ligero y no ampliar la superficie de ataque, mantenga al mínimo el número de bibliotecas usadas y tome otros parsers como ejemplo.

#### defusedXML en lugar de lxml
Como xml es por defecto un formato inseguro, la información analizada a partir de diversas salidas xml debe analizarse de forma segura. Tras una evaluación, determinamos que defusedXML es la biblioteca que usaremos en el futuro para analizar archivos xml en los parsers, ya que esta biblioteca se considera más segura. Por lo tanto, solo aceptaremos PR con la biblioteca defusedxml.

### No todos los atributos son obligatorios

Los parsers pueden tener muchos campos, de los cuales muchos pueden ser opcionales.
Es mejor no establecer un atributo si no tiene datos, en lugar de rellenarlo con valores como `NA`, `No data` etc...

Consulte la clase `dojo.models.Finding`

### Podrían faltar datos en el informe de origen

Asegúrese siempre de incluir comprobaciones para evitar posibles errores `KeyError` (por ejemplo, cuando un campo no existe), para aquellos campos de los que no esté absolutamente seguro de que siempre estarán en el archivo que se cargará. Esto se traduce en un error 500, y no queda bien.

Buen ejemplo:

```python
   if "mykey" in data:
       finding.cwe = data["mykey"]
```

```python
   finding.cwe = data.get("mykey", 123)
```

```python
   some_list = data.get("key_of_the_list") or []
```

El último ejemplo protege contra los casos en los que `key_of_the_list` está presente, pero es `null`.


### Análisis de vectores CVSS

Los datos pueden tener vectores o puntuaciones `CVSS`. Defect Dojo usa el módulo `cvss` proporcionado por RedHat Security.
También existe un método auxiliar para validar el vector y extraer la puntuación base y la severidad a partir de él.

```python
    from dojo.utils import parse_cvss_data

    cvss_vector = <get CVSS3 or CVSS4 vector from the report>
    cvss_data = parse_cvss_data(cvss_vector)
    if cvss_data:
        finding.severity = cvss_data["severity"]
        finding.cvssv3 = cvss_data["cvssv3"]
        finding.cvssv4 = cvss_data["cvssv4"]
        # we don't set any score fields as those will be overwritten by Defect Dojo
```
No es necesario usar todos los valores, ya que los informes de escaneo suelen proporcionar su propio valor de `severity`.
Y a veces también para `cvss_score`. Defect Dojo no sobrescribirá ningún `cvss3_score` ni `cvss4_score`.
Si no se establece ninguna puntuación, Defect Dojo usará la biblioteca `cvss` para calcularla.
La respuesta también contiene la versión mayor detectada del vector CVSS en `cvss_data["major_version"]`.


Si necesita un procesamiento más manual, puede analizar el vector `CVSS` directamente.

Ejemplo de uso:

```python
    import cvss.parser
    from cvss import CVSS2, CVSS3, CVSS4

    # TEMPORARY: Use Defect Dojo implementation of `parse_cvss_from_text` white waiting for https://github.com/RedHatProductSecurity/cvss/pull/75 to be released
    vectors = cvss.parser.parse_cvss_from_text("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
        if len(vectors) > 0 and type(vectors[0]) is CVSS3:
            print(vectors[0].severities())  # this is the 3 severities

            cvssv3 = vectors[0].clean_vector()
            severity = vectors[0].severities()[0]
            vectors[0].compute_base_score()
            cvssv3_score = vectors[0].scores()[0]
            finding.severity = severity
            finding.cvssv3_score = cvssv3_score
```

No haga algo como esto:

```
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss < 9:
                return "High"
            elif cvss >= 9:
                return "Critical"
            else:
                return "Informational"
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"
```

## Algoritmo de deduplicación

Por defecto, un parser nuevo usa el algoritmo de deduplicación 'legacy' documentado en [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/)

Utilice un algoritmo de deduplicación predefinido cuando sea posible. Al usar los campos `unique_id_from_tool` o `vuln_id_from_tool` en la configuración del hash code, es importante que estos sean únicos para el hallazgo y constantes a lo largo del tiempo entre escaneos posteriores. Si no es el caso, los valores igualmente pueden ser útiles para establecerlos en el modelo del hallazgo sin usarlos para la deduplicación.
Los valores deben provenir directamente del informe y no deben ser algo calculado internamente por el parser.

## Pruebas unitarias

Cada parser debe tener pruebas unitarias, al menos para probar 0 vulnerabilidades, 1 vulnerabilidad y muchas vulnerabilidades. Puede consultar cómo lo hacen otros parsers para empezar. Cuantas más pruebas de calidad, mejor.

Es importante añadir comprobaciones sobre los atributos de los hallazgos.
Por ejemplo:

```python
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("test title", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(False, finding.duplicate)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("CVE-2020-36234", finding.vulnerability_ids[0])
            self.assertEqual(261, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
            self.assertIn("security", finding.tags)
            self.assertIn("network", finding.tags)
            self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
            self.assertEqual("TEST1", finding.vuln_id_from_tool)
```

### Use with para abrir archivos de ejemplo

Para asegurarse de que los descriptores de archivo se cierran correctamente, utilice el patrón with para abrir archivos.
En lugar de:
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

use:
```python
    with open("path_to_file.json") as testfile:
        ...
```

Esto garantiza que el archivo se cierre al final del bloque with, incluso si se produce una excepción en algún punto del bloque.

### Base de datos de pruebas

Django usa una base de datos de pruebas independiente para ejecutar las pruebas unitarias, llamada `test_defectdojo`. Se crea e inicializa automáticamente con un conjunto básico de datos de prueba.

### Ejecute sus pruebas

Este comando local lanzará la prueba unitaria de su nuevo parser

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

o de esta forma:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

Ejemplo para el parser de aqua:

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_aqua_parser.TestAquaParser -v2'
{{< /highlight >}}

o de esta forma:

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_aqua_parser.TestAquaParser
{{< /highlight >}}

Si desea ejecutar todas las pruebas unitarias de los parsers, simplemente ejecute `$ docker-compose exec uwsgi bash -c 'python manage.py test -p "test_*_parser.py" -v2'`

### Validación de endpoints

Algunos tipos de parsers crean una lista de endpoints vulnerables (se almacenan en `finding.unsaved_endpoints`). DefectDojo requiere almacenar los endpoints en un formato específico (que sigue las RFC). Los endpoints que no siguen este formato pueden almacenarse, pero se marcarán como rotos (bandera roja 🚩en la interfaz de usuario). Para asegurarse de que su parser almacena los endpoints en el formato correcto, ejecute la función `.clean()` para todos los endpoints en las pruebas unitarias

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### Pruebas de parsers de API

No solo debe probarse el parser, sino también el importador.
El método `patch` de `unittest.mock` suele ser útil para simular respuestas de API.
Se recomienda encarecidamente usarlo.

## Otros archivos que podrían verse involucrados

### Cambio en el modelo

En caso de que tenga que cambiar el modelo, por ejemplo para aumentar el tamaño de una columna de la base de datos y así admitir una cadena de datos más larga que guardar
* Cambie lo que necesite en `dojo/models.py`
* Cree un nuevo archivo de migración en dojo/db_migrations ejecutando lo siguiente e incluyéndolo como parte de su PR

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### Aceptar un tipo de archivo distinto para cargar

Si desea poder aceptar un nuevo tipo de archivo para su parser, consulte `dojo/forms.py` alrededor de la línea 436 (en el momento de escribir esto) o localice los 2 lugares (para import y re-import) donde encuentre la cadena `attrs={"accept":`.

Formatos aceptados actualmente: .xml, .csv, .nessus, .json, .html, .js, .zip.

### La necesidad de más que el simple parser.py

Por supuesto, nada le impide tener más archivos además del archivo `parser.py`. Es python :-)

## Ejemplos de pull request

Si desea consultar parsers anteriores que ahora forman parte de DefectDojo, eche un vistazo a https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed

## Actualice la documentación de la página de importación

Añada un nuevo archivo .md en [`docs/content/en/connecting_your_tools/parsers`] con los detalles de su nuevo parser.  Incluya los siguientes encabezados de contenido:

* Tipo(s) de archivo aceptable(s) - incluya cómo generar este tipo de archivo desde la herramienta relacionada, ya que algunas herramientas tienen varios métodos o requieren comandos específicos.
* Un bloque de ejemplo de prueba unitaria, si corresponde.
* Un enlace a la carpeta de pruebas unitarias correspondiente para que los usuarios puedan navegar rápidamente hasta allí desde la documentación.
* Un enlace al propio escáner - (por ejemplo, enlace de GitHub o del proveedor)

Aquí tiene un ejemplo de una página de documentación de parser completada: [https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md)
