---
title: Ajuste de la deduplicación
description: 'Configure la deduplicación en DefectDojo Open Source: algoritmos, campos
  hash, endpoints y service'
weight: 5
audience: opensource
aliases:
- /es/en/working_with_findings/finding_deduplication/deduplication_tuning_os
- /es/en/working_with_findings/finding_deduplication/deduplication_algorithms
---

La edición Open Source de DefectDojo utiliza archivos de configuración y variables de entorno para ajustar la deduplicación.

Consulte también: [Configuración de Open Source](/get_started/open_source/configuration/) para obtener detalles sobre las variables de entorno y las anulaciones de `local_settings.py`.

## Qué puede configurar

- **Algoritmo por parser**: Elija una de las opciones Unique ID From Tool, Hash Code, Unique ID From Tool or Hash Code, o Legacy (solo en OS).
- **Campos hash por escáner**: Decida qué campos contribuyen al hash de cada parser.
- **Permitir CWE nulo**: Controle si un CWE ausente/cero es aceptable al calcular el hash.
- **Consideración de endpoints**: Opcionalmente, use endpoints para la deduplicación cuando no formen parte del hash.
- **Campos siempre incluidos**: Agregue campos (por ejemplo, `service`) a todos los hashes independientemente de la configuración por escáner.

## Configuraciones clave (se muestran los valores predeterminados)

Todos los valores predeterminados se definen en `dojo/settings/settings.dist.py`. Anúlelos mediante variables de entorno o `local_settings.py`.

### Algoritmo por parser

- Configuración: `DEDUPLICATION_ALGORITHM_PER_PARSER`
- Valores por parser: uno de `unique_id_from_tool`, `hash_code`, `unique_id_from_tool_or_hash_code`, `legacy`.
- Ejemplo (cadena JSON de variable de entorno):

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### Campos hash por escáner

- Configuración: `HASHCODE_FIELDS_PER_SCANNER`
- Ejemplo predeterminado para Trivy en OS:

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- Ejemplo de anulación (cadena JSON de variable de entorno):

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### Permitir CWE nulo por escáner

- Configuración: `HASHCODE_ALLOWS_NULL_CWE`
- Controla, por parser, si un CWE nulo/cero es aceptable al calcular el hash. Si es False y el Hallazgo tiene `cwe = 0`, el hash recurre al cálculo heredado para ese Hallazgo.

### Campos siempre incluidos en el hash

- Configuración: `HASH_CODE_FIELDS_ALWAYS`
- Predeterminado: `["service"]`
- Impacto: Se agrega al hash de todos los escáneres. Quitar `service` aquí evita que afecte a los hashes de forma generalizada.

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### Deduplicación opcional basada en endpoints

- Configuración: `DEDUPE_ALGO_ENDPOINT_FIELDS`
- Predeterminado: `["host", "path"]`
- Propósito: Si los endpoints no forman parte de los campos del hash, aún puede exigir una coincidencia mínima de endpoint para deduplicar. Si la lista está vacía `[]`, los endpoints se ignoran en la ruta de deduplicación.

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## Endpoints: cómo ajustarlos

Los endpoints pueden afectar la deduplicación mediante dos mecanismos:

1) Incluya `endpoints` en `HASHCODE_FIELDS_PER_SCANNER` para un parser. Entonces los endpoints forman parte del hash y deben coincidir exactamente según las reglas de hashing del parser.
2) Si los endpoints no están en los campos del hash, use `DEDUPLE_ALGO_ENDPOINT_FIELDS` para especificar los atributos a comparar. Ejemplos:
   - `[]`: los endpoints se ignoran para la deduplicación.
   - `["host"]`: los Hallazgos se deduplican si algún par de endpoints coincide por host.
   - `["host", "port"]`: los Hallazgos se deduplican si algún par de endpoints coincide por host Y port.

Notas:

- Para el algoritmo Legacy, los Hallazgos estáticos y dinámicos tienen reglas de coincidencia de endpoint diferentes (consulte la página de algoritmos). La configuración `DEDUPLE_ALGO_ENDPOINT_FIELDS` se aplica a la ruta de hash-code, no a la lógica intrínseca del algoritmo Legacy.
- Para la coincidencia `unique_id_from_tool` (basada en ID), los endpoints se ignoran para la decisión de deduplicación.

## Campo service: deduplicación y reimportación

- Con el valor predeterminado `HASH_CODE_FIELDS_ALWAYS = ["service"]`, el campo `service` se agrega al hash. Dos Hallazgos por lo demás iguales con valores de `service` diferentes no se deduplicarán en las rutas basadas en hash.
- Durante la importación mediante la UI/API, la entrada `Service` puede anular el service proporcionado por el parser. Cambiarlo modifica el hash y puede alterar el comportamiento de deduplicación y la coincidencia de reimportación.
- Si desea una deduplicación independiente del service, quite `service` de `HASH_CODE_FIELDS_ALWAYS` o deje vacío el campo `Service` durante la importación.

## Después de cambiar la configuración de deduplicación

Después de cambiar los algoritmos o el cálculo del Hash, deberá **recalcular los hashes** para el parser/tipo de test afectado antes de que el nuevo comportamiento de coincidencia se aplique de manera consistente en los datos existentes.

Nota: Recalcular los hashes puede provocar tiempos de espera largos en instancias grandes. Planifique las ventanas de mantenimiento en consecuencia.

- Los cambios en la configuración de deduplicación (por ejemplo, `HASHCODE_FIELDS_PER_SCANNER`, `HASH_CODE_FIELDS_ALWAYS`, `DEDUPLICATION_ALGORITHM_PER_PARSER`) no se aplican retroactivamente de forma automática. Para reevaluar los Hallazgos existentes debe ejecutar el comando de administración que se indica a continuación.

### Ejecutar dedup sobre un backlog de datos preexistentes

Cuando configura los ajustes de dedup por primera vez (o los cambia más adelante), los Hallazgos que se importaron antes del cambio conservan sus hashes anteriores hasta que vuelva a ejecutar dedup explícitamente. Use el comando de administración `dedupe` para recalcular el hash y/o reevaluar los Hallazgos existentes.

Ejecútelo dentro del contenedor uwsgi. Ejemplo (solo códigos hash, sin dedup):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

Para **recalcular los hashes y ejecutar dedup** en todos los parsers (el flujo de trabajo típico de "acabo de activar dedup y quiero limpiar el backlog"):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe"
```

Para apuntar solo a un parser específico:

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --parser 'Trivy Scan'"
```

Ayuda/uso:
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

Si envía dedup a Celery (sin `--dedupe_sync`), espere el tiempo necesario para que las tareas se completen antes de evaluar los resultados. En instancias grandes esto puede tardar un tiempo considerable; supervise los logs del worker de Celery para hacer seguimiento del progreso.

## Dónde configurar

- Prefiera las variables de entorno en los despliegues. Para desarrollo local o anulaciones avanzadas, use `local_settings.py`.
- Consulte `configuration.md` para obtener detalles sobre cómo establecer variables de entorno y configurar anulaciones locales.

### Solución de problemas

Para ayudar a solucionar problemas de deduplicación, use las siguientes herramientas:

- Observe la salida de logs en la categoría `dojo.specific-loggers.deduplication`. Este es un logger independiente de la clase que muestra detalles sobre el proceso y la configuración de deduplicación al procesar Hallazgos.
- Observe los valores de `unique_id_from_tool` y `hash_code` pasando el cursor sobre el campo `ID` o la columna `Status`:

![Unique ID from Tool and Hash Code en la página Ver Hallazgo](images/hash_code_id_field.png)

![Unique ID from Tool and Hash Code en la columna Status de la lista de Hallazgos](images/hash_code_status_column.png)
