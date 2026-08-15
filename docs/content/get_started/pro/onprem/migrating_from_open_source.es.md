---
title: Migración de código abierto a DefectDojo Pro autoalojado
description: Traslade la base de datos y los archivos multimedia de su DefectDojo
  de código abierto a una implementación autoalojada de DefectDojo Pro
draft: false
weight: 6
audience: pro
---

Esta página describe cómo trasladar los datos de una instancia de DefectDojo de código abierto a una implementación autoalojada de DefectDojo Pro.

Los ejemplos usan Amazon Web Services, ya sea con Docker Compose en EC2 o Kubernetes en EKS, y la base de datos en Amazon RDS para PostgreSQL. Esa es la combinación con la que se validó este procedimiento. La misma secuencia se aplica a otros proveedores que ofrecen PostgreSQL gestionado y cómputo equivalente, y a hardware on-premise, cambiando los comandos específicos del proveedor según corresponda.

Como usted aloja la implementación, sus datos permanecen dentro de su propio entorno durante toda la migración. Usted ejecuta la exportación y la restauración, y el equipo de soporte de DefectDojo puede ayudarlo en cualquier paso. Si su instancia de DefectDojo Pro está alojada en la nube por DefectDojo en lugar de ser autoalojada, contacte en su lugar a [support@defectdojo.com](mailto:support@defectdojo.com), porque el equipo de DefectDojo realiza la restauración por usted.

En términos generales, usted exporta la base de datos y los archivos multimedia de la instancia de código abierto, los restaura en la base de datos y el almacenamiento que usa su implementación de Pro, apunta Pro hacia la base de datos restaurada y luego valida el resultado.

## Antes de empezar

Confirme lo siguiente antes de exportar nada.

Su motor de base de datos. DefectDojo admite PostgreSQL. El soporte de MySQL quedó obsoleto y luego se [eliminó en la versión 2.37.0](/releases/os_upgrading/2.37/), por lo que una instancia antigua que todavía use MySQL debe convertirse a PostgreSQL antes de poder migrarla. Contacte a soporte si este es su caso.

Dónde se ejecuta su base de datos. Puede ser un contenedor de la configuración predeterminada de Docker Compose, o un servicio independiente en el mismo host, en otra VM, o en un servicio gestionado como Amazon RDS o Cloud SQL. El comando de exportación varía según cuál de los dos sea.

Su versión de código abierto. Encuéntrela en el pie de página de la interfaz, o a partir de las etiquetas de su implementación y las versiones de imagen. Todas las versiones 2.x se pueden migrar con este procedimiento. Si está ejecutando 3.0.0, 3.0.1, 3.0.2 o 3.0.100, actualice a [3.0.200](/releases/os_upgrading/3.0.200/) o posterior antes de empezar. Revise las [notas de actualización](/releases/os_upgrading/upgrading_guide/) de cada versión entre su versión actual y la versión a la que actualiza.

Alineación de versiones. Su versión de código abierto debe coincidir, o estar lo más cerca posible, con la versión de DefectDojo Pro a la que está migrando. En el primer inicio, Pro ejecuta las migraciones de base de datos que llevan el esquema a su propia versión, por lo que una diferencia de versión grande aumenta el riesgo de una migración larga o fallida. Alinee las versiones antes de generar el volcado.

Su base de datos de destino. Aprovisione una versión principal de PostgreSQL actualmente compatible, 16 o posterior, y nunca anterior a la versión que ejecuta su instancia de código abierto, porque un volcado no se puede restaurar en una versión principal anterior. En AWS, coloque la instancia de RDS en la misma VPC que su cómputo de Pro y permita el tráfico entrante en el puerto 5432 desde el host desde el que restaura.

Su host de restauración. Necesita una máquina en la misma red que la base de datos, con las herramientas cliente de PostgreSQL `pg_restore` y `psql` instaladas. En AWS, use una instancia de EC2 en la misma VPC, idealmente en la misma zona de disponibilidad que la instancia de RDS.

Espacio libre en disco. El servidor de origen necesita espacio para el volcado de la base de datos y el archivo multimedia comprimido antes de moverlos.

## Paso 1: exporte su base de datos

La configuración predeterminada de Docker Compose usa `defectdojo` tanto para el nombre de usuario de la base de datos como para el nombre de la base de datos. Estos se pueden sobrescribir, así que verifique el valor de `DD_DATABASE_URL` en su archivo `docker-compose.yml` o `.env`. La cadena de conexión predeterminada es:

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

En los comandos siguientes, reemplace `<db_username>`, `<database_name>` y `<postgres_container_name>` con sus propios valores. Encuentre el nombre del contenedor con `docker ps`.

Se recomienda un volcado comprimido en formato personalizado (custom). `pg_restore` puede cargarlo directamente, y evita la mayoría de los problemas de propiedad y roles que surgen al restaurar en una base de datos gestionada.

Para un PostgreSQL en contenedor, que es la configuración predeterminada de Docker Compose:

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Si la base de datos requiere una contraseña, pásela en el entorno:

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Para un PostgreSQL externo o remoto, como una VM independiente, Amazon RDS o Cloud SQL:

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Un volcado SQL en texto plano, generado omitiendo `-Fc`, también funciona. Suele incluir sentencias `CREATE ROLE`, `ALTER ROLE` y `CREATE DATABASE` que una base de datos gestionada rechazará, así que consulte la nota del Paso 4 si usa uno.

## Paso 2: exporte sus archivos multimedia

DefectDojo almacena artefactos cargados, como capturas de pantalla, modelos de amenazas y documentos de aceptación de riesgo, en un directorio multimedia. DefectDojo de código abierto no conserva en disco los archivos de escaneo usados para la importación y reimportación, ya que se descartan una vez analizados, por lo que el directorio multimedia contiene únicamente los artefactos cargados por el usuario.

La ubicación del directorio depende de cómo haya implementado:

| Método de implementación | Ruta multimedia típica |
| --- | --- |
| Docker Compose | Volumen con nombre `defectdojo_media`, montado en `/app/media` |
| Bare metal | `/opt/dojo/media`, o la ruta definida en `DD_MEDIA_ROOT` |
| Kubernetes | Volumen persistente montado en `/app/media` |

Comprima el directorio en un único archivo. Desde un volumen con nombre:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

Desde una ruta en disco:

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## Paso 3: nombre sus archivos

Incluya su versión de código abierto en ambos nombres de archivo para que la versión en juego sea inequívoca durante la restauración. Para una instancia que ejecuta 2.38.1:

| Archivo | Renombrado a |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

Mueva ambos archivos a su host de restauración. Puede copiarlos directamente con una herramienta como `scp`, o almacenarlos temporalmente en un almacenamiento de objetos privado en su propia cuenta y descargarlos al host de restauración. En AWS eso significa un bucket de S3 privado y `aws s3 cp`. De cualquier forma, los datos permanecen dentro de su propio entorno.

## Paso 4: restaure la base de datos

Ejecute la restauración desde su host de restauración, apuntando al endpoint de la base de datos. Los servicios de PostgreSQL gestionado difieren en lo que admiten aquí. Amazon RDS no ofrece una importación en un solo paso de un archivo de volcado desde un bucket, por lo que la vía admitida es un `pg_restore` del lado del cliente.

1. Cree la base de datos y el rol de la aplicación. Conéctese como su usuario maestro y cree la base de datos de destino y el rol que espera el volcado. Los valores predeterminados son `defectdojo` para ambos, así que use sus propios valores si los sobrescribió.

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. Restaure el volcado. Para un volcado en formato personalizado, use `--no-owner` y `--no-privileges` para que la restauración no intente reasignar la propiedad a roles que no existen en el destino. Una base de datos gestionada no otorga un verdadero superusuario, así que una restauración que intente hacer esto fallará.

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

Para un volcado SQL en texto plano, primero comente o elimine cualquier sentencia `CREATE ROLE`, `ALTER ROLE`, `CREATE DATABASE` y `ALTER DATABASE ... OWNER`, y luego cárguelo:

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

Si la restauración reporta errores, capture la salida y contacte a soporte antes de eliminar nada más del volcado. Quitar demasiado puede dejar la base de datos en un estado inconsistente que es más difícil de diagnosticar que el error original.

## Paso 5: restaure sus archivos multimedia

Coloque el contenido del archivo multimedia en el lugar desde donde su implementación de Pro lee los archivos cargados. La aplicación los busca en `/app/media`, que su implementación respalda mediante un bind mount o un volumen persistente. Consulte la documentación de instalación suministrada con su licencia para conocer la ruta de host o el volumen que usa su implementación.

Para una implementación de Docker Compose respaldada por un volumen con nombre:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

Para una implementación de Kubernetes, extraiga el archivo localmente y cópielo al pod de Django, que escribe en el persistent volume claim montado en `/app/media`:

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## Paso 6: apunte DefectDojo Pro hacia la base de datos restaurada

Actualice la conexión de base de datos para que Pro use la base de datos que acaba de restaurar, y luego inicie la aplicación. En el primer inicio, Pro ejecuta las migraciones de base de datos que actualizan el esquema desde su versión de código abierto hasta la versión de Pro. Según el tamaño de su base de datos y la magnitud de la diferencia de versión, esto puede tardar un tiempo, y la aplicación no estará disponible hasta que finalice.

Para implementaciones de Docker Compose, defina la URL de la base de datos en la configuración de su implementación y reinicie el stack. La clave de configuración y el comando exactos dependen de la versión de `dojo-compose-cli` que se le suministró, así que siga la documentación de instalación que vino con su licencia. La cadena de conexión tiene esta forma:

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Para implementaciones de Kubernetes, defina la URL de la base de datos en sus valores de Helm y vuelva a implementar:

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Qué capacidades de Pro están disponibles para su implementación depende de su licencia y de cómo implemente, ya que algunas no aplican a una instalación autoalojada. DefectDojo confirma el conjunto que le corresponde durante la migración.

## Paso 7: valide sus datos

Una vez que la aplicación esté ejecutándose contra la base de datos restaurada:

1. Inicie sesión en su implementación de DefectDojo Pro.
2. Verifique que sus Activos, Organizaciones, Compromisos, Tests y Hallazgos estén presentes. Activos y Organizaciones se llamaban Productos y Tipos de producto en código abierto.
3. Descargue un archivo representativo cargado desde la interfaz, por ejemplo un adjunto de un Hallazgo, Test o Compromiso, para confirmar que la restauración de archivos multimedia funcionó.
4. Verifique que las cuentas de usuario y los grupos estén intactos. SSO y otras configuraciones de autenticación normalmente deben reconfigurarse para la nueva implementación.
5. Informe cualquier discrepancia a su contacto de DefectDojo.

## Planificación de la migración final

El volcado es una instantánea en un momento determinado, por lo que cualquier elemento creado en la instancia de código abierto después de generarlo no estará en la implementación de Pro. Para evitar perder datos, congele la instancia de código abierto para el volcado final y la migración, o ejecute la migración durante un período de baja actividad.

Vale la pena hacer una prueba en seco (dry run). Migre primero una copia reciente, valídela y luego repita el proceso para la migración real. La segunda ejecución es más rápida, y le indica cuánto tiempo tomará la migración del esquema del Paso 6.

## Lista de verificación de la migración

- Motor de base de datos, ubicación de la base de datos y versión de código abierto identificados
- Versión de código abierto alineada con la versión de Pro de destino
- PostgreSQL de destino aprovisionado, accesible desde un host de restauración con las herramientas cliente de PostgreSQL
- Base de datos exportada, con un volcado en formato personalizado si es posible
- Directorio multimedia localizado y comprimido
- Ambos archivos nombrados con la versión de código abierto
- Base de datos y rol de la aplicación creados en el destino
- Volcado restaurado, con la salida de la restauración revisada en busca de errores
- Archivos multimedia restaurados en la ruta o el volumen que usa su implementación
- Pro apuntado a la base de datos restaurada e iniciado, con las migraciones de esquema completas
- Datos validados en la nueva implementación

## Preguntas o soporte

DefectDojo brinda soporte para esta migración de principio a fin. Para obtener ayuda en cualquier paso, contacte a su representante de cuenta o a [support@defectdojo.com](mailto:support@defectdojo.com).
