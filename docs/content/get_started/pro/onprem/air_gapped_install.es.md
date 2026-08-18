---
title: Instalación de DefectDojo Pro en un entorno air-gapped
description: Prepare los artefactos de instalación de DefectDojo Pro en un host con
  acceso a internet y luego llévelos a una red air-gapped
draft: false
weight: 8
audience: pro
---

Esta página es un complemento de las instrucciones de instalación que se incluyen con su licencia de DefectDojo Pro. Cubre únicamente lo que cambia cuando el host de destino no tiene ruta a internet. Todo lo demás, incluidos los requisitos previos del host y la configuración de PostgreSQL, sigue las instrucciones estándar.

El enfoque utiliza dos hosts. Un host de preparación (staging) con acceso normal a internet descarga los artefactos de implementación y las imágenes de contenedor. A continuación, traslada esos artefactos a la red air-gapped mediante el proceso de transferencia que permita su entorno, y completa la instalación en el host de destino, que no tiene acceso de red a DefectDojo.

Planifique que el host de preparación siga siendo accesible más adelante. Las actualizaciones repiten la misma transferencia, por lo que vale la pena conservarlo.

## Qué necesita

En el host de preparación: un host Linux con acceso a internet, Docker instalado y suficiente espacio libre en disco para el directorio de implementación más las imágenes de contenedor comprimidas. Las imágenes son la mayor parte y cada una ronda varios cientos de megabytes.

En el host air-gapped: Docker instalado y funcionando, y un servidor PostgreSQL ya aprovisionado y accesible, ambos conforme a las instrucciones de instalación estándar.

En ambos: una copia del archivo `dojo-compose-cli` y su archivo de licencia, tal como los proporciona DefectDojo. Use la versión 2.1.0 o posterior de la CLI. Las versiones anteriores no tienen modo air-gapped, y sin él la CLI intenta llegar al registro de contenedores en cada comando y falla con errores de resolución de nombres en lugar de indicarle cuál es el problema.

## Prepare los artefactos

Ejecute estos pasos en el host de preparación.

### 1. Registre la CLI

Instale Docker primero si aún no está presente. Consulte la [documentación de instalación de Docker](https://docs.docker.com/engine/install/) para obtener instrucciones específicas de su distribución.

Extraiga el archivo de la CLI y luego regístrela:

```bash
sudo ./dojo-compose-cli register
```

El registro instala la CLI en `/usr/bin`, crea el grupo `dojosrv`, agrega su usuario a los grupos `dojosrv` y `docker`, valida la licencia y autentica Docker frente al registro de contenedores de DefectDojo.

Se le solicitará una `DOJO_CLI_KEY`, que cifra la configuración almacenada de la CLI en disco. Defínala en el entorno para evitar que se le solicite en cada comando:

```bash
export DOJO_CLI_KEY="your-key"
```

La nueva pertenencia a los grupos no se aplica a su shell actual. Abra una sesión nueva, o bien actualice los grupos en el mismo shell:

```bash
newgrp docker
```

Confirme con `id` que aparecen tanto `docker` como `dojosrv`. Una vez que su usuario esté en el grupo `docker`, el resto de los comandos no necesitan `sudo`.

Si el host de preparación llega a internet a través de un proxy HTTPS de salida, configure las variables de proxy antes de descargar nada. Consulte [Cómo ejecutar DefectDojo detrás de un proxy HTTPS de reenvío](/onprem_deployment/forward_proxy/).

### 2. Defina la versión

Defina tanto la versión de implementación como la versión de la aplicación con la versión que planea instalar, reemplazando `x.y.z`:

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

Use la misma versión en ambos comandos, y manténgala de forma coherente durante el resto de este procedimiento. Mezclar versiones entre los artefactos de implementación y las imágenes produce una pila que no arranca o que arranca con las imágenes incorrectas.

### 3. Descargue los artefactos de implementación y las imágenes

Descargue el directorio de implementación:

```bash
dojo-compose-cli deploy download
```

Esto puebla `/opt/dojo` con el archivo compose, la configuración de nginx, las plantillas del sistema de seguimiento de incidencias, el directorio de personalizaciones y un subdirectorio con versión para la versión que seleccionó.

Luego descargue las imágenes de contenedor:

```bash
dojo-compose-cli app pull-images
```

Confirme qué llegó:

```bash
docker image ls
```

Anote el prefijo de repositorio que comparten las imágenes de DefectDojo en esa salida. Lo necesitará en el siguiente paso, y el conjunto de imágenes varía entre versiones, así que léalo de su propia salida en lugar de suponer una lista.

### 4. Registre la configuración generada

La instalación estándar genera varios valores de configuración en la primera ejecución. En una instalación air-gapped, usted los define manualmente en el host de destino, así que captúrelos ahora:

```bash
dojo-compose-cli environment print | head -n 9
```

Conserve la clave de cifrado de credenciales y la clave secreta. Ambas son cadenas aleatorias generadas de 64 caracteres, y la clave de credenciales en particular debe coincidir con la que se usó al cifrar las credenciales, así que anótela con exactitud y guárdela como un secreto. Los valores de uwsgi y celery en la misma salida son útiles como punto de partida para el host de destino.

Trate esta salida como información sensible. Contiene las claves que protegen las credenciales almacenadas de su implementación.

### 5. Empaquete todo

Cree un directorio para la transferencia, usando la versión en su nombre para que el contenido sea inequívoco más adelante:

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

Archive el directorio de implementación, conservando los permisos:

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

Guarde las imágenes de contenedor. Este script toma el prefijo de repositorio que anotó en el paso 3, guarda cada imagen coincidente y la comprime:

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

Hágalo ejecutable y ejecútelo con su prefijo:

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

Verifique que cada imagen del paso 3 haya producido un archivo, y luego empaquete el directorio:

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

Traslade `artifacts-x.y.z.tar.gz` a la red air-gapped mediante su proceso de transferencia habitual, junto con el archivo de la CLI y su archivo de licencia si aún no están allí.

## Instale en el host air-gapped

### 6. Instale la CLI y active el modo air-gapped

Extraiga el archivo de la CLI y luego coloque la licencia donde la CLI la espera:

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

Active el modo air-gapped. Este es el primer comando de la CLI que ejecuta en este host, e instala la CLI en `/usr/bin`, valida la licencia a partir del archivo y cifra la configuración almacenada a medida que avanza:

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

Confirme que se aplicó:

```bash
dojo-compose-cli config print
```

La salida incluye `Air Gapped Deploy` establecido en true. Defina también aquí `DOJO_CLI_KEY` en el entorno, para que los comandos posteriores no se la soliciten.

No ejecute `register` en este host. El registro existe para autenticarse frente al registro de contenedores, que por definición es inalcanzable, y en modo air-gapped la CLI lo rechaza en lugar de intentarlo. Lo mismo se aplica a los demás comandos que acceden al registro:

| Comando | Comportamiento en modo air-gapped |
| --- | --- |
| `register` | Rechazado. La autenticación con el registro no está disponible. |
| `deploy download` | Rechazado. Ejecútelo en el host de preparación en su lugar. |
| `app pull-images` | Rechazado. Ejecútelo en el host de preparación en su lugar. |
| `app upgrade` | Rechazado. Consulte la sección de actualización más abajo. |
| `app start`, `app stop`, `app restart` | Disponible. Estos no contactan el registro. |

Cada comando rechazado finaliza con un mensaje que menciona el modo air-gapped, por lo que un rechazo aquí es la CLI funcionando como se espera, no un fallo que haya que diagnosticar.

Actualice su nueva pertenencia a los grupos antes de continuar:

```bash
newgrp docker
```

### 7. Restaure el directorio de implementación

Extraiga el paquete de transferencia y luego mueva el archivo de implementación a su lugar:

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

Es posible que la configuración de la CLI haya creado un `/opt/dojo` casi vacío que contenga solo la licencia. Si está allí, elimínelo primero para que el archivo no se combine con él:

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

Extraiga el directorio de implementación real y luego corrija la propiedad y los permisos de media:

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. Defina la configuración manualmente

Una instalación air-gapped no utiliza la primera instalación interactiva, así que defina los valores que de otro modo se generarían automáticamente. Use las claves que capturó en el paso 4:

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

Defina la versión para que coincida con los artefactos que trasladó:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

Defina la URL del sitio y los hosts permitidos. La URL del sitio debe ser la dirección que resuelve a este host dentro de su red:

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

Defina la conexión a la base de datos, usando el servidor PostgreSQL que aprovisionó anteriormente:

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. Cargue las imágenes de contenedor

Este script carga cada archivo de imagen en el directorio de imágenes:

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

Ejecútelo desde dentro del directorio de artefactos extraído:

```bash
chmod u+x load-images.bash
./load-images.bash
```

Luego confirme con `docker image ls` que todas las imágenes se cargaron, en la versión que espera.

### 10. Inicie la pila

Inicie la pila con la CLI. Esto funciona en modo air-gapped, ya que lee la configuración que definió y opera el archivo compose local sin contactar el registro:

```bash
dojo-compose-cli app start
```

`app stop` y `app restart` están disponibles de la misma manera. Use `app restart` después de cambiar cualquier valor de entorno, porque recrea los contenedores para que se apliquen los valores nuevos.

Hay dos cosas que verificar si la pila no arranca. El comando necesita el directorio de implementación en su lugar, así que confirme que `/opt/dojo/docker-compose.yml` existe a partir del paso 7. Y la versión configurada selecciona las etiquetas de imagen, así que debe coincidir con las imágenes que cargó en el paso 9.

DefectDojo queda entonces disponible en la dirección que definió como URL del sitio.

## Actualización de una implementación air-gapped

`app upgrade` descarga desde el registro de contenedores, por lo que es uno de los comandos que el modo air-gapped rechaza. Las actualizaciones siguen la misma ruta que la instalación, en lugar de ejecutarse mediante un único comando.

En el host de preparación, defina la nueva versión y repita los pasos 3 a 5 para ella. Traslade el nuevo paquete, cargue las nuevas imágenes y luego, en el host air-gapped, defina la versión con la nueva y reinicie:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

Hay dos cosas que suelen atrapar a la gente. Reiniciar sin cambiar la versión configurada vuelve a levantar la pila con las imágenes que ya tenía, porque la versión selecciona las etiquetas de imagen. Y el conjunto de imágenes puede cambiar entre versiones, así que compare lo que cargó con lo que produjo la descarga de la nueva versión, en lugar de suponer que la lista anterior sigue siendo válida.

Su directorio de implementación existente no incorpora por sí solo el archivo compose ni la configuración de nginx de la nueva versión, así que restaure el contenido nuevo de `/opt/dojo` como lo hizo en el paso 7, conservando sus propias personalizaciones, certificados y media.

Haga una copia de seguridad de su base de datos antes de cualquier actualización, y revise las [notas de actualización](/releases/os_upgrading/upgrading_guide/) de cada versión entre la actual y la de destino. Si está varias versiones atrás, comuníquese con soporte antes de comenzar.

## Funciones que necesitan acceso de salida

Una implementación air-gapped funciona sin ninguna conectividad de salida, pero las funciones que se comunican con servicios externos no pueden funcionar mientras esté desconectada. Esto se aplica a los conectores e integradores que obtienen datos de herramientas alojadas en la nube, a las integraciones con sistemas de seguimiento de incidencias como Jira, a las notificaciones de salida hacia servicios como Slack y Microsoft Teams, y a los datos de enriquecimiento de vulnerabilidades que normalmente se obtienen según una programación.

Estas se configuran por implementación en lugar de estar activas de forma predeterminada, así que una instalación air-gapped no se ve afectada por su ausencia. Si activa alguna, espere que falle con errores de resolución de nombres o de conexión hasta que la implementación tenga una ruta hacia ese servicio. Cuando la ruta de salida existe pero pasa por un proxy, consulte [Cómo ejecutar DefectDojo detrás de un proxy HTTPS de reenvío](/onprem_deployment/forward_proxy/).

### Datos de EPSS y KEV desde una réplica interna

El enriquecimiento de EPSS y KEV es una excepción que vale la pena configurar, porque no requiere una ruta hacia internet público. Ambos se configuran en el Tuner, en Finding Enrichment, y cada uno tiene su propio interruptor de activación y su propia URL de consulta. Los campos de URL vienen apuntando a las fuentes públicas, y puede redirigirlos a una copia alojada dentro de su propia red.

La réplica debe servir los mismos archivos en el mismo formato que las fuentes públicas. Las consultas obtienen un archivo específico de la URL que les indique, en lugar de descubrir lo que haya allí, así que una réplica que reempaqueta o reorganiza los datos no funcionará. Actualice sus copias según la programación que le convenga, ya que la implementación solo lee lo que sirve su réplica.

## Preguntas o soporte

Si necesita ayuda con una instalación o actualización air-gapped, comuníquese con su representante de cuenta o con [support@defectdojo.com](mailto:support@defectdojo.com).
