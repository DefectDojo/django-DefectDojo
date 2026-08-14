---
title: Instalación en Docker Compose
description: Instale DefectDojo Pro autoalojado en un solo host usando dojo-compose-cli,
  con PostgreSQL en un servidor separado
draft: false
weight: 15
audience: pro
---

Esta página cubre la instalación de DefectDojo Pro en Docker Compose, que es el más sencillo de los dos modelos autoalojados y la opción adecuada si aún no está ejecutando Kubernetes.

El resultado son dos hosts. Uno ejecuta la aplicación y sus servicios de soporte bajo Docker Compose, y el otro ejecuta PostgreSQL. Puede apuntar a una base de datos administrada en lugar de ejecutar la suya propia, y para evaluación puede ejecutar la base de datos en un contenedor en el host de la aplicación, aunque eso no es lo que desea para datos de producción.

Casi todo el trabajo lo realiza `dojo-compose-cli`, que DefectDojo proporciona junto con su licencia. Su comando `first-install` es un asistente interactivo que configura la implementación, descarga las imágenes, inicia todo y registra un servicio systemd.

## Antes de empezar

Dimensione primero la implementación. La guía de dimensionamiento de hardware de esta sección cubre qué aprovisionar tanto para el host de la aplicación como para la base de datos.

Ubuntu 24.04 LTS es el sistema operativo compatible para esta instalación. Actualícelo completamente antes de comenzar. La instalación ejecuta comandos como root, por lo que necesita `sudo` o un shell de root en ambos hosts.

Necesitará dos archivos de DefectDojo, que llegan con su suscripción: el archivo `dojo-compose-cli` y su archivo de licencia, normalmente llamado `dojopro.lic`. Póngase en contacto con su representante de cuenta o con [support@defectdojo.com](mailto:support@defectdojo.com) si no los tiene.

## Configurar la base de datos

DefectDojo Pro requiere PostgreSQL 16 o una versión más reciente.

### Uso de una base de datos administrada

Si utiliza un servicio de PostgreSQL administrado, siga la documentación de ese proveedor para crear la instancia y luego cree lo siguiente:

- Una base de datos llamada `dojodb`
- Un usuario de base de datos llamado `dojodbusr`, con todos los privilegios sobre `dojodb`, y configurado como su propietario

Anote el nombre de host, el puerto si no es el predeterminado 5432, y las credenciales. Los necesitará durante la instalación.

### Ejecutar PostgreSQL usted mismo

En Ubuntu 24.04, PostgreSQL 16 está en los repositorios predeterminados:

```bash
apt update
apt -y install postgresql postgresql-contrib
```

Cree las bases de datos y el usuario de la aplicación. DefectDojo usa una segunda base de datos para su servicio de orquestación, así que cree ambas:

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

Use una contraseña alfanumérica. Los caracteres especiales deben codificarse como URL más adelante, cuando la contraseña se incluya en una cadena de conexión, y ese es un paso fácil de hacer mal.

Luego permita que la base de datos escuche conexiones desde el host de la aplicación. En `/etc/postgresql/16/main/postgresql.conf`, configure `listen_addresses` con la propia dirección del servidor de base de datos, o con `*` si prefiere no fijarla:

```bash
listen_addresses = '<db-server-address>'
```

Y en `/etc/postgresql/16/main/pg_hba.conf`, añada tres líneas que autoricen al host de la aplicación. Restringir a la dirección del host de la aplicación es mejor que abrirlo a todo:

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

Reinicie para que ambos cambios surtan efecto:

```bash
systemctl restart postgresql
```

## Preparar el host de la aplicación

### Conectividad saliente

En una red restringida, el host de la aplicación necesita acceso saliente a lo siguiente. Todos son HTTPS en el puerto 443 salvo que se indique lo contrario.

| Destino | Propósito | Obligatorio |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | El registro de contenedores de DefectDojo Pro | Sí |
| Su host de base de datos, normalmente puerto 5432 | Aplicación a base de datos | Sí |
| Los repositorios de paquetes de su distribución | Dependencias del sistema operativo durante la configuración | Sí |
| `download.docker.com` | Paquetes de Docker Engine durante la configuración | Sí |
| `api.first.org` | Puntuaciones de predicción de explotación EPSS | Opcional |
| `www.cisa.gov` | El catálogo KEV de vulnerabilidades conocidas explotadas | Opcional |

Incluya en la lista de permitidos por nombre de host en lugar de por dirección. El registro está detrás de una red de distribución de contenido, por lo que sus direcciones varían según la ubicación y cambian con el tiempo.

Si el host llega a internet a través de un proxy saliente, consulte [Ejecución de DefectDojo detrás de un proxy HTTPS de reenvío](/onprem_deployment/forward_proxy/). Si no tiene ninguna ruta a internet, siga en su lugar el procedimiento de instalación con espacio de aire (air-gapped) de esta sección.

### Confirmar que la base de datos es accesible

Instale las herramientas de cliente y conéctese antes de continuar. Un problema de base de datos es mucho más fácil de diagnosticar ahora que en medio de la instalación:

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### Instalar Docker Engine

Siga las [instrucciones de instalación de Docker Engine para Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Use la documentación propia de Docker en lugar de una copia, ya que los pasos cambian con el tiempo. Instale el paquete `docker-compose-plugin` junto con el motor, que esas instrucciones incluyen de forma predeterminada.

Luego añada su usuario al grupo `docker` y aplique la nueva pertenencia:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## Instalar DefectDojo

Copie el archivo de la CLI y su archivo de licencia al host de la aplicación, en el mismo directorio, y extraiga la CLI:

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

Luego ejecute el instalador desde ese directorio:

```bash
sudo ./dojo-compose-cli first-install
```

El asistente solicita lo siguiente.

| Solicitud | Qué es |
| --- | --- |
| `DOJO_CLI_KEY` | Una clave de cifrado para la configuración que la CLI almacena en disco. Elíjala ahora y consérvela, ya que los comandos posteriores la necesitan. |
| DefectDojo Version | La versión que se va a instalar. |
| Deploy Version | Los archivos de implementación que se van a usar. Configúrela con el mismo valor que la versión. |
| Deploy Type | `separate-db` para una base de datos en su propio host, o `containerized-db` para ejecutar PostgreSQL en un contenedor. |
| Database Connection Type | Elija Single Line y proporcione toda la cadena de conexión. |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`. Debe comenzar con `postgres://` en lugar de `postgresql://`. |
| `DD_ALLOWED_HOSTS` | Los encabezados de host a los que responderá la aplicación. |
| `DD_SITE_URL` | La URL completa donde los usuarios acceden a DefectDojo, por ejemplo `https://defectdojo.internal.example.com`. |

Dos cosas que vale la pena saber sobre las solicitudes. Proporcione la conexión de base de datos como una sola línea en lugar de valor por valor, ya que la ruta valor por valor actualmente no solicita el nombre de usuario. Y si la contraseña contiene caracteres como `!`, `@`, o `#`, codifíquelos como URL en la cadena de conexión.

El instalador entonces descarga las imágenes, inicia la pila, crea un servicio systemd e imprime las credenciales de administrador generadas. **Guarde esas credenciales antes de cerrar la terminal. No se muestran de nuevo.**

Una vez que termina, DefectDojo está disponible en la URL del sitio que proporcionó.

## Qué creó la instalación

| Elemento | Ubicación |
| --- | --- |
| Binario de la CLI | `/usr/bin/dojo-compose-cli` |
| Archivos de la aplicación, archivo de compose, configuración de nginx, medios | `/opt/dojo/` |
| Archivo de licencia | `/etc/defectdojo/dojopro.lic` |
| Configuración cifrada de la CLI | `/etc/defectdojo/compose.config` |
| Certificados TLS | `/opt/dojo/certs/` |
| Sus personalizaciones | `/opt/dojo/customizations/` |
| Servicio systemd | `/etc/systemd/system/defectdojo-compose.service` |

También crea un usuario y grupo `dojosrv`, que son propietarios de los archivos de la aplicación.

La pila en ejecución es la aplicación Django, un contenedor independiente que gestiona las importaciones de escaneos, nginx, un worker y planificador de Celery, Valkey para caché y colas, el servicio de conectores y el servidor MCP. `docker ps` los muestra.

Día a día, estos son los comandos que necesita:

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

Use `app restart` después de cambiar cualquier configuración, ya que recrea los contenedores para que se apliquen los nuevos valores.

## Reemplazar el certificado TLS

La instalación incluye un certificado autofirmado para que el sitio funcione de inmediato. Reemplácelo por el suyo sobrescribiendo dos archivos, manteniendo los nombres exactamente como están:

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

Luego ejecute `dojo-compose-cli app restart` para aplicarlos.

## Restablecer la contraseña de administrador

Si pierde la contraseña generada, restablézcala desde el host de la aplicación. DefectDojo debe estar en ejecución:

```bash
dojo-compose-cli app change-password
```

## Actualización

Haga una copia de seguridad de su base de datos primero, y lea las notas de la versión de cada versión entre la actual y la de destino, no solo la de destino. Consulte las [notas de actualización](/releases/os_upgrading/upgrading_guide/).

La CLI puede realizar toda la actualización, solicitando la versión:

```bash
dojo-compose-cli app upgrade
```

Si prefiere hacerlo por pasos, detenga la aplicación, establezca la nueva versión, descargue los archivos de implementación correspondientes y luego inicie de nuevo:

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

El paso de descarga compara el `docker-compose.yml` entrante, la configuración de nginx y `local_settings.py` con lo que ya tiene, e indica cuándo difieren para que pueda reconciliar sus cambios. Añadir `--overwrite` acepta las nuevas versiones de esos archivos y descarta las modificaciones locales realizadas en ellos, así que úselo deliberadamente.

Mantenga su propia configuración en `/opt/dojo/customizations/local_settings.py`. Ese archivo es suyo y sobrevive a las actualizaciones.

## Referencia de comandos

`dojo-compose-cli --help` enumera todo, y cada subcomando también acepta `--help`. Los comandos que más probablemente necesite:

| Comando | Qué hace |
| --- | --- |
| `first-install` | Instalación interactiva inicial |
| `app start`, `app stop`, `app restart` | Controla la pila |
| `app upgrade` | Actualiza a una versión más reciente |
| `app pull-images`, `app purge-images` | Obtiene o elimina las imágenes configuradas |
| `app change-password` | Restablece la contraseña de administrador, con la aplicación en ejecución |
| `config print` | Muestra la configuración actual |
| `config set` | Establece la versión, la versión de implementación, el tipo de implementación o el modo air-gapped |
| `config rotate-secret` | Rota la clave que cifra la configuración almacenada |
| `environment print`, `environment add`, `environment remove` | Gestiona las variables de entorno |
| `deploy download` | Obtiene los archivos de implementación para la versión configurada |
| `license print`, `license status`, `license update` | Inspecciona y actualiza su licencia |
| `validate db-connection` | Verifica la cadena de conexión de la base de datos |
| `validate deploy-version` | Verifica que los archivos de implementación coincidan con la versión configurada |
| `diagnostics collect` | Recopila un paquete de diagnóstico para una solicitud de soporte |
| `register` | Se autentica en el registro de contenedores |
| `update-binary` | Actualiza la propia CLI |

La mayoría de los comandos necesitan `DOJO_CLI_KEY`, ya que la configuración está cifrada en reposo. Expórtela para su sesión, o páselo a través de `sudo` con `sudo -E`:

```bash
export DOJO_CLI_KEY="your-key"
```

## Preguntas o soporte

Si una instalación no se completa, `dojo-compose-cli diagnostics collect` recopila un paquete de informe que es la forma más rápida de ayudarlo. Envíelo, junto con lo que estaba ejecutando cuando falló, a [support@defectdojo.com](mailto:support@defectdojo.com).
