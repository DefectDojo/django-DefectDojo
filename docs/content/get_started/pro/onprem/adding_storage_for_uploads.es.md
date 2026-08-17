---
title: Añadir almacenamiento para los archivos subidos
description: Ampliar el almacenamiento disponible para los archivos subidos en un
  despliegue de Docker Compose sin modificar el despliegue en sí
draft: false
weight: 11
audience: pro
---

Los archivos subidos residen en el directorio media del host, y en un despliegue de Docker Compose el espacio disponible para ellos es el que le quede libre al disco de la VM. Las cargas grandes, como los SBOM, pueden llenar ese disco. Esta página explica cómo ampliar el espacio sin modificar el despliegue en sí.

## Por qué esto funciona a nivel de sistema operativo

El despliegue de Docker Compose monta mediante bind mount el directorio media del host en los contenedores que lo necesitan, tanto los contenedores de la aplicación como el nginx que sirve los archivos subidos a los usuarios. Los contenedores leen y escriben en una ruta del host, de modo que usan el sistema de archivos que esté montado en esa ruta. Montar más capacidad ahí es transparente para la aplicación.

Por eso el enfoque aquí es un cambio a nivel de sistema operativo en lugar de un cambio en el despliegue. Mantener sin modificar el archivo Compose que se distribuye con su versión mantiene su instalación coherente con otros despliegues on-premise, y evita perder el cambio cuando una actualización reemplace ese archivo.

## Almacenamiento en bloque, la opción más sencilla

Montar un dispositivo de bloque adicional es la forma habitual de solucionar un disco lleno en Linux, y es la primera opción a la que recurrir. Un volumen NAS o SAN funciona, al igual que el almacenamiento en bloque de un proveedor de nube, como un volumen de Amazon EBS.

Separar el almacenamiento de la aplicación del disco del sistema operativo es, en general, una buena práctica, así que tiene dos opciones razonables. Monte el dispositivo en el directorio media para dar a las cargas su propia capacidad, o móntelo un nivel más arriba, en el directorio de despliegue, para que todos los datos de la aplicación residan en un sistema de archivos separado de la VM.

## Almacenamiento de objetos, con salvedades

Respaldar las cargas con almacenamiento de objetos como Amazon S3 es factible, y elimina por completo el límite de capacidad, pero encaja de forma menos natural que un dispositivo de bloque. Considere lo siguiente antes de elegirlo.

El almacenamiento de objetos no es un sistema de archivos. S3 no admite escrituras aleatorias, añadir contenido a un archivo existente ni bloqueo de archivos. Una capa FUSE disimula estas carencias, pero está emulando una semántica que el almacenamiento subyacente no tiene.

La latencia es más alta que la de un dispositivo de bloque. Esto afecta a las cargas, y como nginx sirve los archivos subidos desde el mismo directorio, también afecta a las descargas.

Añade dependencias de red. Según dónde se encuentre la VM en su red, llegar al bucket puede implicar un recorrido de red adicional, y esa ruta ahora tiene que estar disponible para que las cargas funcionen.

Los reinicios requieren cuidado. El bucket tiene que montarse en el arranque, lo que introduce una relación temporal entre la finalización del montaje y el inicio de DefectDojo. Según la latencia, esto puede provocar que el reinicio se quede colgado o que el inicio ocurra con el montaje aún no listo.

Los permisos tienen que coincidir. Los permisos de IAM del bucket deben conciliarse con los permisos del sistema de archivos que la aplicación necesita para escribir las cargas.

### Herramientas para montar almacenamiento de objetos

Se suelen usar tres herramientas para montar S3 como sistema de archivos en Linux.

`rclone mount` es estable, se mantiene activamente y ofrece modos de caché de sistema de archivos virtual que gestionan bien el buffering de lectura y escritura. De las tres, es la que recomendaríamos si opta por este camino.

`goofys` está optimizado para la velocidad. Lo consigue realizando las creaciones y escrituras de archivos de forma asíncrona e ignorando las operaciones que S3 no admite de forma nativa, como las escrituras aleatorias y el bloqueo de archivos.

`s3fs-fuse` es el más compatible con POSIX de los tres, ya que admite cosas como cambiar la propiedad y los permisos, pero imitar un sistema de archivos real lo hace considerablemente más lento que goofys.

## Trasladar el directorio media a un nuevo sistema de archivos

Esto requiere tiempo de inactividad, ya que la aplicación no debe estar escribiendo cargas mientras se copian.

1. Detenga DefectDojo con `dojo-compose-cli app stop`, para que nada cambie bajo sus pies durante el traslado.
2. Cambie el nombre del directorio media existente para conservarlo como punto de retorno, por ejemplo moviendo `media` a `old-media` dentro de su directorio de despliegue.
3. Cree un directorio vacío en la ruta media original para que actúe como punto de montaje.
4. Conecte el nuevo sistema de archivos. Los detalles dependen de lo que haya elegido antes, pero se reducen a tres cosas: hacer que el almacenamiento esté disponible para Linux, lo que en el caso del almacenamiento de objetos significa crear el bucket y sus permisos; montarlo en la ruta media; y hacer que el montaje sobreviva a un reinicio, normalmente con una entrada en `/etc/fstab` o el equivalente para su herramienta.
5. Copie el contenido antiguo, conservando la propiedad y los permisos. `rsync -Pav` desde el directorio antiguo al nuevo hace esto e informa del progreso, lo cual es útil cuando hay mucho que mover.
6. Confirme que los archivos llegaron. Para el almacenamiento de objetos, comprobar el bucket en la consola de su proveedor es la forma más rápida de asegurarse de que el montaje realmente está escribiendo donde usted cree.
7. Inicie DefectDojo con `dojo-compose-cli app start` y suba un archivo de prueba. Si la carga falla, los registros del contenedor indicarán el motivo, y los permisos suelen ser la causa habitual.

Conserve el directorio antiguo hasta que la carga de prueba tenga éxito y haya confirmado que los archivos migrados desde él son legibles en la interfaz. Es su vía de regreso si el nuevo sistema de archivos no se comporta correctamente.

## Alcance del soporte

Estas son recomendaciones generales. Añadir almacenamiento a una VM es una tarea de sistema operativo, y los detalles concretos del método que elija, en particular un almacenamiento de objetos montado mediante FUSE, quedan fuera del alcance del soporte on-premise. El enfoque está deliberadamente planteado para mantener su despliegue coherente con cualquier otra instalación on-premise, dejando sin modificar el archivo Compose que distribuimos y resolviendo el problema de capacidad en la capa del sistema operativo, que es donde corresponde.

Si está sopesando las opciones para su entorno, contacte con [support@defectdojo.com](mailto:support@defectdojo.com) y podremos analizar juntos las ventajas y desventajas antes de que se decida por una.
