---
title: Cómo hacer copias de seguridad de una implementación autoalojada
description: Las cuatro cosas que debe capturar, dónde vive cada una en implementaciones
  con Compose y Kubernetes, y cómo confirmar que una copia de seguridad realmente
  se puede restaurar
draft: false
weight: 12
audience: pro
---

Una implementación es más que su base de datos. Una copia de seguridad que capture solo la base de datos se restaura en un sistema que funciona, pero al que le faltan los archivos subidos y que no puede descifrar las credenciales que guarda para sus otras herramientas. Esta página cubre qué capturar, dónde vive cada pieza y cómo confirmar que el resultado se puede restaurar.

## Las cuatro cosas que debe capturar

La base de datos contiene sus organizaciones, activos, compromisos, tests, hallazgos, usuarios y configuración.

Los archivos subidos viven fuera de la base de datos. Las capturas de pantalla, los modelos de amenazas, los documentos de aceptación de riesgo y otros adjuntos similares están en un sistema de archivos, y la base de datos solo guarda las rutas hacia ellos.

La configuración de la implementación es lo que hace que la aplicación vuelva a funcionar de la misma manera, incluidas sus propias personalizaciones y los certificados TLS.

Las claves de cifrado son la pieza que más a menudo se pasa por alto. La clave de cifrado de credenciales es lo que permite leer las credenciales almacenadas de sus herramientas conectadas. Si restaura una base de datos sin ella, esas credenciales quedan intactas pero indescifrables, lo que significa que hay que volver a introducir cada integración manualmente.

## La base de datos

La mayoría de las implementaciones autoalojadas apuntan a un servicio de PostgreSQL administrado, que es la configuración predeterminada del chart y la configuración recomendada. En ese caso, use las copias de seguridad automatizadas y la recuperación a un punto en el tiempo del propio proveedor, en lugar de crear las suyas. Vale la pena verificar dos cosas en lugar de darlas por sentado: que las copias de seguridad automatizadas estén realmente activadas en la instancia, ya que una base de datos administrada con las copias de seguridad desactivadas no tiene ninguna, y que la ventana de retención coincida con lo que exige su organización.

Cuando usted mismo ejecuta PostgreSQL, tome un volcado comprimido en formato personalizado:

```bash
pg_dump -h <db_host> -U <db_user> -Fc <db_name> > defectdojo-$(date +%F).dump
```

Restáurelo con `pg_restore`, usando `--no-owner` y `--no-privileges` si el destino tiene roles distintos a los del origen:

```bash
pg_restore -v --no-owner --no-privileges -h <db_host> -U <db_user> -d <db_name> defectdojo-<date>.dump
```

Tome el volcado según una programación, guárdelo fuera de la máquina que lo produjo, y conserve suficientes generaciones para sobrevivir a un problema que no note de inmediato.

## Archivos subidos

En una implementación con Docker Compose, los archivos subidos están en el directorio `media` dentro de su directorio de implementación en el host. Respalde esa ruta con su copia de seguridad de sistema de archivos habitual. Si la trasladó a un almacenamiento independiente, respalde ese sistema de archivos en lugar del punto de montaje.

En Kubernetes, el volumen de media se aprovisiona según el backend de almacenamiento que haya configurado, y el lugar donde viven físicamente los datos determina cómo protegerlos:

| Backend de almacenamiento | Dónde viven los datos | Cómo protegerlos |
| --- | --- | --- |
| `efs` | Un sistema de archivos de Amazon EFS | AWS Backup |
| `filestore` | Una instancia de Google Filestore | Copias de seguridad de Filestore |
| `gcsfuse` | Un bucket de Cloud Storage | Versionado del bucket, o una copia programada a otro bucket |
| `nfs` | Su servidor NFS | Lo que sea que proteja ese servidor |
| `pvc` | Un volumen de su clase de almacenamiento | Una instantánea de volumen CSI, si su driver las admite |

El chart aprovisiona el volumen, no protege el contenido. No tiene incorporada ninguna programación de instantáneas, así que la copia de seguridad tiene que provenir de la plataforma o de sus propias herramientas.

## Configuración y claves

En Compose, capture su directorio `customizations`, su directorio `certs`, y la configuración y los valores de entorno almacenados por la CLI. `config print` y `environment print` le mostrarán lo que está definido.

En Kubernetes, capture sus archivos values y el contenido de los secrets a los que hace referencia su release.

En ambos casos, conserve la clave de cifrado de credenciales y la clave secreta en un lugar duradero y separado, en un gestor de secretos en lugar de junto a la copia de seguridad. Cualquiera que tenga tanto la base de datos como la clave de credenciales puede leer las credenciales de cada herramienta que haya conectado, así que no deben viajar juntas.

## Qué no es una copia de seguridad

El chart anota sus persistent volume claims para que sobrevivan a `helm uninstall`, algo que está activado de forma predeterminada. Eso es una protección contra una desinstalación accidental, no una copia de seguridad. No sirve de nada ante una corrupción, una eliminación dentro de la aplicación o una actualización que sale mal, porque en cada uno de esos casos el volumen sobrevive y el daño está en él.

Las instantáneas conservadas únicamente en la misma cuenta o proyecto que la implementación son, de manera similar, más débiles de lo que parecen. Lo que sea capaz de eliminar la implementación normalmente también puede eliminarlas a ellas.

## Cómo confirmar que una copia de seguridad se puede restaurar

Una copia de seguridad que nadie ha restaurado es una suposición. Pruébela en un entorno provisional en lugar de sobre producción, y verifique lo siguiente:

1. Inicie sesión y confirme que sus organizaciones, activos, compromisos, tests y hallazgos están presentes en las cantidades que espera.
2. Abra un hallazgo que tenga un adjunto y descárguelo. Esto es lo que demuestra que la restauración de media funcionó, ya que la base de datos por sí sola mostraría el adjunto en la lista pero no podría entregarlo.
3. Abra una conexión de herramienta configurada y confirme que sus credenciales están intactas. Esto es lo que demuestra que restauró correctamente la clave de cifrado de credenciales, y es la verificación con más probabilidades de revelar una carencia.
4. Confirme que los usuarios y grupos se trasladaron correctamente. Los ajustes de autenticación, como SSO, suelen necesitar reconfigurarse para un entorno distinto, así que trate las diferencias allí como algo esperado y no como una restauración fallida.

Ejecute este simulacro según una programación, no solo cuando lo necesite. Hacer una restauración por primera vez durante un incidente es donde suelen fallar los planes de copias de seguridad.

## Preguntas o soporte

Si necesita ayuda para planificar las copias de seguridad de su implementación, o si una restauración no funciona como se espera, comuníquese con [support@defectdojo.com](mailto:support@defectdojo.com).
