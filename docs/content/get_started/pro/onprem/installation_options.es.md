---
title: Alojamiento propio de DefectDojo Pro
date: 2021-02-02 20:46:29+01:00
weight: 5
audience: pro
---

DefectDojo Pro puede alojarse completamente en su propio entorno, lo que le da control sobre su infraestructura, sus datos y su postura de seguridad. Es adecuado para organizaciones con requisitos de cumplimiento, residencia de datos o seguridad interna que descartan una implementación alojada en la nube, y ofrece las mismas capacidades que el producto alojado en la nube.

Esta página cubre los modelos de implementación disponibles, lo que necesita antes de empezar y dónde encaja el resto de esta sección.

## Dos modelos de implementación

**Docker Compose en un solo host** es el más sencillo de los dos. La aplicación, los workers asíncronos y la caché se ejecutan todos en una sola máquina, gestionada por una herramienta de línea de comandos que proporcionamos. Como nada en esa disposición escala horizontalmente, el host debe dimensionarse para su pico en lugar de su promedio, y en la mayoría de las implementaciones el pico se produce cuando llega una importación de escaneo grande mientras las personas trabajan en la interfaz.

**Kubernetes, usando nuestro chart de Helm**, ejecuta esos mismos componentes como cargas de trabajo independientes. Eso le permite aprovisionar para el estado estable y añadir réplicas cuando llega la carga, y le permite escalar la parte que realmente está ocupada en lugar de toda la máquina.

Ambos modelos usan PostgreSQL. Para producción recomendamos una base de datos administrada externa, que es lo que el chart de Helm asume de forma predeterminada. Las herramientas de Compose también pueden ejecutar PostgreSQL en un contenedor junto a la aplicación, lo cual es conveniente para evaluación y no es lo que desea para datos de producción.

Si ya ejecuta Kubernetes, úselo. Un solo host funciona perfectamente bien, y muchas implementaciones se ejecutan así, pero termina comprando un margen que no puede reasignar. Si no ejecuta Kubernetes y no quiere hacerlo, Compose es una opción legítima y no un compromiso.

## Antes de empezar

Dimensione primero la implementación. Ambos modelos dependen de saber aproximadamente cuántos hallazgos espera mantener y cuántas personas trabajarán en el producto a la vez, y esos dos números determinan partes distintas de la implementación. La guía de dimensionamiento de hardware de esta sección cubre ambos casos.

Necesitará un archivo de licencia y las herramientas de implementación para el modelo que elija. DefectDojo proporciona ambos cuando comienza su suscripción. Si no los tiene, o necesita que se los reemitan, póngase en contacto con su representante de cuenta o con [support@defectdojo.com](mailto:support@defectdojo.com).

También necesitará un lugar donde ejecutarlo, una base de datos PostgreSQL a la que pueda acceder y un nombre de host que resuelva a la implementación. Las páginas de instalación individuales cubren los detalles específicos de cada modelo.

## Qué más incluye esta sección

Las páginas junto a esta cubren el resto del ciclo de vida. Hay orientación de dimensionamiento para elegir el hardware, instrucciones para trasladar una instancia de código abierto existente a una implementación Pro autoalojada, y un procedimiento para instalar donde el host de destino no tiene ruta a internet.

Para implementaciones que ya están en ejecución, hay páginas sobre actualización, sobre copias de seguridad, sobre aumentar los límites que rechazan cargas de escaneo grandes, y sobre ampliar el almacenamiento de archivos cargados cuando un host se queda sin espacio. Use la navegación de la sección para explorarlas.

## Preguntas

Si está evaluando los dos modelos para su entorno, o sus circunstancias no se parecen a los supuestos aquí descritos, preferimos hablarlo con usted antes de que aprovisione que después.

Los clientes existentes deben ponerse en contacto con su representante de cuenta o con [support@defectdojo.com](mailto:support@defectdojo.com). Si está evaluando DefectDojo Pro y desea hablar sobre el alojamiento propio, contáctenos en [hello@defectdojo.com](mailto:hello@defectdojo.com).
