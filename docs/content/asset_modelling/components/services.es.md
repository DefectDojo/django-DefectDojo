---
title: Servicios
description: Seguimiento de microservicios
weight: 1
---

## ¿Qué es un Servicio?

Los Servicios (abreviatura de Microservicios) son una función opcional dentro de los Activos que proporciona contexto adicional sobre el origen de los Hallazgos dentro de un Activo. Ayudan a aislar los Hallazgos a un componente particular de un Activo, en lugar de a todo el Activo en su conjunto, lo que aporta claridad y precisión en los informes en entornos con arquitecturas complejas.

Los Servicios son útiles cuando necesita segmentar aún más los resultados que provienen de un Test, o si espera tener múltiples instancias del mismo Hallazgo dentro de un flujo de Reimportación que no desea deduplicar. Algunas herramientas de escaneo pueden crear Hallazgos separados para cada ubicación de archivo, y si prefiere mantener esas instancias de un Hallazgo como Hallazgos separados, los servicios pueden ser una manera útil de etiquetar esas diferentes ubicaciones.

## Servicios en Pro

Los Servicios están disponibles en la versión Pro, pero en gran medida han sido reemplazados por la capacidad de establecer relaciones padre-hijo entre Activos. Los Servicios logran el mismo resultado y aún pueden ser útiles cuando reestructurar los Activos no es viable o cuando se requiere delimitar la deduplicación a nivel de escaneo sin alterar la jerarquía de Activos, pero eliminan el contexto. Por ejemplo, la criticidad de negocio, los ingresos y el personal se pueden atribuir a los Activos, pero no a los Servicios. Por lo tanto, los Servicios son principalmente útiles en el contexto de DefectDojo OS.

## ¿Cómo especifico un Servicio? 

La opción para especificar un Servicio está disponible en los formularios de Importar escaneo o Reimportar, dentro del menú desplegable de Campos opcionales. A partir de entonces, la deduplicación se limita a los Tests que comparten el mismo valor de Servicio.

Es importante destacar que los Servicios distinguen entre mayúsculas y minúsculas. Si el Servicio de la importación inicial se identificó como “Service 1” (S mayúscula) y reimporta un escaneo que ha resuelto todos los problemas anteriores pero identifica el Servicio como “service 1” (s minúscula), la deduplicación no se aplicará al Servicio previsto.

## ¿Cómo funcionan los Servicios? 

Los Servicios funcionan permitiéndole especificar a qué Tests anteriores se aplicarán las reglas de deduplicación al reimportar. 

Si, por ejemplo, importa un escaneo y establece el Servicio como “Service 1” y luego reimporta un segundo escaneo estableciendo el Servicio como “Service 2”, la deduplicación no se aplicará entre esos dos escaneos porque el Servicio es diferente.

Cualquier reimportación posterior solo deduplicará los resultados anteriores del primer escaneo si el Servicio se ha establecido como “Service 1”, y solo deduplicará los resultados anteriores del segundo escaneo si el Servicio se ha establecido como “Service 2”. En esencia, si el Servicio es diferente entre dos versiones de un escaneo reimportado, se tratarán como Hallazgos distintos, incluso si los escaneos en sí son idénticos. 

En este ejemplo, si al reimportar el Servicio no se establece como Service 1 ni como Service 2, y en su lugar se deja en blanco, la deduplicación no se aplicará ni al primer ni al segundo escaneo, y solo se cerrarán los Hallazgos que no tengan un Servicio.

## ¿Cómo se deben usar los Servicios?

En la práctica, los Servicios son más útiles cuando:

* Un único Activo contiene múltiples componentes desplegados de forma independiente.
* Diferentes equipos son responsables de distintas partes del mismo Activo.
* Las pruebas de seguridad se realizan contra servicios individuales (por ejemplo, escaneando una API o microservicio específico).
