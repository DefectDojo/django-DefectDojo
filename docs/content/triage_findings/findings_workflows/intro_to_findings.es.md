---
title: Introducción a los Hallazgos
description: El principal flujo de trabajo y sistema de seguimiento de vulnerabilidades
  de DefectDojo
weight: 1
aliases:
- /es/en/working_with_findings/intro_to_findings
---

Los Hallazgos son la principal forma en que DefectDojo estandariza y guía el proceso de generación de informes y remediación de sus herramientas de seguridad. Independientemente de si una vulnerabilidad fue reportada en SonarQube, Acunetix o la herramienta personalizada de su equipo, los Hallazgos le brindan la capacidad de gestionar cada vulnerabilidad de la misma manera.

## ¿Qué son los Hallazgos?

Los Hallazgos en DefectDojo se componen de los siguientes elementos:

* Los datos de la vulnerabilidad reportada en cuestión
* El "estado" del Hallazgo, utilizado para hacer seguimiento de la remediación, la aceptación de riesgo u otras decisiones tomadas en torno a la vulnerabilidad
* Otros metadatos relacionados con el Hallazgo. Por ejemplo, esto podría incluir la ubicación de un Hallazgo en su red, las sugerencias de remediación de una herramienta, o enlaces a un CWE o puntaje EPSS asociado.

Además de almacenar los datos de la vulnerabilidad y proporcionar un marco de remediación, DefectDojo también mejora sus Hallazgos de las siguientes maneras:

* Agregando automáticamente los puntajes EPSS relacionados a un Hallazgo para describir su explotabilidad
* Traduciendo automáticamente la métrica de severidad de una herramienta de seguridad a un puntaje de Severidad para cada Hallazgo, lo cual otorga un SLA al Hallazgo según la Configuración de SLA de su Producto.

En general, los Hallazgos de DefectDojo están diseñados para trabajar con la Jerarquía de Productos, con el fin de estandarizar sus esfuerzos y aplicar un método consistente a cada Producto.

## Una página de Hallazgo

La página de Hallazgo contiene varios componentes. Cada uno se completa mediante el proceso de Importación cuando se crea el Hallazgo.

![imagen](images/Introduction_to_Findings.png)

1. **El Título del Hallazgo:** Por lo general, es un identificador descriptivo abreviado que identifica la vulnerabilidad o el problema detectado. Esta sección también es donde se muestran las Etiquetas creadas por el usuario, si existen.
​
2. **Resumen del Hallazgo:** Esta sección contiene cinco páginas separadas de información relevante para el Hallazgo: Descripción, Mitigación, Impacto, Referencias y Notas. Estos campos pueden completarse automáticamente en función de los datos de vulnerabilidad entrantes, o pueden ser editados por un usuario de DefectDojo para proporcionar contexto adicional.
​
- ​**Descripción** es un resumen y explicación más detallados del Hallazgo en cuestión.
- ​**Mitigación** es un método sugerido para mitigar el Hallazgo de modo que ya no esté presente en su sistema.
- ​**Impacto** describe el impacto de la vulnerabilidad en su postura de seguridad. Esta página puede contener texto descriptivo, o puede incluir una [Cadena de Vector CVSS](https://qualysguard.qualys.com/qwebhelp/fo_portal/setup/cvss_vector_strings.htm), que es una forma abreviada de comunicar la explotabilidad general de la vulnerabilidad y las consecuencias de su explotación para su organización. El Impacto está estrechamente relacionado con el campo de Severidad de un Hallazgo.
- ​**Referencias** enumerará cualquier enlace o información adicional relevante para este Hallazgo, si se incluye.
- ​**Notas** es una página donde puede registrar cualquier otra información relevante para este Hallazgo. Las Notas son metadatos "exclusivos de DefectDojo" y no se crean en el momento de la importación. Use este campo para hacer seguimiento de su progreso de mitigación o para agregar detalles más específicos al Hallazgo.
​
3. **Detalles adicionales:** Esta sección enumera otros detalles relacionados con este Hallazgo, si corresponde:



	* Pares de Solicitud/Respuesta asociados con la vulnerabilidad
	* Pasos para reproducir la vulnerabilidad
	* Justificación de la Severidad, donde puede registrar una explicación más detallada de la severidad o el impacto del Hallazgo.
	​

4. **Metadatos: Esta sección contiene metadatos filtrables relacionados con el Hallazgo:**


	* **ID:** el valor de ID del Hallazgo en DefectDojo
	* **Severidad:** el valor de Severidad del Hallazgo. Puede ser Informativa, Baja, Media, Alta o Crítica. Las Severidades de los Hallazgos están directamente relacionadas con el SLA calculado del Hallazgo, según el Producto en el que se almacena el Hallazgo.
	* **Estado:** el estado del Hallazgo. Puede ser Activo o Inactivo. Además de estos, los Hallazgos también pueden tener un Estado de Duplicado, Mitigado, Falso positivo, Fuera de alcance, Riesgo aceptado o En revisión de defecto. Estos Estados explican con más detalle la situación del Hallazgo.
	* **Tipo:** este campo describe cómo se encontró el Hallazgo, ya sea mediante una evaluación Estática (SAST) del código fuente, o mediante una evaluación Dinámica (DAST) del Producto mientras se estaba ejecutando. Este campo está definido por el tipo de herramienta.
	* **Ubicación:** este campo describe la Ruta de archivo relacionada con su vulnerabilidad, si corresponde.
	* **Línea:** este campo describe la línea de código que contiene la vulnerabilidad, si corresponde.
	* **Fecha de descubrimiento:** este campo muestra la fecha en que el Hallazgo se importó a DefectDojo, o la fecha en que la Herramienta descubrió el Hallazgo.
	* **Antigüedad:** este campo calculado muestra la cantidad de días que el Hallazgo ha estado activo.
	* **Informante:** este es el nombre de usuario de la cuenta de DefectDojo que creó este Hallazgo.
	* **CWE:** este campo es un enlace a la definición externa de CWE (Common Weakness Enumeration, catálogo de debilidades comunes) que se aplica a este Hallazgo.
	* **ID de vulnerabilidad:** si existe un valor de ID particular para esta vulnerabilidad dentro de la propia herramienta, se registrará aquí.
	* **Puntaje EPSS / Percentil:** si los datos de origen tienen un valor de CWE, DefectDojo obtendrá automáticamente un [Puntaje EPSS](https://www.first.org/epss/) y Percentil (Exploit Prediction Scoring System). EPSS representa la probabilidad de que una vulnerabilidad de software pueda ser explotada, basándose en datos reales de explotación. Los puntajes EPSS se actualizan de manera continua, utilizando los datos de explotación más recientes de First.
	* **Encontrado por:** aquí se indicará el escáner utilizado para encontrar esta vulnerabilidad.
	​

## Notas y menciones con @

La página de **Notas** de un Hallazgo es donde su equipo registra el contexto que no forma parte de los datos del escaneo importado: el progreso de mitigación, las decisiones de triage o cualquier otro comentario. Las Notas son metadatos exclusivos de DefectDojo y nunca se crean en el momento de la importación.

Las Notas aparecen como un feed, con las más recientes primero, y puede invertir el orden para mostrar las más antiguas primero. Cada nota muestra su autor, el momento en que se escribió, su tipo de nota y una insignia de **Privada** cuando la nota es privada. Una nota privada solo se muestra a la persona que la escribió.

### Escribir notas en markdown

Las entradas de notas admiten markdown, por lo que puede usar encabezados, texto en **negrita** y *cursiva*, listas con viñetas y numeradas, citas en bloque, tablas, enlaces y bloques de código con fences. El editor de notas es el mismo que se usa para la descripción de un Hallazgo, con una barra de herramientas para las opciones de formato más comunes. Para leer una nota exactamente como se escribió, en lugar de como texto con formato, use el interruptor en la parte superior derecha del cuerpo de la nota.

### Editar, eliminar e historial

Cada nota incluye un menú de acciones con **Editar**, **Ver historial** y **Eliminar**, y cada entrada aparece únicamente cuando tiene permiso para usarla:

* Siempre puede editar, eliminar y leer el historial de una nota que usted mismo escribió.
* Para gestionar la nota de otra persona, necesita el permiso de rol correspondiente sobre el objeto al que pertenece la nota: Note Edit, Note Delete o Note View History.
* Agregar una nota requiere Note Add, permiso que posee cada rol por encima de Reader, y que los Readers también poseen.

Una nota editada se etiqueta como **(editada)** y registra quién la modificó y cuándo. **Ver historial** enumera todas las revisiones de la nota, con las más recientes primero, de modo que no se pierde nada cuando se reescribe una nota. Solo puede cambiarse la entrada en sí: el tipo de una nota y su marca de privada quedan fijos una vez creada la nota.

### Mencionar a un usuario con @

Al agregar una nota, puede **mencionar con @** a otro usuario de DefectDojo para notificarle. Escriba `@` inmediatamente seguido de su nombre de usuario (por ejemplo, `@alice`) en cualquier parte de la nota. Al guardar la nota, cada usuario mencionado recibe una notificación de **usuario mencionado** que enlaza de vuelta a la nota.

Algunos detalles que conviene conocer:

* El `@` debe estar al **comienzo de la nota o justo después de un espacio**. Esto es intencional: evita que direcciones de correo electrónico escritas en medio de una frase (como `alice@example.com`) disparen menciones accidentales.
* El nombre que sigue a `@` debe coincidir con un nombre de usuario de DefectDojo **existente y activo**. Las menciones a usuarios desconocidos o desactivados se ignoran.
* Un punto final se ignora, de modo que una mención que termina una frase (`thanks @alice.`) sigue resolviéndose.
* Puede mencionar a más de un usuario en una sola nota.

Puede mencionar con @ a usuarios desde la interfaz en las notas de **Hallazgos**, **Tests**, **Compromisos** y **Aceptaciones de riesgo**. Al escribir `@` se abre una lista de usuarios coincidentes; elegir uno de esa lista es la forma fiable de mencionar a alguien, porque inserta el nombre de usuario exactamente como lo espera la búsqueda de notificaciones.

La mención se entrega mediante el evento de notificación `user_mentioned`. Consulte [Notificaciones](/admin/notifications/about_notifications/) para saber cómo se entregan y configuran las notificaciones; en particular, `user_mentioned` es uno de los eventos que una configuración a nivel de sistema aún puede entregar incluso cuando un usuario ha silenciado sus notificaciones de otro modo (consulte [Anulaciones específicas](/admin/notifications/about_notifications/#specific-overrides)).

## Ejemplos de flujos de trabajo de Hallazgos

La forma en que trabaja con los Hallazgos en DefectDojo depende de las responsabilidades de su equipo dentro de su organización. Aquí hay algunos ejemplos de estos procesos y cómo DefectDojo puede ayudar:

### Descubrir e informar vulnerabilidades

Si usted está a cargo de la generación de informes de seguridad para muchos contextos, Productos de software o equipos diferentes, DefectDojo puede informar sobre las vulnerabilidades detectadas. Usando la Jerarquía de Productos, puede organizar los datos de sus Hallazgos en el contexto adecuado. Por ejemplo:

* Cada Producto en DefectDojo puede tener una configuración de SLA diferente, de modo que pueda marcar instantáneamente los Hallazgos que se descubren en Producción u otros entornos altamente sensibles.
* Puede crear un informe directamente desde un **Tipo de producto, Producto, Compromiso o Test** para "acercar y alejar" su contexto de seguridad. Los **Tests** contienen resultados de una sola herramienta, los **Compromisos** pueden combinar varios Tests, los **Productos** pueden contener varios Compromisos, y los **Tipos de producto** pueden contener varios Productos.

Para obtener más información sobre cómo crear un Informe, consulte nuestras guías de **[Informes personalizados](/metrics_reports/reports/)**.

### Triage de vulnerabilidades usando el Estado del Hallazgo

Si su equipo necesita validar los Hallazgos descubiertos, puede hacerlo aplicando manualmente el estado **Verificado** a los Hallazgos a medida que los revisa. También puede aplicar otros estados, tales como:

* **Falso positivo:** Una herramienta detectó la amenaza, pero la amenaza no está activa en el entorno.
* **Fuera de alcance:** Activo, pero irrelevante para el esfuerzo de prueba actual.
* **Riesgo aceptado:** Activo, pero determinado como no prioritario para abordar hasta que expire la Aceptación de riesgo.
* **En revisión:** puede estar activo o no; su equipo todavía lo está investigando.
* **Mitigado:** Este problema se ha resuelto desde que se creó el Hallazgo.

Si una herramienta informa un Hallazgo previamente clasificado en una importación posterior, DefectDojo recordará el estado anterior del Hallazgo y lo actualizará en consecuencia. Los Hallazgos con estados **Falso positivo**, **Fuera de alcance, Riesgo aceptado y En revisión** permanecerán como están, pero cualquier Hallazgo que haya sido **Mitigado** se **reactivará** para informarle que el Hallazgo ha vuelto al entorno de Test.

### Garantizar el consenso y la responsabilidad de todo el equipo con las Aceptaciones de riesgo

Parte de la responsabilidad de un equipo de seguridad es colaborar con los desarrolladores para priorizar y despriorizar la remediación de problemas de seguridad. Aquí es donde entran las Aceptaciones de riesgo. Agregar una Aceptación de riesgo a un Hallazgo le permite:

* Almacenar registros y archivos "adjuntos" en DefectDojo; estos podrían ser correos electrónicos de colegas que reconocen la Aceptación de riesgo, notas de reuniones, o simplemente una justificación escrita para aceptar el riesgo por parte de su propio equipo de seguridad.
* Agregar una fecha de vencimiento a la Aceptación de riesgo, de modo que la vulnerabilidad pueda volver a examinarse después de un período de tiempo determinado.

Cualquier miembro de un equipo de Appsec entiende que la mitigación de problemas no puede ser priorizada exclusivamente por los equipos de desarrollo, por lo que las Aceptaciones de riesgo le ayudan a registrar esas decisiones sensibles en el momento en que se toman.

### Monitorear vulnerabilidades actuales usando CVE y puntajes EPSS (función Pro)

A veces, la explotabilidad y la amenaza que representa una vulnerabilidad conocida pueden cambiar según nuevos datos. Para mantener su trabajo actualizado, DefectDojo Pro se ha asociado con First.org para mantener una base de datos con los puntajes EPSS más recientes relacionados con los Hallazgos. Cualquier Hallazgo en DefectDojo Pro se mantendrá actualizado automáticamente según su EPSS, el cual se basa directamente en el CVE del Hallazgo.

Si el puntaje EPSS de un Hallazgo cambia (es decir, el Hallazgo relacionado se vuelve más o menos explotable), la Severidad del Hallazgo se ajustará en consecuencia.
