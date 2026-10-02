---
title: Registros de auditoría
description: Acceda a los registros de auditoría de los objetos de DefectDojo
weight: 1
audience: pro
---

Los **Registros de auditoría** proporcionan un registro cronológico de las acciones realizadas dentro de DefectDojo. Garantizan la responsabilidad y el cumplimiento normativo al registrar qué usuario realizó qué acción y cuándo.

Los registros de auditoría son valiosos para:
- **Investigaciones de seguridad**: determinar quién realizó acciones sensibles.
- **Cumplimiento normativo**: demostrar un historial auditable para estándares como SOC 2, ISO 27001 u otros requisitos de gobernanza interna.
- **Resolución de problemas**: identificar cuándo cambió una configuración u objeto.
- **Responsabilidad**: hacer seguimiento de la actividad administrativa y de los usuarios en toda la plataforma.

En resumen, los Registros de auditoría proporcionan un registro centralizado de eventos importantes que ayuda a los administradores a comprender el historial de actividad de su instancia más allá del historial de cualquier objeto individual.

### Acceso a los Registros de auditoría

Se puede acceder a los Registros de auditoría desde la barra lateral, dentro del submenú de Configuraciones.

![image](images/auditlogs_ss2.png)

### Permisos

El acceso a los Registros de auditoría se determina según el rol global del Usuario.

Los roles globales de API Importer, Reader y Writer no permiten el acceso a los Registros de auditoría, mientras que los roles Maintainer y Owner sí lo hacen. Los superusuarios también tienen acceso a los Registros de auditoría independientemente de su rol global.

Puede encontrar más información sobre permisos y roles globales [aquí](/admin/user_management/pro_permissions_overhaul/).

## Contenido de los Registros de auditoría

Los Registros de auditoría hacen seguimiento de una variedad de acciones, incluyendo, entre otras:
- Interacciones con objetos (por ejemplo, crear, actualizar o eliminar objetos).
- Actualizaciones de la prioridad y la puntuación de riesgo de un Hallazgo.
- Creación y edición de perfiles de Usuario.
- Actualizaciones del percentil EPSS.

La lista completa de cambios y acciones registrados en los Registros de auditoría se puede encontrar [aquí](../pro__audit_log_index/).

## Tabla de Registros de auditoría

Los Registros de auditoría incluyen varias columnas con distintos datos para mejorar la trazabilidad, entre ellas:
- **Timestamp**: la hora en la que ocurrió el cambio.
- **Usuario**: el usuario que realizó la acción.
- **Action**: qué acción se realizó (por ejemplo, crear, actualizar, eliminar).
- **Model**: qué aspecto se modificó (por ejemplo, Asset, User, Finding, Location, Firewall, URL, etc.).
- **Object ID**: el ID único de DefectDojo para el objeto que se modificó.
- **Object Name**: el nombre del objeto afectado.
- **Changes**: campos específicos modificados por la acción, incluyendo sus valores anteriores y actualizados.
- **Data**: una instantánea exacta del registro en el momento en que se realizó la acción, incluyendo todos los campos, no solo los que cambiaron.
- **Context**: detalles del contexto de cómo ocurrió el cambio, quién lo hizo, desde dónde en la aplicación se originó, y una etiqueta que indica qué job realizó el cambio (si se trató de un job automatizado).
- **URL**: la URL utilizada para ejecutar la operación en cuestión. Estas rutas pueden referirse a la interfaz Vue de DefectDojo o a la API REST. El campo URL no se completará para los procesos de back-end.
- **IP Address**: la dirección de red del dispositivo que realizó el cambio. Este campo no se completará para los procesos de back-end.

### Cronología de los Registros de auditoría

De forma predeterminada, los Registros de auditoría muestran las entradas de los últimos 31 días. Las entradas más antiguas siguen estando disponibles y se pueden consultar ajustando el filtro Timestamp.

![image](images/auditlogs_ss3.gif)

### Filtrado de los Registros de auditoría

La tabla de Registros de auditoría incluye filtros que ayudan a acotar los resultados mostrados. Por ejemplo, si desea ver únicamente las acciones relacionadas con Assets, puede filtrar por Assets dentro de la tabla.

![image](images/auditlogs_ss1.png)

Las columnas de los Registros de auditoría también se pueden ordenar alfabéticamente, en orden ascendente/descendente o cronológico, según el contenido de la columna en cuestión. Las columnas también se pueden arrastrar hacia la izquierda o la derecha según el orden preferido.

![image](images/auditlogs_ss4.gif)

## Historial del objeto

El **Historial del objeto** proporciona un registro cronológico de los cambios realizados en un objeto individual de DefectDojo (por ejemplo, Organization, Asset, Compromiso, Test, Hallazgos, Endpoints y Aceptaciones de riesgo). Cada entrada incluye detalles como la marca de tiempo, el usuario, la acción realizada y los cambios asociados.

A diferencia de los Registros de auditoría, que registran eventos en toda la instancia, el Historial del objeto se limita estrictamente a la actividad de un solo objeto, lo que facilita comprender el historial de un objeto sin tener que filtrar eventos del sistema no relacionados.

El Historial del objeto es útil para:
- Revisar la evolución de un objeto a lo largo del tiempo.
- Determinar cuándo se realizó un cambio.
- Identificar qué usuario hizo una modificación.
- Resolver cambios inesperados.

### Acceso al Historial del objeto

Se puede acceder al Historial del objeto a través del menú de engranaje en la esquina superior derecha de la vista de cualquier objeto. Solo los Usuarios con acceso al objeto en cuestión pueden ver su Historial del objeto.

### Registros de auditoría e Historial del objeto

Aunque la función de los Registros de auditoría y el Historial del objeto se superpone, operan en ámbitos diferentes. El Historial del objeto se centra en los cambios realizados en objetos individuales, mientras que los Registros de auditoría ofrecen un registro de eventos significativos en toda su instancia de DefectDojo, brindando una vista panorámica más amplia de la actividad.

## Endpoints

### Endpoint de historial del objeto (solo Pro)

Los usuarios de <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> tienen acceso a una ruta de API `/history` para estos objetos, con la que pueden consultar datos similares. Por ejemplo: `/api/v2/findings/{id}/history/`.

### Endpoint de registro de auditoría (solo Pro)

Los usuarios de <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> también tienen acceso a un endpoint dedicado `/audit_log` para toda su instancia. Solo pueden acceder a este registro los usuarios o tokens de API con permisos de superusuario.

Esta API devuelve 31 días de registros de auditoría.

* Enviar parámetros predeterminados o vacíos devolverá los registros de auditoría de los últimos 31 días.

* El parámetro `window_month` toma un mes y un año en formato MM-YYYY y proporciona los registros de auditoría de ese mes.
* Puede configurar el parámetro `window_start` para limitar estos registros a una ventana más corta, en lugar de devolver el mes completo.

Para obtener más información, consulte la documentación de la API, ubicada en su instancia: `your-instance.cloud.defectdojo.com/api/v2/oa3/swagger-ui/`
