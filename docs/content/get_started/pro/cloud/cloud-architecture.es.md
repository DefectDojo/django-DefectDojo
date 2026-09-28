---
title: Arquitectura de Cloud
description: Cómo se implementa y aísla DefectDojo Cloud en Google Kubernetes Engine.
weight: 4
audience: pro
---

DefectDojo Cloud es una plataforma SaaS multiinquilino que se ejecuta en **Google Kubernetes
Engine (GKE)** en Google Cloud. Esta página describe cómo está estructurada
la plataforma y cómo se mantienen separados los entornos de los clientes.

![Arquitectura de Kubernetes de DefectDojo Cloud: el tráfico del cliente entra a través de Google Cloud Load Balancing con TLS gestionado por Google hacia clústeres regionales de GKE; cada cliente se ejecuta en su propio namespace de Kubernetes con una base de datos PostgreSQL dedicada, un bucket de Cloud Storage y un proyecto de Vertex AI dedicados.](images/cloud_architecture_kubernetes.svg)

## Cómo fluye una solicitud

1. El tráfico del cliente (navegador, API o CI) llega por **HTTPS** a **Google
   Cloud Load Balancing**, que termina el TLS usando certificados
   gestionados por Google.
2. El balanceador de carga enruta la solicitud hacia el entorno del cliente dentro de un
   **clúster regional de GKE**, donde la capa web/API (django, servida por nginx y
   uWSGI) la gestiona.
3. La capa web lee y escribe en la **base de datos PostgreSQL dedicada**
   y el **bucket de Cloud Storage dedicado** del cliente, y usa una **caché dentro del namespace**
   (Redis/Valkey) para las sesiones y como intermediario de tareas (task broker).
4. El trabajo de mayor duración, como las importaciones de escaneos, la deduplicación y las notificaciones,
   se entrega a **workers asíncronos** (Celery) para que las solicitudes sigan siendo receptivas.

## Aislamiento de inquilinos

Cada cliente se ejecuta en su **propio namespace de Kubernetes**, y los datos que cada
cliente almacena nunca comparten almacenamiento con otro cliente:

- **Base de datos dedicada**: una base de datos PostgreSQL independiente por cliente (Cloud SQL).
- **Almacenamiento de objetos dedicado**: un bucket de Cloud Storage independiente por cliente para
  los escaneos y medios cargados, montado en las cargas de trabajo mediante el driver CSI de GCS FUSE.
- **Caché dedicada**: cada namespace ejecuta su propia instancia de Redis/Valkey.
- **Credenciales por cliente**: cada entorno tiene sus propios secretos y su propio
  certificado TLS y nombre de host.

No existe un **plano de datos de aplicación compartido** entre clientes. Los datos se cifran
en tránsito (TLS) y en reposo (cifrado predeterminado de Google Cloud).

## Regiones y residencia de datos

La plataforma ejecuta **clústeres regionales de GKE en múltiples geografías** (por
ejemplo, Norteamérica, Europa y Asia-Pacífico). El entorno de un cliente, junto
con su base de datos y su bucket de almacenamiento, reside en la región seleccionada para ese
cliente, lo que permite cumplir con los requisitos de residencia de datos.

## Cargas de trabajo en un entorno de cliente

Cada namespace contiene los componentes necesarios para ejecutar DefectDojo Pro de principio a fin:

| Grupo | Propósito |
|---|---|
| **Web y API** | Sirve la UI y la API REST (django · nginx + uWSGI). |
| **Procesamiento asíncrono** | Trabajos en segundo plano y programación (Celery workers + beat). |
| **Orquestación** | Coordina flujos de trabajo de varios pasos en toda la plataforma. |
| **Integraciones** | Conectores e integraciones de tickets. |
| **Servidor MCP** | Interfaz de IA para conectar sus propias herramientas de IA. |
| **Sensei** | Corrección mediante IA a través de la plataforma Vertex de Google. |
| **Caché dentro del namespace** | Redis/Valkey para sesiones e intermediación de tareas. |

En cada despliegue, un **job inicializador** de corta duración ejecuta las migraciones de base de datos antes de
que la nueva versión atienda tráfico.

## Aislamiento de Sensei y de la IA

Sensei, la capacidad de corrección mediante IA de DefectDojo, se ejecuta a través de la
**plataforma Vertex de Google** con el mismo aislamiento por cliente que el resto del plano de datos:

- Las solicitudes de Sensei de cada cliente se ejecutan en **el proyecto de GCP dedicado
  de ese cliente**, autenticadas con **credenciales por cliente**.
- No existe una multiinquilinato de IA compartido: las instrucciones (prompts), hallazgos y resultados de un cliente
  nunca pasan por el entorno de otro cliente.
- Solo se usa un **proveedor de IA externo si el cliente configura uno** (por
  ejemplo, a través del servidor MCP o una integración de IA proporcionada por el cliente).

## Servicios y operaciones de la plataforma

Los servicios compartidos y gestionados por Google respaldan a cada entorno sin transportar
datos de clientes entre inquilinos:

- **Artifact Registry**: imágenes de contenedor firmadas.
- **Secret Manager**: material de secretos y claves.
- **Cloud Monitoring y Logging**: métricas, registros y alertas usados por nuestro
  equipo de guardia. Los node pools se **autoescalan** para absorber la carga.

El único dato compartido entre clientes es el enriquecimiento público de vulnerabilidades
(EPSS y KEV).

## Las integraciones son solo salientes

Las conexiones con sistemas externos, como correo electrónico (SMTP), tickets (Jira,
ServiceNow y otros), escáneres de seguridad y monitoreo de errores, son
**configuradas por el cliente e iniciadas de forma saliente** desde el entorno
del cliente.

## Aislamiento por nivel

DefectDojo Cloud se ofrece en niveles que difieren en cuánto de la pila está
dedicado a un solo cliente:

![Aislamiento de inquilinos de DefectDojo Cloud por nivel: los inquilinos Standard y Pay-as-you-go se ejecutan en namespaces aislados en un clúster de GKE compartido y comparten una instancia de PostgreSQL con bases de datos lógicas por inquilino; los inquilinos Premium obtienen una base de datos PostgreSQL dedicada; el nivel Dedicated se ejecuta en su propio clúster de GKE, VPC y proyecto de GCP.](images/cloud_architecture_tiers.svg)

| Nivel | Cómputo | Base de datos | Límite de red | Sensei |
|---|---|---|---|---|
| **Standard** | Namespace aislado en un clúster compartido | Base de datos lógica y credenciales propias en una instancia de PostgreSQL compartida | VPC compartida, nombre de host por inquilino + TLS, lista de IP permitidas opcional | Incluido |
| **Pay-as-you-go** *(próximamente)* | Namespace aislado en un clúster compartido | Base de datos lógica y credenciales propias en una instancia de PostgreSQL compartida | VPC compartida, nombre de host por inquilino + TLS, lista de IP permitidas opcional | Incluido |
| **Premium** | Namespace aislado en un clúster compartido | **Base de datos PostgreSQL dedicada** por cliente | VPC compartida, nombre de host por inquilino + TLS, lista de IP permitidas opcional | Incluido |
| **Dedicated** | **Clúster de GKE propio** | **Base de datos PostgreSQL dedicada** en la VPC propia del cliente | **Proyecto de GCP y VPC propios**, ingress restringido al rango de IP del cliente | Incluido |

Sensei está incluido en todos los niveles, y en todos los niveles se ejecuta a través de la
plataforma Vertex de Google en el proyecto de GCP propio del cliente con credenciales por cliente.

*¿Tiene alguna pregunta que esta página no responde? Contacte a su representante
de DefectDojo.*
