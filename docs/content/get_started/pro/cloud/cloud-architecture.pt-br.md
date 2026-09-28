---
title: Arquitetura da Cloud
description: Como o DefectDojo Cloud é implantado e isolado no Google Kubernetes Engine.
weight: 4
audience: pro
---

O DefectDojo Cloud é uma plataforma SaaS multi-tenant executada no **Google Kubernetes
Engine (GKE)** no Google Cloud. Esta página descreve como a plataforma é
estruturada e como os ambientes dos clientes são mantidos separados.

![Arquitetura Kubernetes do DefectDojo Cloud: o tráfego do cliente entra pelo Google Cloud Load Balancing com TLS gerenciado pelo Google em clusters GKE regionais; cada cliente roda em seu próprio namespace Kubernetes com um banco de dados PostgreSQL dedicado, um bucket do Cloud Storage e um projeto do Vertex AI.](images/cloud_architecture_kubernetes.svg)

## Como uma requisição flui

1. O tráfego do cliente (navegador, API ou CI) chega via **HTTPS** ao **Google
   Cloud Load Balancing**, que encerra o TLS usando certificados
   gerenciados pelo Google.
2. O load balancer roteia a requisição para dentro do ambiente do cliente, dentro de um
   **cluster GKE regional**, onde a camada web/API (django, servida por nginx e
   uWSGI) a processa.
3. A camada web lê e escreve no **banco de dados PostgreSQL dedicado**
   e no **bucket do Cloud Storage dedicado** do cliente, e usa um **cache dentro do namespace**
   (Redis/Valkey) para sessões e como broker de tarefas.
4. Trabalhos de execução mais longa, como importações de scan, deduplicação e notificações,
   são repassados a **workers assíncronos** (Celery) para que as requisições continuem responsivas.

## Isolamento de tenants

Cada cliente roda em seu **próprio namespace Kubernetes**, e os dados que cada
cliente armazena nunca compartilham um repositório com outro cliente:

- **Banco de dados dedicado**: um banco de dados PostgreSQL separado por cliente (Cloud SQL).
- **Armazenamento de objetos dedicado**: um bucket do Cloud Storage separado por cliente para
  scans e mídias enviados, montado nas cargas de trabalho via GCS FUSE CSI driver.
- **Cache dedicado**: cada namespace roda sua própria instância Redis/Valkey.
- **Credenciais por cliente**: cada ambiente tem seus próprios secrets e seu próprio
  certificado TLS e hostname.

Não há **plano de dados de aplicação compartilhado** entre clientes. Os dados são criptografados
em trânsito (TLS) e em repouso (criptografia padrão do Google Cloud).

## Regiões e residência de dados

A plataforma roda **clusters GKE regionais em múltiplas geografias** (por
exemplo, América do Norte, Europa e Ásia-Pacífico). O ambiente de um cliente, junto
com seu banco de dados e bucket de armazenamento, reside na região selecionada para esse
cliente, o que atende a requisitos de residência de dados.

## Cargas de trabalho em um ambiente de cliente

Cada namespace contém os componentes necessários para rodar o DefectDojo Pro de ponta a ponta:

| Grupo | Finalidade |
|---|---|
| **Web e API** | Serve a UI e a API REST (django · nginx + uWSGI). |
| **Processamento assíncrono** | Jobs em segundo plano e agendamento (Celery workers + beat). |
| **Orquestração** | Coordena fluxos de trabalho de múltiplas etapas em toda a plataforma. |
| **Integrações** | Conectores e integrações de ticketing. |
| **Servidor MCP** | Interface de IA para conectar suas próprias ferramentas de IA. |
| **Sensei** | Remediação por IA através do Vertex Platform do Google. |
| **Cache dentro do namespace** | Redis/Valkey para sessões e broker de tarefas. |

A cada deploy, um **job inicializador** de curta duração executa as migrações de banco de dados antes
que a nova versão passe a atender o tráfego.

## Sensei e isolamento de IA

O Sensei, a funcionalidade de remediação por IA do DefectDojo, roda através do **Vertex
Platform do Google** com o mesmo isolamento por cliente do restante do plano de dados:

- As requisições do Sensei de cada cliente rodam no **projeto GCP dedicado
  desse cliente**, autenticadas com **credenciais por cliente**.
- Não há tenancy de IA compartilhada: os prompts, achados e resultados de um cliente
  nunca passam pelo ambiente de outro cliente.
- Um **provedor externo de IA só é usado se o cliente configurar um** (por
  exemplo, através do servidor MCP ou de uma integração de IA fornecida pelo cliente).

## Serviços e operações de plataforma

Serviços compartilhados e gerenciados pelo Google dão suporte a todos os ambientes sem transportar
dados de clientes entre tenants:

- **Artifact Registry**: imagens de container assinadas.
- **Secret Manager**: material de secrets e chaves.
- **Cloud Monitoring & Logging**: métricas, logs e alertas usados pela nossa
  equipe de plantão. Os node pools fazem **autoscaling** para absorver a carga.

O único dado compartilhado entre clientes é o enriquecimento de vulnerabilidade público
(EPSS e KEV).

## As integrações são somente de saída

Conexões com sistemas externos, como e-mail (SMTP), ticketing (Jira,
ServiceNow e outros), scanners de segurança e monitoramento de erros, são
**configuradas pelo cliente e iniciadas em saída** a partir do ambiente do
cliente.

## Isolamento por tier

O DefectDojo Cloud é oferecido em tiers que diferem quanto à parcela do stack
dedicada a um único cliente:

![Isolamento de tenants do DefectDojo Cloud por tier: os tenants Standard e Pay-as-you-go rodam em namespaces isolados em um cluster GKE compartilhado e compartilham uma instância PostgreSQL com bancos de dados lógicos por tenant; os tenants Premium têm um banco de dados PostgreSQL dedicado; o tier Dedicated roda em seu próprio cluster GKE, VPC e projeto GCP.](images/cloud_architecture_tiers.svg)

| Tier | Computação | Banco de dados | Fronteira de rede | Sensei |
|---|---|---|---|---|
| **Standard** | Namespace isolado em um cluster compartilhado | Banco de dados lógico e credenciais próprios em uma instância PostgreSQL compartilhada | VPC compartilhada, hostname + TLS por tenant, allowlist de IP opcional | Incluído |
| **Pay-as-you-go** *(em breve)* | Namespace isolado em um cluster compartilhado | Banco de dados lógico e credenciais próprios em uma instância PostgreSQL compartilhada | VPC compartilhada, hostname + TLS por tenant, allowlist de IP opcional | Incluído |
| **Premium** | Namespace isolado em um cluster compartilhado | **Banco de dados PostgreSQL dedicado** por cliente | VPC compartilhada, hostname + TLS por tenant, allowlist de IP opcional | Incluído |
| **Dedicated** | **Cluster GKE próprio** | **Banco de dados PostgreSQL dedicado** na VPC própria do cliente | **Projeto GCP e VPC próprios**, ingress restrito ao intervalo de IP do cliente | Incluído |

O Sensei está incluído em todos os tiers, e em todos eles roda através do
Vertex Platform do Google, no projeto GCP próprio do cliente, com credenciais por cliente.

*Tem alguma pergunta que esta página não responde? Entre em contato com seu
representante DefectDojo.*
