---
title: Arquitetura do sistema
description: A plataforma DefectDojo é composta por diversos componentes que trabalham
  em conjunto de forma integrada.
draft: false
weight: 1
audience: opensource
aliases:
- /pt-br/en/open_source/installation/architecture
---

![image](images/dd-architecture.png)

## NGINX

O servidor web [NGINX](https://nginx.org/en/) entrega todo o conteúdo estático, por exemplo,
imagens, arquivos JavaScript ou arquivos CSS.

## uWSGI

O [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) é o servidor de aplicação
que executa a plataforma DefectDojo, escrita em Python/Django, para servir todo o
conteúdo dinâmico.

## Message Broker

O servidor de aplicação envia tarefas para um [Message Broker](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)
para execução assíncrona. Atualmente, apenas o [Valkey](https://valkey.io/) é suportado como broker na configuração do docker compose.
O Helm chart ainda usa o [Redis](https://github.com/redis/redis) como broker suportado, mas será migrado para o Valkey em breve.


## Celery Worker

Tarefas como a deduplicação ou a sincronização com o JIRA são executadas de forma assíncrona
em segundo plano pelo Worker do [Celery](https://docs.celeryproject.org/en/stable/).

## Celery Beat

Para identificar e notificar os usuários sobre coisas como engajamentos futuros,
o DefectDojo executa tarefas agendadas. Essas tarefas são agendadas e executadas usando o Celery
Beat.

## Initializer

O Initializer configura/mantém o
banco de dados e sincroniza/executa migrações após atualizações de versão. Ele se desliga
automaticamente depois que todas as tarefas são concluídas.

## Banco de dados

O Banco de dados armazena todos os dados da aplicação do DefectDojo. Atualmente, apenas o [PostgreSQL](https://www.postgresql.org/) é suportado.
