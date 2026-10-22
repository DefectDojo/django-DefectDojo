---
title: 系统架构
description: DefectDojo 平台由多个紧密协作的组件构成。
draft: false
weight: 1
audience: opensource
aliases:
- /zh-hans/en/open_source/installation/architecture
---

![image](images/dd-architecture.png)

## NGINX

Web 服务器 [NGINX](https://nginx.org/en/) 负责提供所有静态内容，例如
图片、JavaScript 文件或 CSS 文件。

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) 是运行 DefectDojo 平台的应用服务器，
该平台使用 Python/Django 编写，用于提供所有
动态内容。

## 消息代理

应用服务器将任务发送到[消息代理](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)
以进行异步执行。目前，在 docker compose 部署中仅支持将 [Valkey](https://valkey.io/) 作为代理。
Helm chart 仍然支持使用 [Redis](https://github.com/redis/redis) 作为代理，但很快将迁移到 Valkey。


## Celery Worker

诸如去重或 JIRA 同步之类的任务由 [Celery](https://docs.celeryproject.org/en/stable/)
Worker 在后台异步执行。

## Celery Beat

为了识别即将到来的测试活动等信息并通知用户，
DefectDojo 会运行计划任务。这些任务通过 Celery
Beat 进行调度和运行。

## Initializer

Initializer 用于设置/维护
数据库，并在版本升级后同步/运行迁移。所有任务
执行完毕后，它会自动关闭。

## 数据库

数据库存储 DefectDojo 的所有应用数据。目前仅支持 [PostgreSQL](https://www.postgresql.org/)。
