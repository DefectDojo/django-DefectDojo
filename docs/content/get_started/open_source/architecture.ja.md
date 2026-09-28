---
title: システムアーキテクチャ
description: DefectDojoプラットフォームは、緊密に連携する複数のコンポーネントで構成されています。
draft: false
weight: 1
audience: opensource
aliases:
- /ja/en/open_source/installation/architecture
---

![image](images/dd-architecture.png)

## NGINX

Webサーバーである[NGINX](https://nginx.org/en/)は、画像、JavaScriptファイル、CSSファイルなど、すべての静的コンテンツを配信します。

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/)は、Python/Djangoで書かれたDefectDojoプラットフォームを実行し、すべての動的コンテンツを提供するアプリケーションサーバーです。

## メッセージブローカー

アプリケーションサーバーは、非同期実行のためにタスクを[メッセージブローカー](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)に送信します。現在、docker compose構成ではブローカーとして[Valkey](https://valkey.io/)のみがサポートされています。
Helmチャートは引き続きブローカーとして[Redis](https://github.com/redis/redis)を使用していますが、間もなくValkeyに移行される予定です。


## Celery Worker

重複排除やJIRA同期などのタスクは、[Celery](https://docs.celeryproject.org/en/stable/) Workerによってバックグラウンドで非同期に実行されます。

## Celery Beat

今後予定されているエンゲージメントなどについてユーザーに識別・通知するために、DefectDojoはスケジュールされたタスクを実行します。これらのタスクは、Celery
Beatを使用してスケジュール・実行されます。

## Initializer

Initializerは、データベースをセットアップ・維持し、バージョンアップグレード後に
マイグレーションを同期・実行します。すべてのタスクが完了すると、自動的に
シャットダウンします。

## データベース

データベースは、DefectDojoのすべてのアプリケーションデータを保存します。現在は[PostgreSQL](https://www.postgresql.org/)のみがサポートされています。
