---
title: 設定
description: DefectDojoは高度に設定可能です。
draft: false
weight: 2
audience: opensource
aliases:
- /ja/en/open_source/installation/configuration
---

## dojo/settings/settings.dist.py

主要な設定は[`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py)に保存されています。このファイルは、何を設定できるかを確認するための参考として使用するには最適ですが、DefectDojoの更新時に変更が上書きされてしまうため、直接編集すべきではありません。デフォルト設定を変更する方法はいくつかあります。

### 環境変数

ほとんどのパラメータは環境変数で設定できます。

**Docker Compose**を使ってDefectDojoをデプロイする場合、[`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml)で環境変数を設定できます。`uwsgi`、`celerybeat`、`celeryworker`という3つのサービスすべてに対して変数を設定する必要がある点に注意してください。

**Kubernetes**クラスターにDefectDojoをデプロイする場合、[`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml)内の`extraConfigs`および`extraSecrets`として環境変数を設定できます。

### 環境ファイル(Docker ComposeまたはKubernetesを使用しない場合)

`settings.dist.py`は、環境変数`DD_ENV_PATH`で指定された名前のファイルから環境変数を読み込みます。この変数が設定されていない場合、デフォルトの`.env.prod`が使用されます。このファイルは`dojo/settings`ディレクトリに配置する必要があります。

例は[`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env)にあります。

### local_settings.py

`local_settings.py`には、MIDDLEWAREやINSTALLED_APPのエントリの追加など、より複雑なカスタマイズを含めることができます。
このファイルはsettings.dist.pyが処理された*後に*処理されるため、DefectDojoが標準で提供する設定を変更できます。
 このファイルは`dojo/settings`ディレクトリに配置する必要があります。このファイル内の環境変数には`DD_`プレフィックスを付けてはいけません。
ファイルが存在しない場合は、自由に作成してください。`settings.dist.py`を直接編集しないでください。

例は[`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings)にあります。

Docker Composeのリリースモードでは、`docker/extra_settings/`(`docker-compose.yml`ファイルからの相対パス)内のファイルが、起動時にdockerコンテナ内の`dojo/settings/`にコピーされます。

`local_settings.py`はKubernetesでも使用できます。変数`localsettingspy`はConfigMapとして保存され、コンテナの該当する場所にマウントされます。

## UIでの設定

スーパーユーザー権限を持つユーザーは、UIの`Configuration` / `System Settings`から、さらに多くのオプションを設定できます。
