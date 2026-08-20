---
title: 在离线（气隙）环境中安装 DefectDojo Pro
description: 先在有互联网访问权限的主机上准备好 DefectDojo Pro 安装所需的制品，然后将其转移到离线（气隙）网络中
draft: false
weight: 8
audience: pro
---

本页是对 DefectDojo Pro 许可证随附的安装说明的补充。内容仅涉及目标主机无法访问互联网时需要更改的部分。其余部分，包括主机的前提条件和 PostgreSQL 设置，均遵循标准说明进行。

该方法使用两台主机。一台具备正常互联网访问权限的暂存主机（staging host）用于下载部署制品和容器镜像。随后，您通过环境所允许的任何传输方式，将这些制品转移到离线网络中，并在无法访问 DefectDojo 网络的目标主机上完成安装。

请规划让暂存主机日后仍可再次访问。升级过程会重复相同的传输流程，因此保留该主机是值得的。

## What you need

在暂存主机上，需要一台具备互联网访问权限、已安装 Docker 的 Linux 主机，并具备足够的可用磁盘空间，用于存放部署目录以及压缩后的容器镜像。镜像占用了其中的大部分空间，每个镜像可达数百兆字节。

在离线（气隙）主机上，需要已安装并可正常运行的 Docker，以及一台已按标准安装说明预先配置好且可访问的 PostgreSQL 服务器。

两台主机上都需要一份 DefectDojo 提供的 `dojo-compose-cli` 压缩包和您的许可证文件。请使用 2.1.0 或更高版本的 CLI。较早版本没有离线（气隙）模式，缺少该模式时，CLI 会在执行每条命令时尝试连接容器镜像仓库，并因名称解析错误而失败，而不会明确告知问题所在。

## Stage the artifacts

在暂存主机上执行以下步骤。

### 1. Register the CLI

如果尚未安装 Docker，请先进行安装。有关适用于您所用发行版的具体说明，请参阅 [Docker 安装文档](https://docs.docker.com/engine/install/)。

解压 CLI 压缩包，然后进行注册：

```bash
sudo ./dojo-compose-cli register
```

注册操作会将 CLI 安装到 `/usr/bin`，创建 `dojosrv` 组，将您的用户添加到 `dojosrv` 和 `docker` 组，验证许可证，并使 Docker 通过身份验证以访问 DefectDojo 容器镜像仓库。

系统会提示您输入 `DOJO_CLI_KEY`，该密钥用于加密磁盘上 CLI 存储的配置。将其设置为环境变量，可避免每次执行命令时都被提示输入：

```bash
export DOJO_CLI_KEY="your-key"
```

新的组成员身份不会立即应用于当前 shell。您可以打开一个新的会话，或者按以下方式立即生效：

```bash
newgrp docker
```

使用 `id` 命令确认输出中同时列出了 `docker` 和 `dojosrv`。一旦您的用户加入 `docker` 组，后续命令就无需使用 `sudo`。

如果暂存主机是通过出站 HTTPS 代理访问互联网的，请在拉取任何内容之前先配置好代理相关变量。请参阅[在正向 HTTPS 代理后运行 DefectDojo](/onprem_deployment/forward_proxy/)。

### 2. Set the version

将部署版本和应用程序版本都设置为您打算安装的发行版本，并将 `x.y.z` 替换为实际版本号：

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

两条命令中请使用相同的版本号，并在本流程的后续步骤中保持一致。如果部署制品与镜像的版本不一致，会导致技术栈无法启动，或者启动时使用了错误的镜像。

### 3. Download the deployment artifacts and images

下载部署目录：

```bash
dojo-compose-cli deploy download
```

该命令会向 `/opt/dojo` 填充 compose 文件、nginx 配置、问题跟踪工具模板、customizations 目录，以及与您所选发行版本对应的带版本号子目录。

然后拉取容器镜像：

```bash
dojo-compose-cli app pull-images
```

确认已获取的内容：

```bash
docker image ls
```

请记下该输出中 DefectDojo 各镜像共用的镜像仓库前缀（repository prefix）。下一步会用到它，并且不同发行版本所包含的镜像集合有所不同，因此请以您自己的输出为准，而不要假定某个固定列表。

### 4. Record the generated configuration

标准安装流程会在首次运行时生成若干配置值。而在离线（气隙）安装中，您需要在目标主机上手动设置这些值，因此请现在先将它们记录下来：

```bash
dojo-compose-cli environment print | head -n 9
```

请保留凭证加密密钥（credential encryption key）和 secret key。两者均为自动生成的 64 字符随机字符串，其中凭证密钥必须与加密凭证时所使用的密钥完全一致，因此请准确记录，并作为机密信息妥善保存。同一输出中的 uwsgi 和 celery 相关取值，也可作为目标主机配置的初始参考。

请将此输出视为敏感信息，因为其中包含了保护您部署环境中所存储凭证的密钥。

### 5. Package everything

创建一个用于传输的目录，并在目录名中包含版本号，以便日后能明确区分其中的内容：

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

对部署目录进行归档，并保留其权限设置：

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

保存容器镜像。以下脚本会使用您在第 3 步中记下的镜像仓库前缀，保存所有匹配的镜像并进行压缩：

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

为其赋予可执行权限，并使用您的前缀运行该脚本：

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

检查第 3 步中的每个镜像是否都生成了对应文件，然后对该目录进行打包：

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

使用您常规的传输流程，将 `artifacts-x.y.z.tar.gz` 转移到离线（气隙）网络中；如果 CLI 压缩包和许可证文件尚未转移过去，也请一并转移。

## Install on the air-gapped host

### 6. Install the CLI and enable air-gapped mode

解压 CLI 压缩包，然后将许可证文件放置到 CLI 所期望的位置：

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

启用离线（气隙）模式。这是您在该主机上执行的第一条 CLI 命令，它会将 CLI 安装到 `/usr/bin`，根据文件验证许可证，并在此过程中对存储的配置进行加密：

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

确认设置已生效：

```bash
dojo-compose-cli config print
```

输出中会包含设置为 true 的 `Air Gapped Deploy`。同样，请在此处将 `DOJO_CLI_KEY` 设置为环境变量，以便后续命令不再提示输入。

请勿在该主机上运行 `register`。注册操作的目的是对容器镜像仓库进行身份验证，而按照定义该仓库是无法访问的，因此在离线（气隙）模式下，CLI 会直接拒绝执行该命令，而不会尝试执行。其他需要访问镜像仓库的命令也是如此：

| Command | Behavior in air-gapped mode |
| --- | --- |
| `register` | 拒绝执行。无法进行镜像仓库身份验证。 |
| `deploy download` | 拒绝执行。请改为在暂存主机上运行。 |
| `app pull-images` | 拒绝执行。请改为在暂存主机上运行。 |
| `app upgrade` | 拒绝执行。请参阅下文的升级部分。 |
| `app start`, `app stop`, `app restart` | 可用。这些命令不会连接镜像仓库。 |

每条被拒绝的命令退出时都会给出提及离线（气隙）模式的消息，因此这里出现的拒绝是 CLI 按预期工作的表现，而不是需要排查的故障。

在继续之前，请先使新的组成员身份生效：

```bash
newgrp docker
```

### 7. Restore the deployment directory

解压传输包，然后将部署归档文件移动到相应位置：

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

设置 CLI 的过程可能已创建了一个几乎为空、仅包含许可证的 `/opt/dojo` 目录。如果该目录存在，请先将其删除，以避免归档内容与其合并：

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

解压真正的部署目录，然后修正所有权和 media 目录的权限：

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. Set the configuration by hand

离线（气隙）安装不会使用交互式的首次安装流程，因此需要手动设置那些原本会自动生成的值。请使用您在第 4 步中记录的密钥：

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

将版本设置为与您所转移的制品相匹配的版本：

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

设置站点 URL 和允许的主机（allowed hosts）。站点 URL 必须是在您的网络内部能够解析到该主机的地址：

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

设置数据库连接，使用您此前配置好的 PostgreSQL 服务器：

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. Load the container images

以下脚本会加载镜像目录中的每一个镜像文件：

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

在解压后的制品目录内运行该脚本：

```bash
chmod u+x load-images.bash
./load-images.bash
```

然后使用 `docker image ls` 确认所有镜像均已加载，且版本符合预期。

### 10. Start the stack

使用 CLI 启动技术栈。该操作在离线（气隙）模式下同样有效，因为它读取的是您已设置的配置，并基于本地 compose 文件运行，而无需连接镜像仓库：

```bash
dojo-compose-cli app start
```

`app stop` 和 `app restart` 同样可以这样使用。每次更改任何环境变量后，请使用 `app restart`，因为它会重新创建容器，使新的值生效。

如果技术栈未能正常启动，请检查以下两点。该命令需要部署目录已就绪，因此请确认第 7 步生成的 `/opt/dojo/docker-compose.yml` 文件确实存在。此外，所配置的版本决定了所使用的镜像标签，因此必须与您在第 9 步中加载的镜像相匹配。

完成后，即可通过您设置为站点 URL 的地址访问 DefectDojo。

## Upgrading an air-gapped deployment

`app upgrade` 需要从容器镜像仓库下载内容，因此它属于离线（气隙）模式所拒绝执行的命令之一。升级流程遵循与安装相同的路径，而不是通过单条命令完成。

在暂存主机上，设置新版本号，并针对该版本重复第 3 步到第 5 步的操作。将新的传输包转移过去，加载新镜像，然后在离线（气隙）主机上将版本设置为新版本并重新启动：

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

有两点容易让人踩坑。如果在未更改所配置版本的情况下重新启动，技术栈仍会使用您原有的镜像重新运行，因为版本决定了所使用的镜像标签。另外，不同发行版本所包含的镜像集合可能会发生变化，因此请将您已加载的镜像与新版本拉取所产生的镜像进行对比，而不要假定原有列表依然适用。

您现有的部署目录不会自动获取新版本的 compose 文件或 nginx 配置，因此请像第 7 步那样恢复新的 `/opt/dojo` 内容，同时保留您自己的 customizations、证书和 media 内容。

在进行任何升级之前，请先备份数据库，并查阅从您当前版本到目标版本之间每个版本的[升级说明](/releases/os_upgrading/upgrading_guide/)。如果您落后目标版本多个发行版本，请在开始升级前联系支持团队。

## Features that need outbound access

离线（气隙）部署在没有任何出站连接的情况下运行，但需要访问外部服务的功能，在处于断网状态时无法正常工作。这包括从云端托管工具拉取数据的连接器（connector）和集成器（integrator）、诸如 Jira 之类的问题跟踪工具集成、面向 Slack 和 Microsoft Teams 等服务的出站通知，以及通常按计划定期获取的漏洞增强数据（vulnerability enrichment data）。

这些功能是按部署单独配置的，而非默认开启，因此缺少这些功能并不会导致离线（气隙）安装出现故障。如果您启用了其中某项功能，在该部署具备通往相应服务的连接路径之前，应预料到它会因名称解析或连接错误而失败。如果存在出站路径但需经过代理，请参阅[在正向 HTTPS 代理后运行 DefectDojo](/onprem_deployment/forward_proxy/)。

### EPSS and KEV data from an internal mirror

EPSS 和 KEV 增强功能是一个值得配置的例外，因为它并不需要访问公共互联网的路径。两者均可在 Tuner 的 Finding Enrichment 下进行配置，各自拥有独立的启用开关和查询 URL。这些 URL 字段出厂时指向公共数据源，您可以将其重新指向托管在您自己网络内部的副本。

该镜像必须以与公共数据源相同的格式提供相同的文件。查询操作会从您提供的 URL 中获取指定的文件，而不是自行发现该处存在的任意内容，因此对数据进行了重新打包或重组的镜像将无法正常工作。请按照适合您的计划定期刷新副本内容，因为部署环境只会读取您的镜像所提供的内容。

## Questions or support

如需获取有关离线（气隙）安装或升级方面的帮助，请联系您的客户代表，或发送邮件至 [support@defectdojo.com](mailto:support@defectdojo.com)。
