---
title: DefectDojo Pro 升级指南
description: 升级现有的 DefectDojo Pro Helm 发行版，包括拉取 Chart、执行升级和回滚
draft: false
weight: 14
audience: pro
aliases:
- /zh-hans/get_started/pro/onprem/upgrading/
---

<!--
  生成自 DefectDojo Pro Helm chart 仓库。
  来源：chart 版本 3.1.304 的 docs/UPGRADE_GUIDE.md。
  请编辑源指南，而不是此文件。本地修改会在下次发布 chart 时
  被覆盖。
-->
本文介绍如何将现有的 DefectDojo Pro 发行版升级到更新的 chart 版本。
推荐的方式是直接从 DefectDojo OCI 注册表拉取 chart —— 无需解压 zip 包。
安装时使用的打包 zip 工作流同样适用于升级，具体说明见下文。

本指南涵盖以下内容：

- [升级前须知](#before-you-upgrade)
- [Chart 来源：OCI 注册表](#chart-source-oci-registry)
- [向注册表进行身份验证](#authenticate-to-the-registry)
- [通过 OCI 注册表升级（推荐）](#upgrade-via-oci-registry-recommended)
- [通过解压后的 Zip 包升级](#upgrade-via-extracted-zip)
- [使用 ArgoCD 升级](#upgrade-with-argocd)
- [验证升级结果](#verify-the-upgrade)
- [回滚](#rollback)
- [故障排查](#troubleshooting)

---

## 升级涵盖的内容

一个 DefectDojo Pro 发行版由 chart 版本、一组容器镜像版本以及 Pro 配置文件
共同组成。这些内容是一起构建和测试的，因此也必须一起变更。单独升级镜像标签
不受支持，会破坏部署。

配置文件同理。几乎每个发行版都会附带一个新的 `pro_settings.py`。切勿在
升级时沿用旧版本的副本，也不要手动修补旧文件：应用程序必须运行与其版本匹配
的 `pro_settings.py`。您自己的自定义配置应放在 `local_settings.py` 中，该
文件会在升级时保留，也是这两个文件中唯一应该由您编辑的文件。

使用该 chart 会自动为您处理这一切。它会随附并挂载与之匹配的
`pro_settings.py`，与您的 `local_settings.py` 放在一起，因此无需手动复制
或迁移任何内容。

## 升级前须知

每次升级都应遵循相同的起始步骤。跳过这些步骤是升级失败最常见的原因。

1. **阅读发行说明**，涵盖从当前发行版到目标版本之间的每一个版本。其中会
   列出破坏性变更、新增的必填字段以及迁移前置条件。每个标签的 GitHub 发行
   页面都链接到相应的变更日志。
2. **检查当前的 chart 版本。** 这是本次升级的起点：

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **备份数据库。** Chart 升级可能包含会更改数据库结构（schema）的 Django
   迁移。在继续操作之前，请对 PostgreSQL 实例进行逻辑转储（或存储级快照）。
4. **准备好 values 文件。** 升级命令必须传入与安装时相同的平台预设
   （platform preset）、规格预设（profile preset）和客户 values 文件。
   values 文件缺失或与实际不一致会导致意外的差异。
5. **确认 secret 引用仍然存在。** 如果您在安装时使用了
   `--set dojo.existingSecret=...` 或 `--set license.existingSecret=...`，
   请确认这些 Kubernetes secret 在命名空间中依然存在。
6. **先在本地渲染升级结果**，在触碰集群之前发现缺失的字段、无效的值或
   模板错误：

   ```bash
   helm template dojopro $CHART_REF \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/<size>.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     > /tmp/dojopro-upgrade-render.yaml
   ```

   `$CHART_REF` 是 OCI 引用地址（见下文）或解压后的 chart 路径。

> 只需设置一次 `NAMESPACE` —— 本指南中的每条命令都会使用 `$NAMESPACE`：
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **网络策略默认值已更改。** NetworkPolicy 现在由 `networkPolicy.profile`
> 控制，其默认值为 `standard`：允许全部出站流量，以及该发行版自身 Pod
> 之间的入站流量（外部入站流量仍仅限于 ingress 路径）。这比此前始终精细化
> 的出站允许列表更为宽松。若要保留原有的严格限制行为，请设置
> `networkPolicy.profile: aggressive` 并检查其中的例外项（`nodeLocalDns`、
> `dnsSelectors`、`externalAPIs`）—— 参见
> [网络策略](/get_started/pro/onprem/installing_on_kubernetes/#network-policies)。

> **编排器数据库要求。** 编排器（`ddorch`）使用一个名为
> `<main-db-name>-ddorch` 的第二数据库，如果该数据库不存在，会在启动时
> 自动创建。如果您的应用程序角色缺少 `CREATEDB` 权限，请在升级到启用
> ddorch 的 chart 版本之前预先创建该数据库
> （`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`）—— 否则
> ddorch Pod 会因 `permission denied to create database (SQLSTATE 42501)`
> 而失败。参见
> [预检：编排器（ddorch）数据库](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database)。

> **Organization/Asset 重新标注默认值。**
> `dojo.V3EnableOrganizationAssetRelabel` 现在默认值为 `null`（自动）：
> **新安装默认启用**，**升级时保持关闭**，因此界面重新标注
> （Organization/Asset 替代 ProductType/Product）不会在现有发行版上意外
> 开启。若要为已升级的发行版启用该功能，请显式设置
> `dojo.V3EnableOrganizationAssetRelabel: true`；显式设置的 `true`/`false`
> 始终优先于自动默认值。

---

## Chart 来源：OCI 注册表

该 chart 以 OCI 制品的形式发布到 DefectDojo 的 GCP Artifact Registry：

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

每个发行版都会以 chart 版本作为标签（例如 `2.57.2`）。chart 版本与
`Chart.yaml` 中的应用版本一致，因此您在 `helm upgrade --version` 中传入
的标签，与 GitHub 发行版页面上显示的版本号相同。

列出可用的 chart 版本：

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **为什么升级要使用 OCI？** 预设文件（`presets/platforms/*.yaml`、
> `presets/profiles/*.yaml`）打包在 chart 内部。通过 OCI URL 引用 chart，
> 会自动拉取与目标 chart 相匹配的正确预设版本 —— 无需重新解压，也不会用到
> 过期的预设。

---

## 向注册表进行身份验证

该注册表是私有的。Helm 必须先登录才能拉取 chart。请使用 GCP 服务账号
密钥，或由 DefectDojo 支持团队提供的短期访问令牌。

**方式 A —— 服务账号 JSON 密钥：**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**方式 B —— 交互式 gcloud 登录（适用于拥有注册表访问权限的人员）：**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

`gcloud auth print-access-token` 生成的访问令牌一小时后过期。如果在升级
过程中看到 `401 Unauthorized`，请重新运行 `helm registry login`。

> **隔离网络/防火墙环境：** 如果您的集群节点可以访问
> `us-south1-docker.pkg.dev`，但工作站无法访问，请使用下文的解压 zip 包
> 工作流。OCI 工作流仅在运行 `helm upgrade` 的主机能够访问注册表时才有效。

---

## 通过 OCI 注册表升级（推荐）

将 `helm upgrade` 直接指向 OCI URL，并通过 `--version` 固定 chart 版本。
所有 values 文件、`--set` 标志和 `--set-file` 标志都与最初安装时保持一致。

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> 上面的平台和规格预设路径为 `presets/platforms/...`（没有 `$CHART/`
> 前缀）。当 Helm 从 OCI 拉取 chart 时，预设文件位于拉取到的 chart 内部，
> 但这里的 `-f` 指向的是这些文件的**本地副本**。如果您没有保留预设文件的
> 本地副本，请先使用 `helm pull oci://... --version $VERSION --untar` 解压
> chart，然后从解压目录中引用这些文件 —— 或者使用解压 zip 包工作流。

**内联 secret + license 文件变体：**

```bash
helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> 请始终固定 `--version`。省略它会导致拉取命令执行时注册表所解析到的
> 任意标签 —— 既不可重复，也无法审计。固定版本号可以确保重跑、回滚和
> 事件响应始终引用同一制品。

---

## 通过解压后的 Zip 包升级

对于无法访问 OCI 注册表的工作站，或者希望将 chart 作为本地文件暂存的
客户，GitHub 发行版中的打包 zip 包在升级时的使用方式与安装时完全相同。
与安装唯一的区别在于命令动词（使用 `helm upgrade` 而不是 `helm install`）。

1. 从 GitHub 发行版下载 `dojo-pro-helm-bundled-<version>.zip`（以及独立
   签名文件 `.asc`）。
2. 按照安装指南中的说明，使用公钥（`dojo-pro-release-signing.asc`）验证
   签名。
3. 将 chart 解压到**带版本号的路径**中，避免预设文件与旧的解压内容发生
   冲突：

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. 使用解压后的 chart 路径运行升级 —— values 文件和标志与最初安装时
   相同：

   ```bash
   helm upgrade dojopro $CHART \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/standard.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     --set-file ddorch.tls.rootCa=orch_ca.crt \
     --set-file ddorch.tls.cert=orch_server.crt \
     --set-file ddorch.tls.key=orch_server.key \
     --wait --timeout 15m
   ```

> **每次升级都要重新解压。** 预设文件会随 chart 版本演进而变化。复用旧的
> 解压内容会在不知不觉中把本次升级锁定在旧的预设默认值上。

---

## 使用 ArgoCD 升级

当 DefectDojo Pro 由 ArgoCD 管理时，升级只需修改 Application spec 中的
`targetRevision` 这一处。平台和规格预设的版本内置于 chart 中，因此会同步
更新。

```yaml
spec:
  source:
    repoURL: us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2
    chart: dojopro
    targetRevision: <chart-version>    # bump this
    helm:
      valueFiles:
        - presets/platforms/aws-eks.yaml
        - presets/profiles/standard.yaml
      values: |
        # your environment-specific values
      parameters:
        - name: dojo.existingSecret
          value: dojopro-secrets
        - name: license.existingSecret
          value: dojopro-license
```

编辑完 `targetRevision` 后同步该 Application。ArgoCD 会从 OCI 注册表
拉取新的 chart 并进行协调（reconcile）。

> ArgoCD 需要拥有自己访问 OCI 注册表的凭据。请将仓库 secret 配置为
> `type: helm` 并设置 `enableOCI: "true"`。有关 Secret 的具体结构，请参见
> ArgoCD 的
> [Helm OCI 文档](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support)。

---

## 验证升级结果

在 `helm upgrade` 命令返回后（或 ArgoCD 报告 Synced / Healthy 状态后），
确认新版本已经生效：

```bash
# Chart revision bumped and status is deployed
helm list -n $NAMESPACE

# All pods Running and Ready — expect django, celery worker/beat,
# connectors, ddorch, ddorch-workers, and (if enabled) mcp-server
kubectl get pods -n $NAMESPACE

# Migrations succeeded — the initializer job should show Completed
kubectl get jobs -n $NAMESPACE

# App version matches the target
kubectl get deployment -n $NAMESPACE \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

访问登录页面，确认界面能够正常打开，且管理员用户可以完成身份验证。如需
进行程序化检查，应用正常时 `/login/` 端点会返回 200。

---

## 回滚

Helm 会按修订版本（revision）保留发行历史。如果升级导致行为回退，可以
回滚到上一个修订版本：

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **数据库迁移不会随之回滚。** Helm 回滚只会恢复清单状态（镜像、配置、
> secret），并不会运行 `migrate --revert`。如果本次升级应用了需要撤销的
> 数据库结构迁移，请在回滚 Helm 发行版之前，使用
> [升级前须知](#before-you-upgrade)中所做的备份进行恢复，或与 DefectDojo
> 支持团队协调进行手动迁移回退。

ArgoCD 用户可以通过在 git 中回退 `targetRevision` 的更改（或使用
`argocd app rollback`）并同步来完成回滚。

---

## 故障排查

**拉取 chart 时出现 `401 Unauthorized`。**
访问令牌已过期。请使用新的 `gcloud auth print-access-token` 重新运行
`helm registry login`。

**出现 `Error: UPGRADE FAILED: cannot patch ... field is immutable`。**
说明选择器（selector）或其他不可变字段发生了偏移。该 chart 固定了稳定的
选择器标签，因此这通常意味着之前有人对某个 Deployment 进行过原地修改。
请记录下差异，删除有问题的资源，然后重新运行升级，让 Helm 重新创建该
资源。

**出现 `Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`。**
Helm 4 使用服务端应用（server-side apply），会跟踪字段的所有权。此错误
意味着另一个管理者 —— `kubectl edit`、`kubectl scale`，或 HPA 控制器
（`kube-controller-manager`）—— 修改了 Helm 渲染的某个字段，最常见的是
`.spec.replicas`。可以一次性重新夺回所有权：

```bash
helm upgrade ... --force-conflicts
```

包含此修复的 chart 版本，在已启用 HPA 的 Deployment 中省略了 `replicas`
字段，因此 HPA 的扩缩容不会再与升级产生冲突。如果您曾经使用 `kubectl`
手动调整过某个 Deployment 的副本数，建议改为调整对应的
`replicas`/`horizontalpodautoscaler` 值，以便该 chart 继续保持所有权。

**出现 `Error: UPGRADE FAILED: timed out waiting for the condition`。**
Pod 未能在 `--timeout` 窗口内达到 Ready 状态。请检查滞后的工作负载：

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

常见原因包括：镜像拉取失败（注册表身份验证问题）、数据库结构迁移仍在
运行（可以调高 `--timeout`），或就绪探针（readiness probe）因 FQDN
配置错误而失败。

**版本之间的预设发生了变化，导致我的 values 文件出现冲突。**
请使用 `helm template` 重新渲染（参见[升级前须知](#before-you-upgrade)），
在运行 `helm upgrade` 之前，将您的覆盖项与新的预设默认值进行核对协调。

**出现 `values don't meet the specifications of the schema ... got string, want boolean`。**
说明您覆盖项中的某个开关值被加上了引号。Helm 会把 `"false"` 视为一个
非空字符串，而非空字符串在布尔判断中为真，因此该功能原本想关闭却被打开
了。现在 schema 会拒绝这种带引号的写法，而不是放行。请去掉引号：

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

错误信息中会指出具体的问题路径。不加引号的 `false`、`no` 和 `off` 都会
被解析为真正的布尔值，可以正常接受。
