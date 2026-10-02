---
title: 编辑文档
description: 如何修改文档
draft: false
weight: 4
audience: opensource
aliases:
- /zh-hans/en/open_source/contributing/documentation
---

本文档使用 [Hugo](https://gohugo.io/) 构建，并使用 [Doks](https://getdoks.org/) 主题的一个变体。

网站的静态文件通过 GitHub Actions 构建，并发布到 gh-pages 分支。

## 如何运行本地预览

1. [安装 Hugo](https://gohugo.io/getting-started/installing/)。请确保安装的是支持 Sass/SCSS 的扩展版（extended version）。请注意，[Hugo GitHub](https://github.com/gohugoio/hugo/releases) 上提供了多种 Linux 软件包
2. 使用 Node.js 安装所需主题：执行 `cd docs`，然后运行 `npm install`。
3. 要运行文档本地服务器，执行 `cd docs` 切换到 docs 文件夹，然后运行 `npm run dev` 启动 Hugo 开发服务器。系统支持热重载——服务器运行期间，页面会随更改自动更新。
4. 访问 [http://localhost:1313](http://localhost:1313)。

## 贡献指南

现阶段，我们的文档主要由 DefectDojo Pro 团队维护，但我们仍然欢迎社区为文档做出贡献。

* 请注意，我们的搜索功能使用指向 **docs.defectdojo.com** 的外部索引——因此您无法通过搜索找到仍在 dev 分支中的页面。请改为查阅本地的 sitemap.xml 文件，以查找您新创建的 URL：`http://localhost:1313/sitemap.xml`
* 我们的文档目前面向两类受众撰写：开源版和 Pro 版，因此请在 Hugo 前置元数据（front matter）中包含相应的标签，如下所示：

```
---
title: "Your great article"
audience: opensource
---
```

* 请勿使用相对链接路径：`[link](../your_article/)`。虽然在 Hugo 中技术上"合法"，但这样无法通过我们的单元测试。

## 文档的单元测试

DefectDojo 的文档使用 Lychee 检查 404 及其他链接错误。CI 会运行两项检查：渲染后的文档站点，以及硬编码在 Django 应用（模板和设置）中的任何 `docs.defectdojo.com` URL。两者都使用 `--remap`，以便绝对的 `docs.defectdojo.com` URL 能够解析到最新构建的站点。要在仓库根目录本地运行这两项检查：

```
cd docs && rm -rf public/ && hugo --minify --gc --config config/production/hugo.toml && cd ..

lychee --offline --no-progress \
  --root-dir "$PWD/docs/public" \
  --remap "https://docs.defectdojo.com file://$PWD/docs/public" \
  './docs/public/**/*.html'

lychee --offline --no-progress \
  --root-dir "$PWD/docs/public" \
  --remap "https://docs.defectdojo.com file://$PWD/docs/public" \
  --exclude '%7[BD]' \
  $(grep -rl 'docs\.defectdojo\.com' dojo/ --include='*.html' --include='*.py' --include='*.tpl')
```

### 主题覆盖

我们使用了大量的 CSS 覆盖，详情记录在 `docs/layouts` 中。
