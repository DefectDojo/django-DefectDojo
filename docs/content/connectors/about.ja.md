---
title: コネクタについて
description: Pro UI におけるアップストリームおよびダウンストリームコネクタの統合ホーム
summary: ''
date: 2026-07-14 00:00:00+00:00
lastmod: 2026-07-14 00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Connectors are a DefectDojo Pro-only feature.</span>

**コネクタ**は、DefectDojo が双方向でやり取りするすべてのツールのための、DefectDojo Pro UI 上の単一のホームです。これは、これまで別々の場所で設定されていた2つの機能を統合したものです。

* **アップストリームコネクタ**(旧称 **API Connectors**)は、スキャナーやセキュリティツールから検出事項とアセットインベントリを*取り込み*ます。
* **ダウンストリームコネクタ**(旧称 **Integrations**)は、検出事項を課題管理システムやチケッティングシステムに*送信*します。

DefectDojo をセキュリティデータのハブと考えると、アップストリームコネクタはデータが到着する経路であり、ダウンストリームコネクタは修復作業が出ていく経路です。

## コネクタの場所

Pro UI のサイドバーで、**Import** ヘッダーの下にある **Connectors** グループを開きます。

* **Connectors > Upstream Connectors** — 旧 **API Connectors** エントリ(以前は Import の下にありました)を置き換えます。
* **Connectors > Downstream Connectors** — 旧 **Integrations** エントリ(以前は Settings の下にありました)を置き換えます。この方向は現在 **ベータ版** です。

古いブックマークやディープリンクは引き続き機能します。従来の **API Connectors** および **Integrations** の URL は、新しい **Upstream Connectors** および **Downstream Connectors** ページへ自動的にリダイレクトされます。

## 閲覧できるユーザー

* **Upstream Connectors** は、グローバルロールが Reader 以上のユーザーに表示されます。
* **Downstream Connectors** はスーパーユーザーのみに表示され、現在クラウドホスト型の DefectDojo Pro インスタンスでは **ベータ版** です。

**Connectors** グループは、2つのページのうち少なくとも一方があなたに表示される場合にサイドバーに表示されます。

## コネクタページについて

両方向とも、同じ刷新されたレイアウトを共有しています。

* 各ツールは全幅の **タイル** として表示されます。左側にロゴ、中央にツール名と簡単な説明、右側にアクションボタンがあります。
* 各セクションには、入力に応じてツール名でタイルを絞り込む **検索ボックス** があります。

**Upstream Connectors** ページでは、

* **Configured Connectors** に、すでに設定済みのコネクタが一覧表示されます。各タイルには稼働状況の概要(ヘルスステータス、最終オペレーション、合計/マッピング済みレコード数)と、**Manage Records & Operations**、**Edit Configuration**、**Delete Configuration** の各アクションを含む **Manage Configuration** メニューが表示されます。
* **Available Connectors** に、まだ設定されていない対応ツールが一覧表示され、それぞれに **Add Configuration** ボタンがあります。
* ページヘッダーのフィルターにより、両方のセクションをコネクタの種類で絞り込めます。**All**、アセットインベントリを取り込むコネクタ向けの **Asset**(インスタンスの用語によっては **Product**)、脆弱性データを取り込むコネクタ向けの **Finding** です。

**Downstream Connectors** ページでは、

* **Available Integrations** に、対応するすべての課題管理ツールが一覧表示されます。設定済みの Integrations のタイルには、既存の Integration Instances の件数が表示されます。

## 次のステップ

* [About Upstream Connectors](/connectors/upstream/about/) を読み、[最初のアップストリームコネクタを追加](/connectors/upstream/add_edit/)して検出事項の自動取り込みを開始しましょう。
* [Downstream Connectors guide](/connectors/downstream/about/) を読み、検出事項を課題管理ツールに送信しましょう。
