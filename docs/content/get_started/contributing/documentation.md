---
title: "Amend Documentation"
description: "How to amend the documentation"
draft: false
weight: 4
audience: opensource
aliases:
  - /en/open_source/contributing/documentation
---

The documentation is built with [Hugo](https://gohugo.io/) and uses a variation of the [Doks](https://getdoks.org/) theme.

Static files for the website are built with Github actions and are published in the gh-pages branch.

## How to run a local preview

1. [Install Hugo](https://gohugo.io/getting-started/installing/). Make sure you have installed the extended version with Sass/SCSS support. Please note there are various Linux packages available on [Hugo GitHub](https://github.com/gohugoio/hugo/releases)
2. Install required theme using Node.js: `cd docs` and then `npm install`.
3. To run the Docs local server, `cd docs` to switch to the docs folder, and start the Hugo development server by running `npm run dev`.  Hot reloading is supported - pages will automatically update with changes while the server is running.
4. Visit [http://localhost:1313](http://localhost:1313).

## Contribution guidelines

At this stage, our documentation is largely maintained by the DefectDojo Pro team, but we still welcome contributions to docs from the community.

* Note that our Search functionality uses an external index which points at **docs.defectdojo.com** - so you won't be able to use Search to find any pages that are in dev.  Instead, consult your local sitemap.xml file to find any new URLs you've created: `http://localhost:1313/sitemap.xml`
* Our docs are currently written for two audiences: Open Source and Pro, so please include an appropriate label in your Hugo front matter, like so:

```
---
title: "Your great article"
audience: opensource
---
```

* Do not use relative link paths: `[link](../your_article/)`.  Although technically 'legal' in Hugo, you will not pass our unit tests.

## Unit tests for docs

DefectDojo's docs use Lychee to check for 404s and other link errors.  To run this test locally, you can run this command from the root of the repo.  This will delete anything in Hugo's `/public/` folder and then rebuild.

`cd docs && rm -rf public/ && hugo --minify --gc --config config/production/hugo.toml && lychee --offline --no-progress --root-dir public './public/**/*.html'`

### Theme overrides

We use significant CSS overrides which are detailed in `docs/layouts`.
