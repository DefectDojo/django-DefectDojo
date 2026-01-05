---
title: "Amend Documentation"
description: "How to amend the documentation"
draft: false
weight: 2
---

The documentation is built with [Hugo](https://gohugo.io/) and uses the theme [Docsy](https://www.docsy.dev).
Static files for the webside are build with github actions and are publish in the gh-pages branch.

## How to run a local preview

1. [Install Hugo](https://gohugo.io/getting-started/installing/). Make sure you have installed the extended version with Sass/SCSS support. Please note there are various Linux packages available on [Hugo GitHub](https://github.com/gohugoio/hugo/releases)
2. Install required theme using Node.js: `cd docs` and then `npm install`.
3. To run the Docs local server, `cd docs` to switch to the docs folder, and start the hugo server by running `npm run dev`.  Hot reloading is supported - pages will automatically update with changes while the server is running.
4. Visit [http://localhost:1313](http://localhost:1313).

DefectDojo Docs are built using a variation of the [Doks](https://getdoks.org/) theme.