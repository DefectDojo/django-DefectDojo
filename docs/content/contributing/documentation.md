---
title: "Documentation"
date: 2021-02-02T20:46:28+01:00
draft: false
---

The documentation is build with [Hugo](https://gohugo.io/) and uses the theme [Learn](https://learn.netlify.app/en/). The source code is located in the [docs](https://github.com/DefectDojo/django-DefectDojo/tree/dev/doc) folder. Static files for the webside are build with github actions and are publish in the gh-pages branch.

## How to run a local preview

1. [Install Hugo](https://gohugo.io/getting-started/installing/)
2. Clone the DefectDojo git repository with the option `--recurse-submodules`. If you have already cloned the repository, make sure that you have checkouted out the hugo theme learn or use git submoduls check it out `cd docs/themes/learn && git submodule init && git submodule update`
3. Switch to the docs folder and start the hugo server with hot reloading `hugo server -D`
4. Visit [http://localhost:1313/django-DefectDojo](http://localhost:1313/django-DefectDojo).
