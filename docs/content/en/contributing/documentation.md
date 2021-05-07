---
title: "Documentation"
date: 2021-02-02T20:46:28+01:00
draft: false
---

The documentation is build with [Hugo](https://gohugo.io/) and uses the theme [Docsy](https://www.docsy.dev). The source code is located in the [docs](https://github.com/DefectDojo/django-DefectDojo/tree/dev/doc) folder. Static files for the webside are build with github actions and are publish in the gh-pages branch.

## How to run a local preview

1. [Install Hugo](https://gohugo.io/getting-started/installing/). Make sure you have installed the extended version with Sass/SCSS support.
2. Clone the DefectDojo git repository with the option `--recurse-submodules`. If you have already cloned the repository, make sure that you have checked out out the Docsy theme or use `git submodule` to check it out: 

    {{< highlight bash >}}
    cd docs/themes/docsy 
    git submodule update --init --recursive
    {{< /highlight >}}

3. Install PostCSS

    To build or update your site’s CSS resources, you also need PostCSS to create the final assets. If you need to install it, you must have a recent version of NodeJS installed on your machine so you can use npm, the Node package manager. By default npm installs tools under the directory where you run npm install:

    {{< highlight bash >}}
    sudo npm install -D autoprefixer
    sudo npm install -D postcss-cli
    {{< /highlight >}}

    Starting in version 8 of postcss-cli, you must also separately install postcss:

    {{< highlight bash >}}
    sudo npm install -D postcss
    {{< /highlight >}}


3. Switch to the docs folder and start the hugo server with hot reloading `hugo server -D`
4. Visit [http://localhost:1313](http://localhost:1313).

See also the [Docsy installation procedures](https://www.docsy.dev/docs/getting-started/) for reference.
