---
title: "DefectDojo parser"
description: "How to write a DefectDojo parser"
draft: false
weight: 1
---

{{% alert title="Information" color="info" %}}
All commands assume that you're located at the root of the django-DefectDojo cloned repo.
{{% /alert %}}

## Pre-requisites
- You have forked https://github.com/DefectDojo/django-DefectDojo and cloned locally.
- Checkout `dev` and make sure you're up to date with the latest changes.
- It's advised that you create a dedicated branch for your development, such as `git checkout -b parser-name` yet that's up to you.

It is probably easier to use the docker-compose stack (and benefit from the hot-reload capbility for uWSGI).
Set up your environment to use the debug environment, such as:

`$ docker/setEnv.sh debug`

Please have a look at [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/DOCKER.md) for more details.

### Docker images
You'd want to build your docker images locally, and eventually pass in your local user's `uid` to be able to write to the image (handy for database migration files). Assuming your user's `uid` is `1000`, then:

{{< highlight bash >}}
$ docker-compose build --build-arg uid=1000
{{< /highlight >}}

## Which files do you need to modify?

| File                                          | Purpose
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | Empty file for class initialization
|`dojo/tools/<parser_dir>/parser.py`            | The meat. This is where you write your actual parser
|`dojo/unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | Sample files containing meaningful data for unit tests. The minimal set.


## Template Generator

Utilze the [template](https://github.com/DefectDojo/cookiecutter-scanner-parser)  parser to quickly generate the files required. To get started you will need to install [cookiecutter](https://github.com/cookiecutter/cookiecutter).

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

Then generate your scanner parser from the root of django-DefectDojo:

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

Read [more](https://github.com/DefectDojo/cookiecutter-scanner-parser) on the template configuration variables.

## Things to pay attention to

Parsers may have many fields, out of which many of them may be optional.

Always make sure you include checks to avoid potential `KeyError` errors (e.g. field does not exist), for those fields you are not absolutely certain will always be in file that will get uploaded. These translate to 500 error, and do not look good.

## Unit tests

Each parser must have unit tests, at least to test for 0 vuln, 1 vuln and many vulns. You can take a look at how other parsers have them for starters. The more quality tests, the better.

### Test database
To test your unit tests locally, you first need to grant some rights. Get your MySQL root password from the docker-compose logs, login as root and issue the following commands:

{{< highlight mysql >}}
MYSQL> grant all privileges on test_defectdojo.* to defectdojo@'%';
MYSQL> flush privileges;
{{< /highlight >}}

### Run your tests

This local command will launch the unit test for your new parser

{{< highlight bash >}}
$ docker-compose exec uwsgi bash -c 'python manage.py test dojo.unittests.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

Example for the blackduck hub parser:

{{< highlight bash >}}
$ docker-compose exec uwsgi bash -c 'python manage.py test dojo.unittests.test_blackduck_csv_parser.TestBlackduckHubParser -v2'
{{< /highlight >}}

{{% alert title="Information" color="info" %}}
If you want to run all unit tests, simply run `$ docker-compose exec uwsgi bash -c 'python manage.py test dojo.unittests -v2'`
{{% /alert %}}

## Other files that could be involved

### Change to the model
In the event where you'd have to change the model, e.g. to increase a database column size to accomodate a longer string of data to be saved
* Change what you need in `dojo/models.py`
* Create a new migration file in dojo/db_migrations by running and including as part of your PR

    {{< highlight bash >}}
    $ docker-compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### Accept a different type of file to upload
If you want to be able to accept a new type of file for your parser, take a look at `dojo/forms.py` around line 436 (at the time of this writing) or locate the 2 places (for import and re-import) where you find the string `attrs={"accept":`.

Formats currently accepted: .xml, .csv, .nessus, .json, .html, .js, .zip.

### A need for more than just the parser.py

Of course, nothing prevents you from having more files than the `parser.py` file. It's python :-)

## Example PRs

If you want to take a look at previous parsers that are now part of DefectDojo, take a look at https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+label%3A%22import+scans%22+

## Update the GitHub pages documentation

The DefectDojo official documentation lives in the docs folder, https://github.com/DefectDojo/django-DefectDojo/tree/dev/docs Please update [`docs/content/en/integrations/import.md`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/en/integrations/import.md) with the details of your new parser.
