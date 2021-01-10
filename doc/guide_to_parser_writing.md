# How to write a DefectDojo parser

> All commands assume that you're located at the root of the django-DefectDojo cloned repo.

## Pre-requisites
- You have forked https://github.com/DefectDojo/django-DefectDojo and cloned locally.
- Checkout `dev` and make sure you're up to date with the latest changes.
- It's advised that you create a dedicated branch for your development, such as `git checkout -b parser-name` yet that's up to you.

It is probably easier to use the docker-compose stack (and benefit from the hot-reload capbility for uWSGI).
Set up your environment to use the dev or ptvsd environment, such as:

`$ docker/setEnv.sh dev`
or
`$ docker/setEnv.sh ptvsd` (allows to set breakpoints in uWSGI)

Please have a look at [DOCKER.md](../DOCKER.md) for more details.

### docker images
You'd want to build your docker images locally, and eventually pass in your local user's `uid` to be able to write to the image (handy for database migration files). Assuming your user's `uid` is `1000`, then:

`$ docker-compose build --build-arg uid=1000`

## Which files do you need to modify?

| File                                          | Purpose
|-------                                        |--------
|`dojo/fixtures/test_type.json`                 | Django fixture for the type of scan. Take the next available integer if you intend to push upstream. If you're planning to use only in your own fork, you could jump ahead by 1000 to avoid any potential conflicts.
|`dojo/templates/dojo/import_scan_results.html` | Add the scan to the array presented in the drop-down box
|`dojo/tools/<parser_dir>/__init__.py`          | Empty file for class initialization
|`dojo/tools/<parser_dir>/parser.py`            | The meat. This is where you write your actual parser
|`dojo/unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | Sample files containing meaningful data for unit tests. The minimal set.
|`dojo/unittests/test_<parser_dir>_parser.py`   | The unittest class, holding unit tests definitions
|`dojo/tools/factory.py`                        | Import there your new parser class and add it to the long "if/else" statement

## Things to pay attention to

Parsers may have many fields, out of which many of them may be optional.

Always make sure you include checks to avoid potential `KeyError` errors (e.g. field does not exist), for those fields you are not absolutely certain will always be in file that will get uploaded. These translate to 500 error, and do not look good.

## Unit tests

Each parser must have unit tests, at least to test for 0 vuln, 1 vuln and many vulns. You can take a look at how other parsers have them for starters. The more quality tests, the better.

### Test database
To test your unit tests locally, you first need to grant some rights. Get your MySQL root password from the docker-compose logs, login as root and issue the following commands:

```
MYSQL> grant all privileges on test_defectdojo.* to defectdojo@'%';
MYSQL> flush privileges;
```

### Run your tests

This local command will launch the unit test for your new parser

`$ docker-compose exec uwsgi bash -c 'python manage.py test dojo.unittests.<your_unittest_py_file>.<main_class_name> -v2'`

Example for the blackduck hub parser:

`$ docker-compose exec uwsgi bash -c 'python manage.py test dojo.unittests.test_blackduck_csv_parser.TestBlackduckHubParser -v2'`

> If you want to run all unit tests, simply run `$ docker-compose exec uwsgi bash -c 'python manage.py test dojo.unittests -v2'`

## Other files that could be involved

### Change to the model
In the event where you'd have to change the model, e.g. to increase a database column size to accomodate a longer string of data to be saved
* Change what you need in `dojo/models.py`
* Create a new migration file in dojo/db_migrations by running and including as part of your PR

    `$ docker-compose exec uwsgi bash -c 'python manage.py makemigrations -v2'`

### Accept a different type of file to upload
If you want to be able to accept a new type of file for your parser, take a look at `dojo/forms.py` around line 436 (at the time of this writing) or locate the 2 places (for import and re-import) where you find the string `attrs={"accept":`.

Formats currently accepted: .xml, .csv, .nessus, .json, .html, .js, .zip.

### A need for more than just the parser.py

Of course, nothing prevents you from having more files than the `parser.py` file. It's python :-)

## Example PRs

If you want to take a look at previous parsers that are now part of DefectDojo, take a look at https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+label%3A%22import+scans%22+

## Update the readthedocs documentation

The DefectDojo official documentation lives in another repository, https://github.com/DefectDojo/documentation

Please update the `docs/integration.rst` with the details of your new parser and create a PR in that repo. Reference the PR in the main DefectDojo repository to establish an automatic link between the two.
