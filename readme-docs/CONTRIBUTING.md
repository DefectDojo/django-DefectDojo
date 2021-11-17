We greatly appreciate all of our
[contributors](https://github.com/DefectDojo/django-DefectDojo/graphs/contributors).

We would also like to highlight the contributions from Michael Dong and Fatimah
Zohra who contributed to DefectDojo before it was open source.



# Submitting an Issue

## For Bugs

Before submitting, please ensure that you are using the latests code by performing a `git pull`.

Please include your operating system name, your operating system version number (16.04, 18.6, etc), and the dojo install type you are using (setup.bash, docker, k8s, etc).

Bugs that do not have this information will be closed.

# Contributing to DefectDojo

Here are a few things to keep in mind when making changes to DefectDojo.

## Writing a new parser

Please see [the parser guide](https://defectdojo.github.io/django-DefectDojo/contributing/how-to-write-a-parser/) for guidance on how to write a parser.

## Modifying DefectDojo and Testing

Please use [these test scripts](./tests) to test your changes. These are the scripts we run in our [integration tests](DOCKER.md#run-the-tests-with-docker).

For changes that require additional settings, you can now use local_settings.py file. See the logging section below for more information.

## Python3 version
For compatibility reasons, the code in dev branch should be python3.8 compliant.

## Submitting Pull Requests

The following are things to consider before submitting a pull request to
DefectDojo.

0. Base your PR against the `dev` branch, unless discussed otherwise with the maintainers

0. Make sure that the install is working properly.

0. All tests found in [these test scripts](./tests) should be passing.

0. All submitted code should conform to [__PEP8 standards__][pep8].

0. See [flake8 built-in commit hooks] on how to easily check for for pep8 with flake8 before comitting.

0. Pull requests should be submitted to the 'dev' branch.

0. In dev branch, the code should be python 3.8 compliant.

[dojo_settings]: /dojo/settings/settings.dist.py "DefectDojo settings file"
[pep8]: https://www.python.org/dev/peps/pep-0008/ "PEP8"
[flake8 built-in commit hooks]: https://flake8.pycqa.org/en/latest/user/using-hooks.html#built-in-hook-integration
