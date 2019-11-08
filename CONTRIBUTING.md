# Submitting an Issue

## For Bugs

Before submitting, please ensure that you are using the latests code by performing a `git pull`.

Please include your operating system, your operating system version number (16.04, 10.6, etc), and the dojo install you are using (setup.bash, docker, etc).

Bugs that do not have this information will be closed.

# Contributing to DefectDojo

Here are a few things to keep in mind when making changes to DefectDojo.

## Modifying DefectDojo and Testing

Please use [these test scripts](./tests) to test your changes. These are the exact scripts we run in our [Travis Build](https://travis-ci.org/OWASP/django-DefectDojo).

For changes that require additional settings, settings.dist.py is the file you want to change. Settings.py is created by setup.bash from settings.dist.py

## Transition to python3

With the nearing deprecation of python 2.7, the conversion to python3 will be
executed as smoothly as possible. During this process, DefectDojo will also be
upgraded to Django 2.2.1. Going forward, the 'dev' branch will only accept
bug fixes, Please instead contribute features / bug fixes  to the ‘python3_dev’ branch.

## Python3 version
For compatibility reasons, the code in dev branch should be python3.5 compliant.

## Logging
Logging is configured in `settings.dist.py`.

Specific logger can be added. For example to activate logs related to the deduplication, change the level from DEBUG to INFO in:

```
          'dojo.specific-loggers.deduplication': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        }
```

## Submitting Pull Requests

The following are things to consider before submitting a pull request to
DefectDojo.

0. Ensure all changes made to the code, packages, etc. are reflected in the
[__setup.bash__][setup_bash] script and the [__setup.py__][setup_py] script.


0. Make sure that the install is working properly.

0. All tests found in [these test scripts](./tests) should be passing.

0. All submitted code should conform to [__PEP8 standards__][pep8].

0. Pull requests should be submitted to the 'dev' or 'legacy-python2.7' branch.

0. In dev branch, the code should be python 3.5 compliant.


[dojo_settings]: /dojo/settings/settings.dist.py "DefectDojo settings file"
[setup_py]: /setup.py "Python setup script"
[setup_bash]: /setup.bash "Bash setup script"
[pep8]: https://www.python.org/dev/peps/pep-0008/ "PEP8"
