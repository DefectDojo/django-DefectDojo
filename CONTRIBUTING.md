# Submitting an Issue

## For Bugs

Before submitting, please ensure that you are using the latests code by performing a `git pull`.

Please include your operating system name, your operating system version number (16.04, 18.6, etc), and the dojo install type you are using (setup.bash, docker, etc).

Bugs that do not have this information will be closed.

# Contributing to DefectDojo

Here are a few things to keep in mind when making changes to DefectDojo.

## Modifying DefectDojo and Testing

Please use [these test scripts](./tests) to test your changes. These are the scripts we run in our integration tests.

For changes that require additional settings, you can now use local_settings.py file. See the logging section below for more information.

## Python3 version
For compatibility reasons, the code in dev branch should be python3.6 compliant.

## Logging
Logging is configured in `settings.dist.py` and can be tuned using a `local_settings.py`, see [template for local_settings.py](dojo/settings/template-local_settings)
Specific logger can be added. For example to activate logs related to the deduplication, change the level from DEBUG to INFO in `local_settings.py`:


```
LOGGING['loggers']['dojo.specific-loggers.deduplication']['level'] = 'DEBUG'
```

Or you can modify `settings.dist.py` directly, but this adds the risk of having conflicts when `settings.dist.py` gets updated upstream. 

```
          'dojo.specific-loggers.deduplication': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        }
```

## Debug Toolbar
In the `dojo/settings/template-local_settings.py` you'll find instructions on how to enable the [Django Debug Toolbar](https://github.com/jazzband/django-debug-toolbar).
This toolbar allows you to debug SQL queries, and shows some other interesting information.

## Submitting Pull Requests

The following are things to consider before submitting a pull request to
DefectDojo.

0. Ensure all changes made to the code, packages, etc. are reflected in the
[__setup.bash__][setup_bash] script and the [__setup.py__][setup_py] script.


0. Make sure that the install is working properly.

0. All tests found in [these test scripts](./tests) should be passing.

0. All submitted code should conform to [__PEP8 standards__][pep8].

0. See [flake8 built-in commit hooks] on how to easily check for for pep8 with flake8 before comitting.

0. Pull requests should be submitted to the 'dev' branch.

0. In dev branch, the code should be python 3.5 compliant.

[dojo_settings]: /dojo/settings/settings.dist.py "DefectDojo settings file"
[setup_py]: /setup.py "Python setup script"
[setup_bash]: /setup.bash "Bash setup script"
[pep8]: https://www.python.org/dev/peps/pep-0008/ "PEP8"
[flake8 built-in commit hooks]: https://flake8.pycqa.org/en/latest/user/using-hooks.html#built-in-hook-integration

   
