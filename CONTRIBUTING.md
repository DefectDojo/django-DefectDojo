# Submitting an Issue

## For Bugs

Before submitting, please ensure that you are using the latests code by performing a `git pull`.

Please include your operating system, your operating system version number (16.04, 10.6, etc), and the dojo install you are using (setup.bash, docker, etc).

Bugs that do not have this information will be closed.

# Contributing to DefectDojo

Here are a few things to keep in mind when making changes to DefectDojo.

## Modifying DefectDojo and Testing

Please use [these](./dojo/unittests) and [these test scripts](./tests) to test your changes. These are the exact scripts we run in our [Travis Build](https://travis-ci.org/DefectDojo/django-DefectDojo).

For changes that require additional settings, settings_dist.py is the file you want to change. settings.py is populated by setup.bash from settings_dist.py

For changes affecting a model class, please ensure you have run Django's ``makemigrations`` command to create the corresponding DB migration scripts. This will also be checked automatically via the [Travis Build](https://travis-ci.org/DefectDojo/django-DefectDojo).
In order to make it easy to create migrations from your development environment, there is the ``unittest`` settings file. So, once you're done with your changes, you can run the following command. This will create a new migration file at ``dojo/migrations/``, which you can now give a meaningful name (keep the starting numbers in the file name, though).

```
DJANGO_SETTINGS_MODULE=dojo.settings.unittest python manage.py makemigrations dojo
```

More on Django's migrations (for example how to deal with migration conflicts) can be found [here](https://docs.djangoproject.com/en/dev/topics/migrations/).


## Submitting Pull Requests

The following are things to consider before submitting a pull request to
DefectDojo.

0. Ensure all changes made to the code, packages, etc. are reflected in the
[__setup.bash__][setup_bash] script and the [__setup.py__][setup_py] script.

0. Make sure all migration files are present and up to date

0. Make sure that the install is working properly.

0. All tests found in [these](./dojo/unittests) and [these test scripts](./tests) should be passing.

0. All submitted code should conform to [__PEP8 standards__][pep8].

0. Pull requests should be submitted to the 'master' branch.

[dojo_settings]: /dojo/settings/settings_dist.py "DefectDojo settings file"
[setup_py]: /setup.py "Python setup script"
[setup_bash]: /setup.bash "Bash setup script"
[pep8]: https://www.python.org/dev/peps/pep-0008/ "PEP8"
