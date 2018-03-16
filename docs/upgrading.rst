Upgrading
=========

The easiest way to upgrade to a new version of DefectDojo is to pull from Github.  Assuming the source code lives in a
directory named `defect-dojo` you can complete the following steps to upgrade to the latest DefectDojo release.::

    cd defect-dojo
    git checkout master
    git pull
    pip install .
    ./manage.py migrate

Because yarn assets change from time to time, it is always a good idea to re-install them and collect the static
resources. ::

    cd defect-dojo
    cd components
    yarn
    cd ..

At this point yarn may ask you to select from different versions of packages, choose the latest on each.

Next you can run: ::

    ./manage.py collectstatic --noinput

If you are in your production system, you will need to restart gunicorn and celery to make sure the latest code is
being used by both.

Upgrading to Django 1.1.5
-------------------------

If you are upgrading an existing version of DefectDojo, you will need to run the following commands manually: ::

First install Yarn:

Follow the instructions based on your OS: https://yarnpkg.com/lang/en/docs/install/

The following must be removed/commented out from settings.py: ::

    'djangobower.finders.BowerFinder',

    From the line that contains:
    # where should bower install components
    ...

    To the end of the bower declarations
      'justgage'
    )

The following needs to be updated in settings.py: ::

    STATICFILES_DIRS = (
        # Put strings here, like "/home/html/static" or "C:/www/django/static".
        # Always use forward slashes, even on Windows.
        # Don't forget to use absolute paths, not relative paths.
        os.path.dirname(DOJO_ROOT) + "/components/yarn_components",
    )

Upgrading to Django 1.11
------------------------

Pull request #300 makes DefectDojo Django 1.11 ready.  A fresh install of DefectDojo can be done with the setup.bash
script included - no special steps are required.

If you are upgrading an existing installation of DefectDojo, you will need to run the following commands manually: ::

    pip install django-tastypie --upgrade
    pip install django-tastypie-swagger --upgrade
    pip install django-filter --upgrade
    pip install django-watson --upgrade
    pip install django-polymorphic --upgrade
    pip install django --upgrade
    pip install pillow --upgrade
    ./manage.py migrate

The following must be removed/commented out from settings.py: ::

    TEMPLATE_DIRS
    TEMPLATE_DEBUG
    TEMPLATE_LOADERS
    TEMPLATE_CONTEXT_PROCESSORS

The following needs to be added to settings.py: ::

    TEMPLATES  = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
    ]

Once all these steps are completed your installation of DefectDojo will be running under Django 1.11


July 6th 2017 - New location for system settings
------------------------------------------------

Pull request #313 moves a number of system settings previously located in the application's settings.py
to a model that can be used and changed within the web application under "Configuration -> System Settings".

If you're using a custom ``URL_PREFIX`` you will need to set this in the model after upgrading by
editing ``dojo/fixtures/system_settings.json`` and setting your URL prefix in the ``url_prefix`` value there.
Then issue the command ``./manage.py loaddata system_settings.json`` to load your settings into the database.

If you're not using a custom ``URL_PREFIX``, after upgrading simply go to the System Settings page and review
which values you want to set for each setting, as they're not automatically migrated from settings.py.

If you like you can then remove the following settings from settings.py to avoid confusion:

* ``ENABLE_DEDUPLICATION``
* ``ENABLE_JIRA``
* ``S_FINDING_SEVERITY_NAMING``
* ``URL_PREFIX``
* ``TIME_ZONE``
* ``TEAM_NAME``

Upgrading to DefectDojo Version 1.2.2
-------------------------------------

Upgrading to 1.2.2 requires:

1. Copying settings.py to the settings/ folder.

2. If you have supervisor scripts change DJANGO_SETTINGS_MODULE=dojo.settings.settings

Upgrading to DefectDojo Version 1.2.3
-------------------------------------

Upgrading to 1.2.3 requires:

1.  ./manage.py makemigrations
    ./manage.py migrate
    ./manage.py loaddata dojo/fixtures/language_type.json

2. Currently languages and technologies can be updated via the API or in the admin section of Django.

Upgrading to DefectDojo Version 1.3.0
-------------------------------------

In version 1.3.0, we've done an important change: we're now keeping migration files under version control.
For you this means the following, depending on how you've used DefectDojo until now:

- **No persistent data to take over**: If you've **cloned** the repo everytime a new release came out,
  **built a Docker container** and ran Defect Dojo this way, you don't
  need to do anything and you can continue as is.
  Be aware, though, that if you want to persist your data, you can do so,
  now with a DB running outside the Docker container.

- **Data needs to be migrated**: If you've **fetched and merged** the latest version and you have run
  **makemigrations** at every new release it's going to be a bit harder.
  In this case, you probably have a couple of migration files under ``dojo/migrations/`` already.

  Follow these steps to reach a consistent state again (**Disclaimer**: no warranty for the correctness of these steps! ALWAYS back up your DB before running this kind of operations!):

  #. Back up your migration files (at ``dojo/migrations/``) **before** merging the remote git branch
  #. Move the ``0001_initial.py`` migration file that came with the merge to a safe place (you'll need it again later)
  #. Add your own migration files back to the ``dojo/migrations/`` folder
  #. Run ``python manage.py makemigrations dojo``, which probably creates a new migration file
  #. Run ``python manage.py migrate`` to apply all migrations
  #. Remove all your migration files from the folder ``dojo/migrations/`` and restore the ``0001_initial.py`` migration that you've backed up in the second step
  #. Remove migration information from the DB by running the raw SQL statement ``DELETE FROM django_migrations WHERE app = 'dojo'``
  #. Run ``python manage.py migrate --fake-initial``
  #. You're done! Your data now follows the DefectDojo migrations under version control.

For future releases of DefectDojo, a simple ``python manage.py migrate`` will be sufficient to keep the DB schema up to date.

For more information on Django's migration mechanism refer to `the Django documentation <https://docs.djangoproject.com/en/dev/topics/migrations/>`_.
