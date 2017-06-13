Upgrading
=========

The easiest way to upgrade to a new version of DefectDojo is to pull from Github.  Assuming the source code lives in a
directory named `defect-dojo` you can complete the following steps to upgrade to the latest DefectDojo release.::

    cd defect-dojo
    git checkout master
    git pull
    ./manage.py makemigrations dojo
    ./manage.py makemigrations
    ./manage.py migrate

Because bower assests change from time to time, it is always a good idea to re-install them and collect the static
resources. ::

    cd defect-dojo
    cd components
    bower install
    cd ..

At this point bower may ask you to select from different versions of packages, choose the latest on each.

Next you can run: ::

    ./manage.py collectstatic --noinput

If you are in your production system, you will need to restart gunicorn and celery to make sure the latest code is
being used by both.

Upgrading to Django 1.11
========================

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
    ./manage.py makemigrations
    ./manage.py migrate

The following must be removed/commendted out from settings.py: ::

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
