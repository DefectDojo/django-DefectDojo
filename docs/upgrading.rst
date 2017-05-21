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