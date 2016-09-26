#!/usr/bin/env python

from setuptools import setup

setup(
    name='DefectDojo',
    version='1.0.5',
    author='Greg Anderson',
    description="Tool for managing vulnerability engagements",
    install_requires=[
        'celery',
        'defusedxml',
        'django-auditlog==0.3.3',
        'django-bower',
        'django-custom-field',
        'django-filter',
        'django-imagekit',
        'django-overextends',
        'django-polymorphic==0.7',
        'django-secure>1.0',
        'django-tagging',
        'django-tastypie>=0.12.2',
        'django-tastypie-swagger',
        'django-watson==1.1.9',
        'gunicorn>=19.1.1',
        'html2text',
        'humanize',
        'mimeparse',
        'MySQL-python',
        'pdfkit==0.5.0',
        'Pillow==3.3.0',
        'python-nmap>=0.3.4',
        'pytz>=2013.9',
        'requests>=2.2.1',
        'sqlalchemy',
        'supervisor',
        'uwsgi',
        'vobject',
        'watson',
        'wsgiref>=0.1.2',
        'Django==1.8.10'],
    dependency_links=[
        "https://github.com/grendel513/python-pdfkit/tarball/master#egg=pdfkit-0.5.0",
    ],
    url='https://github.com/rackerlabs/django-DefectDojo'
)
