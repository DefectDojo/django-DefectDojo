#!/usr/bin/env python

from setuptools import setup

setup(
    name='DefectDojo',
    version='0.9.0',
    author='Greg Anderson',
    description="Tool for managing vulnerability engagements",
    install_requires=[
        'Django==1.6.10',
        'MySQL-python==1.2.5',
        'Pillow==2.3.0',
        'South==0.8.4',
        'django-secure==1.0',
        'django-tastypie==0.11.1',
        'gunicorn==19.1.1',
        'python-nmap==0.3.4',
        'pytz==2013.9',
        'requests==2.2.1',
        'wsgiref==0.1.2',
        'django-tastypie-swagger',
        'django-filter',
        'supervisor',
        'humanize'],
    # packages=['DefectDojo'],
    url='https://github.com/rackerlabs/django-DefectDojo'

        """
        entry_points={
        'console_scripts': [
        'supernova = supernova.executable:run_supernova',
        'supernova-keyring = supernova.executable:run_supernova_keyring'],
        },
        """
)
