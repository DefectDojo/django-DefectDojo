#!/usr/bin/env python

from setuptools import setup

setup(
    name='DefectDojo',
    version='1.0',
    author='Greg Anderson',
    description="Tool for managing vulnerability engagements",
    install_requires=[
        'Django>=1.7',
        'MySQL-python==1.2.5',
        'Pillow==2.3.0',
        'django-secure==1.0',
        'django-tastypie==0.12.1',
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
