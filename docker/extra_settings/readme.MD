A local_settings.py file can be placed here to override/extend the settings bundled with Defect Dojo

If a file if placed here, it will be copied on startup to dojo/setting/local_settings.py.

For an example, see dojo/settings/template-local_settings

Please note this copy action could fail if you have mounted the full dojo/ folder, but that is owned by a different user/group.
That's why this copy action only happens in docker-compose release mode, and not in dev/ptvsd/unit_tests/integration_tests modes.

For advanced usage you can also place a settings.dist.py or settings.py file. These will also be copied on startup to dojo/settings.



