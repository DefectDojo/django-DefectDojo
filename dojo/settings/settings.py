from split_settings.tools import optional, include

# Defetc Dojo uses 3 settings file to get you going
# - settings.dist.py:
#       The main settings are all stored here, it also reads from the environment variables (see contents of settings.dist.py).
# - "env file, i.e. .env.prod" (not stored in git)
#       The settings.dist.py file reads variables from the file with name DD_ENV_PATH (default .env.prod file).
#       Example in template_env file
# - local_settings.py (not stored in git)
#       A file stored locally / on the server containing more complex customizations such as adding MIDDLEWARE or INSTALLED_APP entries.
#       This file is processed *after* settings.dist.py is processed, so you can modify settings delivered by Defect Dojo out of the box.
#       Example in template-local_settings

include(
    'settings.dist.py',
    optional('local_settings.py')
)
