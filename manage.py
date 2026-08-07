#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # Django's parallel test runner supports two multiprocessing start
        # methods, and Python 3.14 defaults to neither of them on Linux: it
        # switched from "fork" to "forkserver". Under forkserver, django/test/
        # runner.py::_init_worker calls django.setup() only when the method is
        # "spawn", so a worker unpickles its subsuite with no app registry and
        # dies on "AppRegistryNotReady: Apps aren't loaded yet."
        #
        # Choose spawn rather than restoring fork: it is the start method whose
        # worker initialisation Django actually implements, and forking a
        # process that may already have threads is what Python moved away from.
        #
        # Only for `test`, so nothing else that runs through manage.py is
        # affected. Django's own get_max_test_processes() falls back to a single
        # process for any other start method, so if this ever stops applying,
        # `--parallel auto` degrades to serial instead of failing.
        import multiprocessing

        multiprocessing.set_start_method("spawn", force=True)

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
