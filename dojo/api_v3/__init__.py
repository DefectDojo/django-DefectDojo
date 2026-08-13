"""
API v3 (alpha) kernel package.

The NinjaAPI instance and mount assembly live in ``dojo.api_v3.api`` (imported by ``dojo/urls.py``
only when ``V3_FEATURE_LOCATIONS`` is on). This package root is deliberately empty of imports so
that importing a kernel submodule (``refs``/``expand``/...) never eagerly builds the API -- that
would create an import cycle with the resource route modules.
"""
