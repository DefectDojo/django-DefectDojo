Extra JSON fixtures in this folder will be added to /app/dojo/fixtures and will be automatically loaded by the initializer.
Files must be prefixed with "extra_" to avoid conflicts with existing default fixtures.

You can define the loading order by adding some numbers to filename:
- extra_001_fixture.json
- extra_002_fixture.json
- extra_003_fixture.json