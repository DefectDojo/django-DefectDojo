# Guide to Writing Documentation

When developing documentation, there are steps to take before submitting a pull request

1. Writing your documentation with [hot reloading](#development-with-hot-reloading) live in your browser
2. Verifying your changes with a [production build](#mimic-production-environment) to ensure Hugo will minify everything correctly

## Development with Hot Reloading

This method performs the following from the `django-DefectDojo/docs` directory:

1. Remove any existing packages to perform a fresh install each time: `rm -rf public node_modules`
2. Install all packages: `npm install`
3. Start the server: `npm run dev`
4. Access the [site in the browser at http://localhost:1313](http://localhost:1313)

### Execution List

```bash
rm -rf public node_modules
npm install
npm run dev
```

or for a one liner:

```bash
rm -rf public node_modules && \
npm install && \
npm run dev
```

## Mimic Production Environment

This method performs the following from the `django-DefectDojo/docs` directory:

1. Remove any existing packages to perform a fresh install each time: `rm -rf public node_modules`
2. Install all packages in CI mode to only install from `package-lock.json`: `npm ci`
3. Run Hugo to build the site in the way the CI job does, but in development environment to point at `localhost` for integrity checks : `npm run build -- --environment development`
4. Change directory to the new `public` directory to run the site locally: `cd public`
5. Run a light weight webserver to server the files, and [access the site at http://localhost:8080](http://localhost:8080): `python3 -m http.server 8080`
6. After killing the webserver process, navigate back to the `django-DefectDojo/docs` directory: `cd ../`

### Execution List

```bash
rm -rf public node_modules
npm ci
npm run build -- --environment development
cd public
python3 -m http.server 8080
cd ../
```

or for a one liner:

```bash
rm -rf public node_modules && \
npm ci && \
npm run build -- --environment development && \
cd public && \
python3 -m http.server 8080 && \
cd ../
```
