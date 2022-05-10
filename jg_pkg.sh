#!/usr/bin/env bash
# adapted from https://github.com/DefectDojo/django-DefectDojo/blob/master/.github/workflows/release-x-manual-helm-chart.yml#L35-L45
helm repo add bitnami https://charts.bitnami.com/bitnami
helm dependency list ./helm/defectdojo
helm dependency update ./helm/defectdojo
mkdir -p build
helm package helm/defectdojo/ --destination ./build
cp build/* .
git add -f ./*.tgz
