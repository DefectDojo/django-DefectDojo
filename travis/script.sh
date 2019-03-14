#!/bin/bash
RETURN_VALUE=0
if [ -z "$TEST" ]; then
  # Build Docker images
  DOCKER_IMAGES=(django nginx)
  for DOCKER_IMAGE in "${DOCKER_IMAGES[@]}"
  do
    docker build \
      --tag "defectdojo/defectdojo-${DOCKER_IMAGE}" \
      --file "Dockerfile.${DOCKER_IMAGE}" \
      .
  done

  # Start Minikube
  sudo minikube start \
    --vm-driver=none \
    --kubernetes-version="${K8S_VERSION}"

  # Configure Kubernetes context and test it
  sudo minikube update-context
  sudo kubectl cluster-info

  # Enable Nginx ingress add-on and wait for it
  sudo minikube addons enable ingress
  echo -n "Waiting for Nginx ingress controller "
  until [[ "True" == "$(sudo kubectl get pod \
    --selector=app.kubernetes.io/name=nginx-ingress-controller \
    --namespace=kube-system \
    -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')" ]]
  do
    sleep 1
    echo -n "."
  done
  echo

  # Create Helm and wait for Tiller to become ready
  sudo helm init
  echo -n "Waiting for Tiller "
  until [[ "True" == "$(sudo kubectl get pod \
    --selector=name=tiller \
    --namespace=kube-system \
    -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')" ]]
  do
    sleep 1
    echo -n "."
  done
  echo

  # Update Helm repository
  sudo helm repo update

  # Update Helm dependencies for DefectDojo
  sudo helm dependency update ./helm/defectdojo

  # Install DefectDojo into Kubernetes and wait for it
  sudo helm install \
    ./helm/defectdojo \
    --name=defectdojo \
    --set django.ingress.enabled=false \
    --set imagePullPolicy=Never
  echo -n "Waiting for DefectDojo to become ready "
  i=0
  # Timeout value so that the wait doesn't timeout the travis build (faster fail)
  TIMEOUT=20
  until [[ "True" == "$(sudo kubectl get pod \
      --selector=defectdojo.org/component=django \
      -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')" \
      || $i -gt $TIMEOUT ]]
  do
    ((i++))
    sleep 6
    echo -n "."
  done
  if [[ $i -gt $TIMEOUT ]]; then
    RETURN_VALUE=1
  fi
  echo
  echo "UWSGI logs"
  sudo kubectl logs --selector=defectdojo.org/component=django -c uwsgi
  echo
  echo "DefectDojo is up and running."
  sudo kubectl get pods

  # Run all tests
  echo "Running tests."
  sudo helm test defectdojo
  # Check exit status
  RETURN_VALUE=$?
  echo
  echo "Unit Tests"
  sudo kubectl logs defectdojo-django-unit-test --namespace default
  echo
  echo "Pods"
  sudo kubectl get pods

  # Uninstall
  echo "Deleting DefectDojo from Kubernetes."
  sudo helm delete defectdojo --purge
  sudo kubectl get pods
  exit RETURN_VALUE
else
echo "Running test=$TEST"
  case "$TEST" in
    flake8)
      echo "$TRAVIS_BRANCH"
      if [ "$TRAVIS_BRANCH" == "k8s" ]
      then
          echo "Running Flake8 tests on dev branch aka pull requests"
          # We need to checkout dev for flake8-diff to work properly
          git checkout dev
          pip install pep8 flake8 flake8-diff
          flake8-diff
      else
          echo "true"
      fi
  esac
fi
