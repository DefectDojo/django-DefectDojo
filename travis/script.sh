#!/bin/bash
travis_fold() {
  local action="${1}"
  local name="${2}"
  echo -en "travis_fold:${action}:${name}\r"
}

build_containers() {
  # Build Docker images
  travis_fold start docker_image_build
  DOCKER_IMAGES=(django nginx)
  for docker_image in "${DOCKER_IMAGES[@]}"
  do
    docker build \
      --tag "defectdojo/defectdojo-${docker_image}" \
      --file "Dockerfile.${docker_image}" \
      .
    return_value=${?}
    if [ ${return_value} -ne 0 ]; then
      (>&2 echo "ERROR: cannot build '${docker_image}' image")
      exit ${return_value}
    fi
  done
  travis_fold end docker_image_build
}

return_value=0
if [ -z "${TEST}" ]; then
  # Start Minikube
  travis_fold start minikube_install
  minikube start \
    --driver=docker \
    --kubernetes-version="${K8S_VERSION}"
  eval $(minikube docker-env)
  build_containers
  # Configure Kubernetes context and test it
  minikube update-context
  kubectl cluster-info

  # Enable Nginx ingress add-on and wait for it
  minikube addons enable ingress
  echo -n "Waiting for Nginx ingress controller "
  until [[ "True" == "$(kubectl get pod \
    --selector=app.kubernetes.io/component=controller,app.kubernetes.io/name=ingress-nginx \
    --namespace=kube-system \
    -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')" ]]
  do
    sleep 1
    echo -n "."
  done
  echo




  # Update Helm dependencies for DefectDojo
  helm repo add stable https://kubernetes-charts.storage.googleapis.com/
  helm dependency update ./helm/defectdojo

  # Set Helm settings for the broker
  case "${BROKER}" in
    rabbitmq)
      HELM_BROKER_SETTINGS=" \
        --set redis.enabled=false \
        --set rabbitmq.enabled=true \
        --set celery.broker=rabbitmq \
        --set createRabbitMqSecret=true \
      "
      ;;
    redis)
      HELM_BROKER_SETTINGS=" \
        --set redis.enabled=true \
        --set rabbitmq.enabled=false \
        --set celery.broker=redis \
        --set createRedisSecret=true \
      "
      ;;
    *)
      (>&2 echo "ERROR: 'BROKER' must be 'redis' or 'rabbitmq'")
      exit 1
      ;;
  esac

  # Set Helm settings for the database
  case "${DATABASE}" in
    mysql)
      HELM_DATABASE_SETTINGS=" \
        --set database=mysql \
        --set postgresql.enabled=false \
        --set mysql.enabled=true \
        --set createMysqlSecret=true \
      "
      ;;
    postgresql)
      HELM_DATABASE_SETTINGS=" \
        --set database=postgresql \
        --set postgresql.enabled=true \
        --set mysql.enabled=false \
        --set createPostgresqlSecret=true \
      "
      ;;
    *)
      (>&2 echo "ERROR: 'DATABASE' must be 'mysql' or 'postgresql'")
      exit 1
      ;;
  esac

  case "${REPLICATION}" in
    enabled)
    HELM_DATABASE_SETTINGS=" \
      --set database=postgresql \
      --set postgresql.enabled=true \
      --set mysql.enabled=false \
      --set createPostgresqlSecret=true \
      --set postgresql.replication.enabled=true \
    "
    ;;
  esac
  # Test does it propagates extra vars and secrets
  case "${EXTRAVAL}" in
    enabled)
    HELM_CONFIG_SECRET_SETTINGS=" \
      --set extraConfigs.DD_EXAMPLE_CONFIG=testme \
      --set extraSecrets.DD_EXAMPLE_SECRET=testme \
    "
    ;;
  esac
  # Install DefectDojo into Kubernetes and wait for it
  helm install \
    defectdojo \
    ./helm/defectdojo \
    --set django.ingress.enabled=false \
    --set imagePullPolicy=Never \
    ${HELM_BROKER_SETTINGS} \
    ${HELM_DATABASE_SETTINGS} \
    ${HELM_CONFIG_SECRET_SETTINGS} \
    --set createSecret=true


  echo -n "Waiting for DefectDojo to become ready "
  i=0
  # Timeout value so that the wait doesn't timeout the travis build (faster fail)
  TIMEOUT=20
  until [[ "True" == "$(kubectl get pod \
      --selector=defectdojo.org/component=django \
      -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')" \
      || ${i} -gt ${TIMEOUT} ]]
  do
    ((i++))
    sleep 6
    echo -n "."
  done
  if [[ ${i} -gt ${TIMEOUT} ]]; then
    return_value=1
  fi
  echo
  echo "UWSGI logs"
  kubectl logs --selector=defectdojo.org/component=django -c uwsgi
  echo
  echo "DefectDojo is up and running."
  kubectl get pods
  travis_fold end minikube_install


  # Test if postgres has replication enabled
  if [[ "${REPLICATION}" == "enabled" ]]
  then
    travis_fold start defectdojo_tests_replication
    items=`kubectl get pods -o name | grep slave | wc -l`
    echo "Number of replicas $items"
    if [[ $items < 1 ]]; then
      echo "Wrong number of replicas"
      return_value=1
    fi
  travis_fold end defectdojo_tests_replication
  fi

  # Test extra config and secret by looking 2 enviroment values testme
  if [[ "${EXTRAVAL}" == "enabled" ]]
  then
    travis_fold start defectdojo_tests_extravars
    items=`kubectl exec -i $(kubectl get pods -o name | grep django | \
    sed "s/pod\///g") -c uwsgi printenv | grep testme | wc -l`
    echo "Number of items $items"
    if [[ $items < 2 ]]; then
      echo "Missing extra variables"
      return_value=1
    fi
  travis_fold end defectdojo_tests_extravars
  fi

  # Run all tests
  travis_fold start defectdojo_tests
  echo "Running tests."
  helm test defectdojo
  # Check exit status
  return_value=${?}
  echo
  echo "Unit test results"
  kubectl logs defectdojo-unit-tests
  echo
  echo "Pods"
  kubectl get pods

  # Uninstall
  echo "Removing DefectDojo from Kubernetes"
  helm uninstall defectdojo
  kubectl get pods
  travis_fold end defectdojo_tests

  exit ${return_value}
else
echo "Running test ${TEST}"
  case "${TEST}" in
    flake8)
      echo "${TRAVIS_BRANCH}"
      if [[ "${TRAVIS_BRANCH}" == "dev" ]]
      then
          echo "Running Flake8 tests on dev branch aka pull requests"
          # We need to checkout dev for flake8-diff to work properly
          git checkout dev
          sudo pip3 install pep8 flake8 flake8-diff
          flake8-diff
      else
          echo "Skipping because not on dev branch"
      fi
      ;;
    docker_integration_tests)
      echo "Validating docker compose"
      # change user id withn Docker container to user id of travis user
      sed -i -e "s/USER\ 1001/USER\ `id -u`/g" ./Dockerfile.django
      cp ./dojo/settings/settings.dist.py ./dojo/settings/settings.py
      # incase of failure and you need to debug
      # change the 'release' mode to 'dev' mode in order to activate debug=True
      # make sure you remember to change back to 'release' before making a PR
      source ./docker/setEnv.sh release
      docker-compose build

      docker-compose up -d
      echo "Waiting for services to start"
      # Wait for services to become available
      sleep 80
      echo "Testing DefectDojo Service"
      curl -s -o "/dev/null" http://localhost:8080 -m 120
      CR=$(curl -s -m 10 -I http://localhost:8080/login?next= | egrep "^HTTP" | cut  -d' ' -f2)
      if [ "$CR" != 200 ]; then
        echo "ERROR: cannot display login screen; got HTTP code $CR"
        docker-compose logs  --tail="all" uwsgi
        exit 1
      fi
      echo "Docker compose container status"
      docker-compose -f docker-compose.yml ps

      echo "run integration_test scripts"
      source ./travis/integration_test-script.sh
      ;;
    snyk)
      echo "Snyk security testing on containers"
      build_containers
      snyk monitor --docker defectdojo/defectdojo-django:latest
      snyk monitor --docker defectdojo/defectdojo-nginx:latest
      ;;
    deploy)
      echo "Deploy and container push"
      build_containers
      source ./travis/deploy.sh
      deploy_demo
      docker_hub
      ;;
  esac
fi
