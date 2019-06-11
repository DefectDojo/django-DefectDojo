#!/bin/bash
ORG="defectdojo"

deploy_demo() {
  # Deploy to dev or prod once merged to master or dev
  if [ "$HEROKU_API_KEY" != "" ]; then
    # Deploy
    echo "Heroku Deployment"
    if [ $TRAVIS_BRANCH == "dev" ] || [ $TRAVIS_BRANCH == "master" ]; then
      DEPLOY_ENV="-dev"
      if [ $TRAVIS_BRANCH == "master" ]; then
        DEPLOY_ENV=""
      fi
      echo "Deploying to: defectdojo${DEPLOY_ENV}"
      docker tag "defectdojo/defectdojo-django" "registry.heroku.com/defectdojo${DEPLOY_ENV}/web"
      docker login -u "$HEROKU_EMAIL" -p "$HEROKU_API_KEY" registry.heroku.com
      docker push registry.heroku.com/defectdojo${DEPLOY_ENV}/web
      heroku container:release web -a defectdojo${DEPLOY_ENV}
      echo "Running migrations"
      heroku run bash /opt/heroku-DefectDojo/scripts/migrate.bash -a defectdojo${DEPLOY_ENV}
    fi
  fi
}

docker_hub() {
  if { [ "${TRAVIS_TAG}" != "" ] || [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; } && [ "${DOCKER_USER}" != "" ] && [  "${DOCKER_PASS}" != "" ]; then
    DOCKER_IMAGES=(django nginx)
    echo "Pushing to Docker Hub"
    for docker_image in "${DOCKER_IMAGES[@]}"
    do
        REPO="${ORG}/${ORG}-${docker_image}"
        echo "Pushing to: ${REPO}"
        # Cron pushed into branch-weekly-dev-image, triggered weekly
        if [ "${TRAVIS_EVENT_TYPE}" == "cron" ]; then
          TRAVIS_TAG=`date +%Y-%m-%d`-${TRAVIS_BRANCH}
          REPO="${ORG}/weekly-${ORG}-${docker_image}"
        elif [ ${TRAVIS_BRANCH} == "master" ]; then
          docker tag $CONTAINER $REPO:latest
        else
          TRAVIS_TAG=${TRAVIS_BRANCH}-${TRAVIS_TAG}
        fi

        CONTAINER="${ORG}/${ORG}-${docker_image}"

        docker tag $CONTAINER $REPO:$TRAVIS_TAG
        docker tag $CONTAINER $REPO:$TRAVIS_BUILD_ID
        docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"
        docker push $REPO
    done
  fi
}
