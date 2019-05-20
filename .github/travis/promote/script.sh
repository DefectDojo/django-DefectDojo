#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash


function promote_dockerhub {
    local latest current_tag target_tag builder
    local docker_image image_repo image_ref target_ref

    #TODO: consider moving to '.travis.yml', to separate build logic from tasks
    # Travis-CI build IDs being incremental, a higher build ID will have a more
    # recent code base, and an image built in such build superseeds current one
    if [ -r "${DOCKER_CACHE}/latest" ]
    then
        latest=$(<"${DOCKER_CACHE}/latest")
        # Do not promote if the job have succeeded before (ex: job restart)
        if [ "${TRAVIS_BUILD_NUMBER}" -le "${latest}" ]
        then
            echo_warning "images already promoted by more recent build ${latest}."
            return 0
        fi
    fi

    echo "${DOCKER_PASS}" | docker login -u "${DOCKER_USER}" --password-stdin

    [ ${?} -ne 0 ] &&
        error_and_exit "cannot login to Docker Hub registry."

    # Merges to 'master' being distant compared to 'dev' and other feature
    # branches, a 'builder' image for 'master' gives no noticable enhancements
    current_tag="travis-${TRAVIS_BUILD_NUMBER}"
    target_tag='latest'
    if [ "${TRAVIS_BRANCH}" != 'master' ]
    then
        target_tag="${TRAVIS_BRANCH}"
        builder='builder'
    fi

    for docker_image in ${DOCKER_IMAGES[@]} ${builder:-}
    do
        image_repo="${DOCKER_USER}/${IMAGE_PREFIX}-${docker_image}"
        image_ref="${image_repo}:${current_tag}"
        target_ref="${image_repo}:${target_tag}"

        travis_fold start promote_dockerhub.${docker_image}
        echo_info "promoting '${image_ref}' to '${target_ref}'..."

        docker tag "${image_ref}" "${target_ref}"
        echo_success "promoting '${image_ref}' to '${target_ref}' done."

        echo_info "pushing '${target_ref}' to Docker Hub registry..."
        docker push "${target_ref}"
        return_value=${?}
        travis_fold end promote_dockerhub.${docker_image}

        [ ${return_value} -ne 0 ] &&
            error_and_exit "cannot push '${target_ref}' to registry."

        echo_success "pushing '${target_ref}' to Docker Hub registry done."
    done
    echo ${TRAVIS_BUILD_NUMBER} > ${DOCKER_CACHE}/latest
}


run_or_die promote_dockerhub
