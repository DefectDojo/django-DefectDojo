#!/bin/bash

source ${BASH_SOURCE%/*}/common-functions.bash
source ${BASH_SOURCE%/*}/common-vars.bash


function cache_load {
    local builder="${1:+ builder}" # Include 'builder' if called with any param
    local build_images docker_image image_id archive image_repo

    # Several builds can share the same Docker image,
    # or images from concurrent builds can be present in the cache,
    # thus the need to track images per build to only load what is needed
    build_images=($(<"${DOCKER_CACHE}/travis-${TRAVIS_BUILD_NUMBER}.images"))

    # Load only Docker images/archives required by the current build and job
    for (( i=0; i<${#build_images[@]}; i+=2 ))
    do
        docker_image="${build_images[$i]}"
        image_id="${build_images[$((i + 1))]}"

        if ! [[ "${DOCKER_IMAGES[@]}${builder}" =~ "${docker_image}" ]]
        then
            echo_warning "skipping '${docker_image}', not requested."
            continue
        fi

        archive="${DOCKER_CACHE}/${image_id}.tar.gz"

        if [ ! -r "${archive}" ]
        then
            echo_warning "cannot import '${archive##*/}' into Docker cache."
            continue
        fi

        echo_info "importing '${archive##*/}' into Docker cache..."
        zcat "${archive}" | docker load

        # Image may come from a previous/concurrent build; tag with current one
        image_repo="${DOCKER_USER}/${IMAGE_PREFIX}-${docker_image}"
        docker tag "${image_id}" "${image_repo}:travis-${TRAVIS_BUILD_NUMBER}"
    done
}


function cache_save {
    local builder="${1:+ builder}" # Include 'builder' if called with any param
    local image_tag build_images image_repo image_id docker_image archive

    # Only cache images produced in current build, others can be pulled; it
    # reduces the time needed by Travis-CI to load the cache in concurrent jobs
    image_tag="travis-${TRAVIS_BUILD_NUMBER}"
    build_images=($(
    docker images \
      --filter 'dangling=false' \
      --filter "reference=${DOCKER_USER}/*:${image_tag}" \
      --format '{{.Repository}} {{.ID}}'
    ))

    for (( i=0; i<${#build_images[@]}; i+=2 ))
    do
        image_repo="${build_images[$i]}"
        image_id="${build_images[$((i + 1))]}"
        docker_image="${image_repo##*-}"

        if ! [[ "${DOCKER_IMAGES[@]}${builder}" =~ "${docker_image}" ]]
        then
            echo_warning "skipping '${docker_image}', not requested."
            continue
        fi

        # Link image with current build; required to handle concurrent builds
        echo "${docker_image} ${image_id}" >> \
             "${DOCKER_CACHE}/travis-${TRAVIS_BUILD_NUMBER}.images"

        archive="${DOCKER_CACHE}/${image_id}.tar.gz"

        # Don't rewrite existing images; tag will be fixed during `cache_load`
        if [ -e "${archive}" ]
        then
            echo_warning "skipping '${image_repo}', image already in cache."
            continue
        fi

        if [ ! -w "${archive%/*}" ]
        then
            echo_error "cannot write '${image_repo}' to '${archive}'."
            continue
        fi

        echo_info "exporting '${image_repo}' to '${archive}'..."
        docker save "${image_id}" | gzip -2 > "${archive}"
        echo_success "exporting '${image_repo}' to '${archive}' done."
    done
}


function cache_clean {
    local dot_images others_deps others_images build_images
    local other_deps other_images i other_id image_repo image_id

    dot_images=$(ls -1 "${DOCKER_CACHE}/"*.images)
    if [ $(echo "${dot_images}" | wc -l) -lt 2 ] # [0-1] includes orphan images
    then
        # Easy case: no images from other builds, delete all archives
        echo_warning "deleting all archives, no images cached by other builds."
        rm -f "${DOCKER_CACHE}/"*.tar.gz
    else
        # Otherwise: delete only images that are not used in other builds
        # 1- gather all image IDs used in other builds into 'others_images'
        others_images=()
        others_deps=($(echo "${dot_images}" | grep -v "${TRAVIS_BUILD_NUMBER}"))
        for other_deps in "${others_deps[@]}"
        do
            echo_info "Getting dependencies from '${other_deps}'..."
            other_images=($(<"${other_deps}"))
            for (( i=0; i<${#other_images[@]}; i+=2 ))
            do
                other_id="${other_images[$((i + 1))]}"
                # Don't bother about duplicates, this is a very small set
                others_images+=("${other_id}")
            done
        done

        # 2- delete images/archives used in current build but not in others
        build_images=($(<"${DOCKER_CACHE}/travis-${TRAVIS_BUILD_NUMBER}.images"))
        for (( i=0; i<${#build_images[@]}; i+=2 ))
        do
            image_repo="${build_images[$i]}"
            image_id="${build_images[$((i + 1))]}"
            if ! [[ "${others_images[@]}" =~ "${image_id}" ]]
            then
                echo_warning "removing '${image_id}' (${image_repo}) from cache."
                rm -f "${DOCKER_CACHE}/${image_id}.tar.gz"
            fi
        done
    fi

    rm -f "${DOCKER_CACHE}/travis-${TRAVIS_BUILD_NUMBER}.images"
}


[ -n "${DOCKER_CACHE}" ] && run_or_die cache_"${1}" "${2}"
