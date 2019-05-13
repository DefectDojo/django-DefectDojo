#!/bin/bash


# Print a message in blue with an 'INFO:' prefix.
function echo_info {
    ANSI_BLUE="\033[34;1m"
    echo -e "${ANSI_BLUE}INFO: ${@}${ANSI_RESET}"
}

# Print a message in magenta with a 'WARNING:' prefix.
function echo_warning {
    ANSI_MAGENTA="\033[35;1m"
    echo -e "${ANSI_MAGENTA}WARNING: ${@}${ANSI_RESET}"
}

# Print a message in green with a 'SUCCESS:' prefix.
function echo_success {
    echo -e "${ANSI_GREEN}SUCCESS: ${@}${ANSI_RESET}"
}

# Print a message in red with a 'ERROR:' prefix.
function echo_error {
    echo -e "${ANSI_RED}ERROR: ${@}${ANSI_RESET}"
}

# Print an error message and exit with 1.
function error_and_exit {
    (>&2 echo_error "${@} Exiting.")
    exit 1
}

# Override standard calls to the `travis_fold` function provided by Travis-CI.
# Add an index suffix to isolate folds having the same name within a job.
# Like with Travis-CI, avoid nested folds named like one of their ancestors.
function travis_fold {
    local action="${1}"
    local name="${2}"

    # Increment the index when a new fold is started
    # Use a temporary file to persist the index between scripts within a job
    local counter_name=$(echo -n "${name}" | tr -s '. \\/' '_')
    local counter_file="${TRAVIS_TMPDIR}/travis_fold:${counter_name}"
    local counter=1
    if [ -f "${counter_file}" ]
    then
	[ ! -r "${counter_file}" ] &&
	    error_and_exit "cannot read from '${counter_file}' file."

	counter=$(<"${counter_file}")
	[ "${action}" = 'start' ] && counter=$((counter + 1))
    fi

    [ ! -w "${TRAVIS_TMPDIR}" ] &&
	error_and_exit "cannot write to '${counter_file}' file."

    echo -n "${counter}" > "${counter_file}"

    echo -en "travis_fold:${action}:${name}.${counter}\r${ANSI_CLEAR}"
}

# Run a function, which output can be folded in a Travis-CI log.
# If the function doesn't exist, print an error message and exit 1.
function run_or_die {
    local func_name="${1}"

    if [ -n "$(declare -F ${func_name})" ]
    then
	travis_fold start ${func_name}
	echo_info "Executing ${func_name}..."

	shift
	${func_name} "${@}"
	return_value=${?}

	travis_fold end ${func_name}
	echo_success "Executing ${func_name} done."
    else
        error_and_exist "function '${func_name}' does not exist."
    fi

    return ${return_value}
}

# Wrapper to override standard calls to the `docker` command.
# Transparently adds caching capabilities to `docker build` subcommand.
# Does not affect other `docker` subcommands.
function docker {
    local subcmd="${1}"

    case ${subcmd} in
	build)
	    shift
	    local cache_from cache_images

	    # Populate the local Docker library if caching is enabled
	    if [ -n "${DOCKER_CACHE}" ]
	    then
		local build_tag="travis-${TRAVIS_BUILD_NUMBER}"

		local docker_image image_repo
		for docker_image in ${DOCKER_IMAGES[@]} builder
		do
		    image_repo="${DOCKER_USER}/${IMAGE_PREFIX}-${docker_image}"
		    cache_from+="--cache-from ${image_repo}:${TRAVIS_BRANCH} "
		    cache_from+="--cache-from ${image_repo}:${build_tag} "
		    # Pull latest in branch but don't error if it doesn't exist
		    # `docker build` skips non-existing --cache-from references
		    command docker pull "${image_repo}:${TRAVIS_BRANCH}" || true
		done
	    fi

	    # Only run the build if the image isn't already in Docker cache
	    # When building with multiple tags, all must be present to skip
	    cache_images="$(command docker images \
    		       	       	      --filter 'reference=${DOCKER_USER}/*' \
		       	       	      --format '{{.Repository}}:{{.Tag}}' \
		            | tr '\n' ' ')"

	    local i build_args=("${@}") skip=true
	    for i in "${!build_args[@]}"
	    do
		if [[ "${build_args[$i]}" =~ ^(-t|--tag)$ ]]
		then
		    local reference="${build_args[$((i + 1))]}"
		    if ! [[ "${cache_images}" =~ "${reference}" ]]
		    then
			echo_info "must build, '${reference}' is not in cache."
			skip=false
			break
		    fi
		fi
	    done

	    ${skip} && echo_warning 'skipping build, already in cache.' &&
		return 0
	    command docker build ${cache_from} "${@}"
	;;
	*)
	    command docker "${@}"
	;;
    esac
}
