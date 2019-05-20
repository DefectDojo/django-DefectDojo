#!/bin/bash

source ${BASH_SOURCE%/*}/../common-functions.bash
source ${BASH_SOURCE%/*}/../common-vars.bash
source ${BASH_SOURCE%/*}/stage-vars.bash


function target_k8s {
    local google_storage='https://storage.googleapis.com'

    # Install `kubectl`
    local kubectl_url="/kubernetes-release/release/${K8S_VERSION}/bin/linux/amd64/kubectl"
    curl -LsO "${google_storage}${kubectl_url}"
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/

    # Install `minikube`
    local minikube_url="/minikube/releases/${MINIKUBE_VERSION}/minikube-linux-amd64"
    curl -Lso minikube "${google_storage}${minikube_url}"
    chmod +x minikube
    sudo mv minikube /usr/local/bin/

    # Install `helm`
    local helm_url="/kubernetes-helm/helm-${HELM_VERSION}-linux-amd64.tar.gz"
    curl -L "${google_storage}${helm_url}" | tar zx
    chmod +x linux-amd64/helm
    sudo mv linux-amd64/helm /usr/local/bin/
    rm -rf linux-amd64/

    # Start Minikube
    echo_info "starting Minikube for Kubernetes ${K8S_VERSION}..."
    sudo minikube start \
         --vm-driver=none \
         --kubernetes-version="${K8S_VERSION}"
    echo_success "starting Minikube for Kubernetes ${K8S_VERSION} done."

    # Update Minikube context
    echo_info 'configuring Kubernetes context and testing it...'
    sudo minikube update-context
    sudo kubectl cluster-info
    echo_success 'configuring Kubernetes context and testing it done.'

    # Enable Nginx ingress add-on, wait for it
    echo_info 'enabling Nginx ingress add-on and waiting for it...'
    sudo minikube addons enable ingress
    local status=''
    until [ "${status}" = 'True' ]
    do
        echo -n '.' && sleep 1
        status=$(sudo kubectl get pod \
                      --selector=app.kubernetes.io/name=nginx-ingress-controller \
                      --namespace=kube-system \
                      -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')

    done
    echo # new line after progress dots
    echo_success 'enabling Nginx ingress add-on and waiting for it done.'

    # Initialize Helm, wait for Tiller
    echo_info 'initializing Helm and waiting for Tiller to become ready...'
    sudo helm init
    local status=''
    until [ "${status}" = 'True' ]
    do
        echo -n '.' && sleep 1
        status=$(sudo kubectl get pod \
                      --selector=name=tiller \
                      --namespace=kube-system \
                      -o 'jsonpath={.items[*].status.conditions[?(@.type=="Ready")].status}')
    done
    echo # new line after progress dots
    echo_success 'initializing Helm and waiting for Tiller to become ready done.'

    # Update Helm repository
    echo_info 'updating Helm repository...'
    sudo helm repo update
    echo_success 'updating Helm repository done.'
}


function target_docker {
    : # Do nothing
}


run_or_die target_"${TARGET}"
