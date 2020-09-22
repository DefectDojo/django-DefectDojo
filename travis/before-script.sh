#!/bin/bash

curl -LsO "https://storage.googleapis.com/kubernetes-release/release/${K8S_VERSION}/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

curl -Lso minikube "https://storage.googleapis.com/minikube/releases/${MINIKUBE_VERSION}/minikube-linux-amd64"
chmod +x minikube
sudo mv minikube /usr/local/bin/

curl -L https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz | tar zx
chmod +x linux-amd64/helm
sudo mv linux-amd64/helm /usr/local/bin/
rm -rf linux-amd64/

echo "127.0.0.1 ${DD_HOST}" | sudo tee -a /etc/hosts
