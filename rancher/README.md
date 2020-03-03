# Rancher
This is meant to help facilitate deploying DefectDojo in a Rancher/Kubernetes environment. This grabs the containers from the Docker registry and instantiates them in a pod. The ports are exposed for communication, MySQL gets a persistent volume, everyone is happy.

### deployment.yaml
Based off the docker-compose.yaml and translated to Kubernetes. MySQL uses a persistent volume claim.

### service.yaml
Exposes the containers's ports within the pod.

### pv.yaml
Persistent volume using the NFS client.

### ingress.yaml
Rancher's ingress yaml for serving HTTPS requests.
