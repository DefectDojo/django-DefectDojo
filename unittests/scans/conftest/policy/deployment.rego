package main

import rego.v1

deny contains msg if {
	input.kind == "Deployment"
	not input.spec.template.spec.securityContext.runAsNonRoot
	msg := sprintf("Deployment %s must set securityContext.runAsNonRoot", [input.metadata.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	endswith(container.image, ":latest")
	msg := sprintf("Container %s must not use the :latest tag", [container.name])
}

deny contains msg if {
	input.kind == "Deployment"
	some container in input.spec.template.spec.containers
	not container.resources.limits.memory
	msg := sprintf("Container %s must set a memory limit", [container.name])
}

warn contains msg if {
	input.kind == "Deployment"
	not input.metadata.labels["app.kubernetes.io/name"]
	msg := sprintf("Deployment %s should carry an app.kubernetes.io/name label", [input.metadata.name])
}
