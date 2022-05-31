# @title: Deny privileged container
#
# 特権コンテナの実行は禁止する
#
# @kinds apps/DaemonSet apps/Deployment apps/StatefulSet core/Pod

package user.kubernetes.deny_privileged_container

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
    "id": "deny-privileged-container",
    "title": "Privileged Container not allowed",
    "severity": "HIGH",
    "type": "Custom Kubernetes Check",
    "description": "Privileged Container is not allowed because of some reason.",
}

__rego_input__ := {
    "combine": false,
    "selector": [
        {"type": "kubernetes"},
    ],
}

get_privileged_containers[container] {
	container := kubernetes.containers[_]
	container.securityContext.privileged == true
}

deny[res] {
	not kubernetes.is_trusted_namespace
	output := get_privileged_containers[_]

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.privileged' to false", [output.name, kubernetes.kind, kubernetes.name]))
  res := result.new(msg, output)
}
