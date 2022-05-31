package user.kubernetes.deny_privileged_container

test_privileged_container_false {
	manifest := {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {"containers": [{
			"name": "test",
			"image": "alpine:latest",
			"securityContext": {"privileged": false},
		}]},
	}

	r := deny with input as manifest
  count(r) == 0
}

test_privileged_container_null {
	manifest := {
		"kind": "Pod",
		"metadata": {"name": "test-pod"},
		"spec": {},
	}

	r := deny with input as manifest
  count(r) == 0
}

test_privileged_container_true {
	manifest := {
    "apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "test-pod", "namespace": "default"},
		"spec": {"containers": [{
			"name": "test",
			"image": "alpine:latest",
			"securityContext": {"privileged": true},
		}]},
	}

	r := deny with input as manifest
  count(r) == 1
  r[_].msg == "Container 'test' of Pod 'test-pod' should set 'securityContext.privileged' to false"
}

