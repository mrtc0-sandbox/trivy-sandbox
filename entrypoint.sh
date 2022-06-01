#!/bin/bash

trivy -q conf -f sarif  --policy policies/policy --namespaces user manifests/ \
  | jq -r '.runs[].results[] | "\(.level[0:1]):\("manifests/" + .locations[].physicalLocation.artifactLocation.uri):\(.locations[].physicalLocation.region.endLine) \(.message.text)"' \
  | reviewdog -efm="%t%f:%l %m" --diff="git diff ${GITHUB_REF}" -reporter=github-pr-review