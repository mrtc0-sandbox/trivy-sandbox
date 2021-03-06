#!/bin/bash

set -ex

trivy -q conf -f sarif --policy policies/policy --namespaces user . \
  | jq '.runs[].results[] | "\(.level[0:1]):\(.locations[].physicalLocation.artifactLocation.uri):\(.locations[].physicalLocation.region.endLine) \(.message.text)"' \
  | sed "s/\\\\n/<br>/g" \
  | reviewdog -efm="\"%t:%f:%l %m\"" --diff="git diff ${GITHUB_REF}" -reporter=github-pr-review
