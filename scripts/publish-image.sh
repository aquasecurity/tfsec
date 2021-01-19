#!/usr/bin/env bash

set -e 

IMAGES=(liamg/tfsec tfsec/tfsec)

for IMAGE in ${IMAGES[@]}; do
    echo "building ${IMAGE}..."
    docker build --build-arg tfsec_version=${TRAVIS_TAG} -t ${IMAGE} .

    echo "publishing ${IMAGE}..."
    docker tag ${IMAGE} ${IMAGE}:${TRAVIS_TAG}
    docker push ${IMAGE}:${TRAVIS_TAG}
    docker tag ${IMAGE} ${IMAGE}:latest
    docker push ${IMAGE}:latest
done;
