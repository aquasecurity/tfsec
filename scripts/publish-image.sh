#!/usr/bin/env bash

set -e 

IMAGES=(liamg/tfsec tfsec/tfsec)

for IMAGE in ${IMAGES[@]}; do
    echo "building ${IMAGE}..."
    docker build --build-arg tfsec_version=${TRAVIS_TAG} -t ${IMAGE} .

    echo "publishing ${IMAGE}..."
    # push the patch tag - eg; v0.36.15
    docker tag ${IMAGE} ${IMAGE}:${TRAVIS_TAG}
    docker push ${IMAGE}:${TRAVIS_TAG}

    # push the minor tag - eg; v0.36
    docker tag ${IMAGE} ${IMAGE}:${TRAVIS_TAG%.*}
    docker push ${IMAGE}:${TRAVIS_TAG%.*}

    # push the latest tag
    docker tag ${IMAGE} ${IMAGE}:latest
    docker push ${IMAGE}:latest
done;
