#!/usr/bin/env bash

set -e 

IMAGES=(tfsec/tfsec)

for IMAGE in ${IMAGES[@]}; do
    echo "building ${IMAGE}..."
    docker build --build-arg tfsec_version=${TRAVIS_TAG} -f Dockerfile -t ${IMAGE} .
    docker build --build-arg tfsec_version=${TRAVIS_TAG} -f Dockerfile.scratch -t ${IMAGE}-scratch .

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

    echo "publishing ${IMAGE}-alpine..."
    # push the patch tag - eg; v0.36.15
    docker tag ${IMAGE} ${IMAGE}-alpine:${TRAVIS_TAG}
    docker push ${IMAGE}-alpine:${TRAVIS_TAG}

    # push the minor tag - eg; v0.36
    docker tag ${IMAGE} ${IMAGE}-alpine:${TRAVIS_TAG%.*}
    docker push ${IMAGE}-alpine:${TRAVIS_TAG%.*}

    # push the latest tag
    docker tag ${IMAGE} ${IMAGE}-alpine:latest
    docker push ${IMAGE}-alpine:latest

    echo "publishing ${IMAGE}-scratch..."
    # push the patch tag - eg; v0.36.15
    docker tag ${IMAGE}-scratch ${IMAGE}-scratch:${TRAVIS_TAG}
    docker push ${IMAGE}-scratch:${TRAVIS_TAG}

    # push the minor tag - eg; v0.36
    docker tag ${IMAGE}-scratch ${IMAGE}-scratch:${TRAVIS_TAG%.*}
    docker push ${IMAGE}-scratch:${TRAVIS_TAG%.*}

    # push the latest tag
    docker tag ${IMAGE}-scratch ${IMAGE}-scratch:latest
    docker push ${IMAGE}-scratch:latest
done;
