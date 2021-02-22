#!/usr/bin/env bash

set -e 

IMAGES=(tfsec/tfsec)

function publish_image() {
    WORKING_IMAGE=$1
    TARGET_IMAGE=$2
    echo "publishing ${TARGET_IMAGE}..."
    # push the patch tag - eg; v0.36.15
    docker tag "${WORKING_IMAGE}" "${TARGET_IMAGE}":"${TRAVIS_TAG}"
    docker push "${TARGET_IMAGE}":"${TRAVIS_TAG}"

    # push the minor tag - eg; v0.36
    docker tag "${WORKING_IMAGE}" "${TARGET_IMAGE}":"${TRAVIS_TAG%.*}"
    docker push "${TARGET_IMAGE}":"${TRAVIS_TAG%.*}"

    # push the latest tag
    docker tag "${WORKING_IMAGE}" "${TARGET_IMAGE}":latest
    docker push "${TARGET_IMAGE}":latest

}

for IMAGE in "${IMAGES[@]}"; do
    echo "building ${IMAGE}..."
    docker build --build-arg tfsec_version="${TRAVIS_TAG}" -f Dockerfile -t "${IMAGE}" .
    docker build --build-arg tfsec_version="${TRAVIS_TAG}" -f Dockerfile.scratch -t "${IMAGE}-scratch" .
    docker build --build-arg tfsec_version="${TRAVIS_TAG}" -f Dockerfile.ci -t "${IMAGE}-ci" .

    publish_image "${IMAGE}" "${IMAGE}"
    publish_image "${IMAGE}" "${IMAGE}-alpine"
    publish_image "${IMAGE}-scratch" "${IMAGE}-scratch"
    publish_image "${IMAGE}-ci" "${IMAGE}-ci"

done;
