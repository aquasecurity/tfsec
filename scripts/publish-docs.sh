#!/bin/bash

set -ex

DEPLOY_REPO="https://${GITHUB_TOKEN}@github.com/tfsec/tfsec.github.io.git"
MESSAGE=$(git log -1 HEAD --pretty=format:%s)

function clone_site {
	echo "getting latest site"
	git clone --depth 1 "${DEPLOY_REPO}" _site
}

function deploy {
	echo "deploying changes"

	if [[ "$TRAVIS_PULL_REQUEST" != "false" ]]; then
	    echo "except don't publish site for pull requests"
	    exit 0
	fi

	if [[ "$TRAVIS_BRANCH" != "master" ]]; then
	    echo "except we should only publish the master branch. stopping here"
	    exit 0
	fi

	pushd _site
	git config user.name "Travis Build"
  git config user.email travis@tfsec
	git add -A
	git commit -m "Travis Build: ${TRAVIS_BUILD_NUMBER}. ${MESSAGE}" || true
	git push "${DEPLOY_REPO}" main:main || true
	popd
}

clone_site
go build ./cmd/tfsec-docs/
./tfsec-docs
cp -r docs-website/* ./_site/
deploy
