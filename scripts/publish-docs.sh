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
	pushd _site
	git config user.name "GitHub Actions Build"
	git config user.email github-actions@tfsec
	git add -A
	git commit -m "GitHub Actions Build: ${GITHUB_RUN_ID}. ${MESSAGE}" || true
	git push "${DEPLOY_REPO}" main:main || true
	popd
}

clone_site
go build ./cmd/tfsec-docs/
./tfsec-docs
cp -r docs-website/* ./_site/
deploy
