#!/bin/bash

set -ex

MAJOR="$(IFS='.' read -ra VERSION <<< "${CI_COMMIT_TAG}" && echo ${VERSION[0]})"
MINOR="$(IFS='.' read -ra VERSION <<< "${CI_COMMIT_TAG}" && echo ${VERSION[1]})"

# COMMIT_BRANCH is the branch that the release commit is
# made to. For major releases, the commit branch is MASTER.
# For minor releases, the commit branch is the TAGGING_BRANCH.
# The TAGGING_BRANCH is the branch from which the tag is made
# to be pushed to GitHub.
# For a major release COMMIT_BRANCH
# and TAGGING_BRANCH have the same HEAD.

TAGGING_BRANCH="release_${MAJOR}.0"
COMMIT_BRANCH=${TAGGING_BRANCH}
if [ ${MINOR} -eq 0 ]
then
    COMMIT_BRANCH="master"
    IS_MAJOR_RELEASE=true
fi

LOCAL_GITHUB_DIR="/repo"


# Functions
clone_github() {
    mkdir ${LOCAL_GITHUB_DIR}
    cd ${LOCAL_GITHUB_DIR}
    git clone https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/${GITHUB_ACCOUNT}/${GITHUB_REPO}.git
}

setup_commit_branch() {
    cd ${LOCAL_GITHUB_DIR}/${GITHUB_REPO}
    git checkout ${COMMIT_BRANCH}
    copy_and_commit
}

create_tagging_branch() {
    cd ${LOCAL_GITHUB_DIR}/${GITHUB_REPO}
    git checkout -b ${TAGGING_BRANCH}
}

create_tag() {
    cd ${LOCAL_GITHUB_DIR}/${GITHUB_REPO}
    git checkout ${TAGGING_BRANCH}
    git tag ${CI_COMMIT_TAG}
}

copy_and_commit() {
    cd ${CI_PROJECT_DIR}
    git checkout ${TAGGING_BRANCH}
    rsync -av ./ ${LOCAL_GITHUB_DIR}/${GITHUB_REPO}/ --exclude .git
    cd ${LOCAL_GITHUB_DIR}/${GITHUB_REPO}
    git add .
    git commit -m "Release ${CI_COMMIT_TAG}"
}

push_to_github() {
    if [ "${IS_MAJOR_RELEASE}" = true ]
    then
        git push -u origin +${COMMIT_BRANCH}
    fi
    git push -u origin +${TAGGING_BRANCH}
    git push origin ${CI_COMMIT_TAG}
}


clone_github
setup_commit_branch
if [ "${IS_MAJOR_RELEASE}" = true ]
then
    create_tagging_branch
fi
create_tag
push_to_github

exit 0
