#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

ROOT_DIR=$SCRIPT_DIR

DEBUG_BUILD_DIR=$ROOT_DIR/Debug
RELEASE_BUILD_DIR=$ROOT_DIR/Release

build_debug() {
    if [ ! -d $DEBUG_BUILD_DIR ]; then
        mkdir -p $DEBUG_BUILD_DIR
    fi

    pushd $DEBUG_BUILD_DIR >/dev/null
        cmake -DCMAKE_BUILD_TYPE=Debug $ROOT_DIR -G Ninja
    popd >/dev/null

    pushd $DEBUG_BUILD_DIR >/dev/null
        ninja
    popd >/dev/null
}

build_release() {
    if [ ! -d $RELEASE_BUILD_DIR ]; then
        mkdir -p $RELEASE_BUILD_DIR
    fi

    pushd $RELEASE_BUILD_DIR >/dev/null
        cmake -DCMAKE_BUILD_TYPE=Release $ROOT_DIR -G Ninja
    popd >/dev/null

    pushd $RELEASE_BUILD_DIR >/dev/null
        ninja
    popd >/dev/null
}

build_debug
build_release