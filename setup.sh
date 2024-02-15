#!/bin/bash

set -eo pipefail

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

PATHSFILE=$SCRIPT_DIR/paths.sh
PYTHON_ENV_DIR=$SCRIPT_DIR/env
DPDK_VERSION="22.11.4"
RTE_TARGET=x86_64-native-linux-gcc

DEPS_DIR=$SCRIPT_DIR/deps
DPDK_DIR=$DEPS_DIR/dpdk
DPDK_KMODS_DIR=$DEPS_DIR/dpdk-kmods

export DEBIAN_FRONTEND=noninteractive

get_deps() {
  sudo apt update
  sudo apt-get -y install \
    build-essential \
    make \
    vim \
    wget \
    curl \
    git \
    python3-pyelftools \
    python3-pip \
    python3-venv \
    linux-generic \
    linux-headers-generic \
    cmake \
    pkg-config \
    libnuma-dev \
    libpcap-dev \
    lshw \
    kmod \
    iproute2 \
    net-tools \
    ninja-build
}

add_expr_to_paths_file() {
  if ! grep "^${1}" "$PATHSFILE" >/dev/null; then
    echo "${1}" >> "$PATHSFILE"
    . "$PATHSFILE"
  fi
}

create_paths_file() {
  rm -f $PATHSFILE > /dev/null 2>&1 || true
  touch $PATHSFILE
}

setup_env() {
  pushd "$SCRIPT_DIR"
    if [ ! -d $PYTHON_ENV_DIR ]; then
      python3 -m venv $PYTHON_ENV_DIR
    fi

    add_expr_to_paths_file ". $PYTHON_ENV_DIR/bin/activate"
    . $PATHSFILE
    pip3 install -r requirements.txt
  popd
}

install_dpdk() {
  if [ ! -z "${RTE_SDK}"]; then
    echo "DPDK found: $RTE_SDK"
    # TODO: check if this is the correct DPDK version
    return 0
  fi

  mkdir -p $DEPS_DIR

  if [ ! -d $DPDK_DIR ]; then
    pushd $DEPS_DIR
      DPDK_TAR="dpdk-$DPDK_VERSION.tar.xz"
      wget https://fast.dpdk.org/rel/$DPDK_TAR
      tar xJf $DPDK_TAR && rm $DPDK_TAR
      mv dpdk-stable-$DPDK_VERSION $DPDK_DIR
    popd
  fi

  pushd $DPDK_DIR
    meson build
    cd build
    meson configure -Dprefix="$DPDK_DIR/build"
    ninja
    meson install
  popd

  DPDK_PKGCONFIG_PATH=$(realpath $(dirname $(find . -name "libdpdk.pc" | head -n 1)))
  add_expr_to_paths_file "export PKG_CONFIG_PATH=\$PKG_CONFIG_PATH:$DPDK_PKGCONFIG_PATH"
}

install_dpdk_kmods() {
	if [ ! -d $DPDK_KMODS_DIR ]; then
		pushd $DEPS_DIR
			git clone http://dpdk.org/git/dpdk-kmods
			sudo mv dpdk-kmods $DPDK_KMODS_DIR || true
		popd
	fi

	pushd $DPDK_KMODS_DIR/linux/igb_uio
		make -j
	popd
}

get_deps
create_paths_file
setup_env
install_dpdk
install_dpdk_kmods