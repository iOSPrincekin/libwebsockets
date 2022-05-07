#!/bin/bash

BASEDIR=$(dirname "$0")
cd ${BASEDIR}

build_target=build_iOS
cd ../
rm -rf ${build_target}

cmake ./ -DCMAKE_TOOLCHAIN_FILE=./contrib/iOS.cmake \
  -DUSE_SHARED_MBEDTLS_LIBRARY=1 \
  -DENABLE_PROGRAMS=0 \
  -Wno-dev && \
  make -j

