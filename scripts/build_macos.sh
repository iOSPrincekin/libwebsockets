#!/bin/bash

BASEDIR=$(dirname "$0")
cd ${BASEDIR}

build_target=build_macos
cd ../
rm -rf ${build_target}
cmake -G Xcode -B ${build_target} -DCMAKE_C_FLAGS="-Wno-error=attributes" -DCMAKE_CXX_FLAGS="-Wno-error=attributes"
