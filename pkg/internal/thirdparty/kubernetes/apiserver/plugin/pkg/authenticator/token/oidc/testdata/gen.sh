#!/usr/bin/env bash

# NOTE: This file was copied based on commit https://github.com/kubernetes/kubernetes/commit/481c2d8e03508dba2c28aeb4bba48ce48904183b

# Copyright 2018 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# MODIFICATION: Use `-f` flag to ignore non-existent files
# rm ./*.pem
rm -f ./*.pem

for N in $(seq 1 3); do
    # MODIFICATION: force the older PEM encoded format so that newer versions of ssh-keygen
    # that generate OPENSSH format keys generate the PEM encoded format that the copied tests expect.
    # ssh-keygen -t rsa -b 2048 -f rsa_"$N".pem -N ''
    ssh-keygen -m PEM -t rsa -b 2048 -f rsa_"$N".pem -N ''
done

for N in $(seq 1 3); do
    # MODIFICATION: use openssl to generate the ECDSA keys so that it generates
    # with named curves that Go is able to parse.
    # ssh-keygen -t ecdsa -b 521 -f ecdsa_"$N".pem -N ''
    openssl ecparam -name secp521r1 -genkey -noout -out ecdsa_"$N".pem
done

rm ./*.pub
