# ckb-miscellaneous-scripts

[![Build Status](https://travis-ci.com/nervosnetwork/ckb-miscellaneous-scripts.svg?branch=master)](https://travis-ci.com/nervosnetwork/ckb-miscellaneous-scripts)

Interesting and useful CKB scripts which aren't necessarily in system scripts.

## Building

The following commands can be used to build all scripts in this repository.

Note: Building these scripts requires [Docker](https://docs.docker.com/engine/install/) to be installed and available to the current user.

```
git clone --depth=2 --branch=master https://github.com/nervosnetwork/ckb-miscellaneous-scripts.git
cd ckb-miscellaneous-scripts
git submodule update --init --recursive
make all-via-docker
```
