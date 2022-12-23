#!/bin/bash

if [[ ! -d /wag ]]; then
    echo "/wag not present, please mount folder onto docker container with -v"
    exit 1
fi

cd /wag
make release