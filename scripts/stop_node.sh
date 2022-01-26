#!/bin/bash

if command -v docker &> /dev/null
then
   CMD=docker
else
   CMD=podman
fi

$CMD stop bitcoin-node
