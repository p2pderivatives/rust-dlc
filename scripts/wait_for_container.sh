#!/bin/bash

while [ "`docker inspect -f {{.State.Status}} $1`" != "running" ]; do
     sleep 2;
done
