#!/bin/bash

old="$IFS"
IFS='_'
filename="$(date +'%Y%m%d%H%M%S')_$*.sql"
echo "making file $filename"
echo "-- version VERSION_NUMBER_HERE" >> $filename
IFS=$old

