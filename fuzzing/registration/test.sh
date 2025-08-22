#!/bin/bash

for i in {1..35}; do
	sudo ./wag registration -add -username toaster$i | grep toaster | cut -d, -f 1 >> output
done


ffuf -v -w output -u http://127.0.0.1:8080/register_device\?key\=FUZZ  -timeout 30