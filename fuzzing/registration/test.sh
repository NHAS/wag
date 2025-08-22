#!/bin/bash



for i in {1..255}; do
	sudo ./wag registration -add -username toaster$i | grep toaster | cut -d, -f 1 >> output
done


ffuf -v -w output -u http://127.0.0.1:8081/register_device\?key\=FUZZ  -timeout 30
