#!/bin/bash

if [ ! -f /cfg/config.json ]; then
	echo "No config file found, generating from example. Ensure /data is mounted for persistence"
	wag gen-config -out /cfg/config.json
	sed -i "s|\"devices.db\"|\"/data/devices.db\"|" /cfg/config.json
	echo "Config generated, you may want to edit the advanced options and start again"
  exit
fi

echo "WAG: start"
exec /usr/bin/wag start -config /cfg/config.json
