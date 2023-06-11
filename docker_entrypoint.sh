#!/bin/bash

if [ ! -f /cfg/config.json ]; then
	echo "No config file found, generating from example. Ensure /data is mounted for persistence"
	cp /tmp/example_config.json /cfg/config.json
	sed -i "s|AN EXAMPLE KEY|$(wg genkey)|" /cfg/config.json
	sed -i "s|\"devices.db\"|\"/data/devices.db\"|" /cfg/config.json
	echo "Please edit your newly generated config file and start again"
	exit
fi

# trap for all processes created inside this block; a single Ctrl+C will stop them all
(trap 'kill 0' SIGINT

echo "WAG: start"
wag start -config /cfg/config.json &

while ! nc -z localhost 4433; do
  echo "Waiting WAG to become online on port 4433 ..."
  sleep 0.5
done

U=$(wag webadmin -list | grep $WEB_USER | cut -d, -f1)
if [ "$U" != "$WEB_USER" ]; then
  echo "WEBADMIN: add user $WEB_USER"
  wag webadmin -add -username "$WEB_USER" -password "$WEB_PWD"
else
  echo "WEBADMIN: user $WEB_USER exists, nothing updated"
fi

# block until 'wag start' finishes
wait )