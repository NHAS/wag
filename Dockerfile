FROM redhat/ubi9-minimal:latest

RUN microdnf update -y
RUN microdnf install -y iptables nc

WORKDIR /app/wag

COPY wag /usr/bin/wag
COPY example_config.json /tmp

COPY docker_entrypoint.sh /
RUN chmod +x /docker_entrypoint.sh

VOLUME /data
VOLUME /cfg

CMD ["/docker_entrypoint.sh"]