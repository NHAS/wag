FROM redhat/ubi9-minimal:latest

RUN microdnf update -y
RUN microdnf install -y iptables nc pam

WORKDIR /app/wag

COPY wag/wag /usr/bin/wag
COPY docker_entrypoint.sh /
RUN chmod +x /docker_entrypoint.sh /usr/bin/wag

VOLUME /data
VOLUME /cfg

CMD ["/docker_entrypoint.sh"]