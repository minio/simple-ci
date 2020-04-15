FROM minio/ubuntu:dind-16.04

RUN  apt-get update && \
	apt-get install -y ca-certificates && \
	update-ca-certificates

ENV DOCKER_DAEMON_ARGS "--ipv6 --fixed-cidr-v6=2001:db8:1::/64 --storage-driver overlay2"

COPY simple-ci /
ADD ui /ui

ENTRYPOINT ["wrapdocker", "/simple-ci", "--v=10"]
