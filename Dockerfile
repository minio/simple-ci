FROM ubuntu:18.04

COPY simple-ci /

ENTRYPOINT ["/simple-ci", "--v=10"]
