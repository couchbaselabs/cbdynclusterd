FROM couchbasebuild/sdk-rockylinux9-build

MAINTAINER Couchbase SDK QE Team <sdk_qe@couchbase.com>

USER root
# Update server
#RUN dnf install --setopt=keepcache=0 -y sudo && \
#    dnf clean all

# Install utils and dependencies
RUN dnf install openssh-server -y

# Install python-httplib2
#RUN curl https://bootstrap.pypa.io/get-pip.py | python - ; pip install httplib2

COPY functions /etc/init.d/

# Install gosu for startup script
# We could use one of below servers to run
#   ha.pool.sks-keyservers.net
#   hkp://p80.pool.sks-keyservers.net:80
#   keyserver.ubuntu.com
#   hkp://keyserver.ubuntu.com:80
#   pgp.mit.edu
RUN gpg --keyserver pgp.mit.edu --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    && curl -o /usr/local/bin/gosu -sSL "https://github.com/tianon/gosu/releases/download/1.4/gosu-amd64" \
    && curl -o /usr/local/bin/gosu.asc -sSL "https://github.com/tianon/gosu/releases/download/1.4/gosu-amd64.asc" \
    && gpg --verify /usr/local/bin/gosu.asc \
    && rm /usr/local/bin/gosu.asc \
    && chmod +x /usr/local/bin/gosu
