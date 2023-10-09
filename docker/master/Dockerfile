# vim:set ft=dockerfile:
#ARG DEBIAN_VERSION=buster
FROM debian:buster
ARG TOKEN=pat_N24JDCyM2XZ6LUCFRj5pzL1D

RUN sed -i 's/http:\/\/deb.debian.org/http:\/\/mirrors.aliyun.com/g' /etc/apt/sources.list

# Source Dockerfile:
# https://github.com/docker-library/postgres/blob/master/9.4/Dockerfile

# explicitly set user/group IDs
RUN groupadd -r freeswitch --gid=999 && useradd -r -g freeswitch --uid=999 freeswitch

# grab gosu for easy step-down from root
RUN apt-get update && apt-get install -y --no-install-recommends dirmngr gnupg2 ca-certificates wget \
    && gpg2 --keyserver hkp://keyserver.ubuntu.com --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 \
    && gpg2 --keyserver hkp://keyserver.ubuntu.com --recv-keys 655DA1341B5207915210AFE936B4249FA7B0FB03 \
    && gpg2 --output /usr/share/keyrings/signalwire-freeswitch-repo.gpg --export 655DA1341B5207915210AFE936B4249FA7B0FB03 \
    && rm -rf /var/lib/apt/lists/* \
    && wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/1.16/gosu-$(dpkg --print-architecture)" \
    && wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/1.16/gosu-$(dpkg --print-architecture).asc" \
    && gpg --verify /usr/local/bin/gosu.asc \
    && rm /usr/local/bin/gosu.asc \
    && chmod +x /usr/local/bin/gosu \
    && apt-get purge -y --auto-remove ca-certificates wget dirmngr gnupg2

# make the "en_US.UTF-8" locale so freeswitch will be utf-8 enabled by default
RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

#freeswitch docker config
RUN apt-get update && apt-get install -yq gnupg2 wget lsb-release \
    && wget --http-user=signalwire --http-password=$TOKEN -O /usr/share/keyrings/signalwire-freeswitch-repo.gpg https://freeswitch.signalwire.com/repo/deb/debian-release/signalwire-freeswitch-repo.gpg \
    && echo "machine freeswitch.signalwire.com login signalwire password $TOKEN" > /etc/apt/auth.conf \
    && chmod 600 /etc/apt/auth.conf \
    && echo "deb [signed-by=/usr/share/keyrings/signalwire-freeswitch-repo.gpg] https://freeswitch.signalwire.com/repo/deb/debian-release/ `lsb_release -sc` main" > /etc/apt/sources.list.d/freeswitch.list \
    && echo "deb-src [signed-by=/usr/share/keyrings/signalwire-freeswitch-repo.gpg] https://freeswitch.signalwire.com/repo/deb/debian-release/ `lsb_release -sc` main" >> /etc/apt/sources.list.d/freeswitch.list \
    && apt-get update 
 
# Install dependencies required for the build
RUN apt-get build-dep freeswitch -y
RUN apt-get update && apt-get install -y vim 
# then let's get the source. Use the -b flag to get a specific branch
RUN cd /usr/src/ \
    && git clone https://github.com/signalwire/freeswitch.git -bv1.10 freeswitch \
    && cd freeswitch \
    && git config pull.rebase true

#copy mod_vad
COPY ["mod_vad","/usr/src/freeswitch/src/mod/applications/mod_vad"]

RUN cd /usr/src/
RUN git clone https://github.com/dpirch/libfvad.git \
    && cd libfvad \
    && autoreconf -i \
    && ./configure \
    && make \
    && make install \
    && ldconfig

# Because we're in a branch that will go through many rebases, it's
# better to set this one, or you'll get CONFLICTS when pulling (update).
#RUN cd /usr/src/freeswitch

RUN sed -i '1s/^/applications\/mod_vad\n/' /usr/src/freeswitch/build/modules.conf.in

#WORKDIR /usr/src/freeswitch
# ... and do the build
RUN cd /usr/src/freeswitch \
    &&./bootstrap.sh -j \
    && ./configure \
    && make \
    && make install 

RUN sed -i '10i<load module="mod_vad"/>' /usr/local/freeswitch/conf/autoload_configs/modules.conf.xml
COPY mod_vad/conf/autoload_configs/vad.conf.xml /usr/local/freeswitch/conf/autoload_configs

# Add anything else here
COPY docker-entrypoint.sh /

# 创建用于存储 Core Dump 的目录
RUN mkdir /core_dumps

# 配置系统以将 Core Dump 输出到 /core_dumps 目录
#RUN echo '/core_dumps/core.%e.%p.%h.%t' > /proc/sys/kernel/core_pattern
## Ports
# Open the container up to the world.
### 8021 fs_cli, 5060 5061 5080 5081 sip and sips, 64535-65535 rtp
EXPOSE 8021/tcp
EXPOSE 8001/tcp
EXPOSE 5060/tcp 5060/udp 5080/tcp 5080/udp
EXPOSE 5061/tcp 5061/udp 5081/tcp 5081/udp
EXPOSE 7443/tcp
EXPOSE 5070/udp 5070/tcp
EXPOSE 64535-65535/udp
EXPOSE 16384-32768/udp


# Volumes
## Freeswitch Configuration
VOLUME ["/usr/local/freeswitch/conf"]
## Tmp so we can get core dumps out
VOLUME ["/core_dumps"]

# Limits Configuration
COPY    build/freeswitch.limits.conf /etc/security/limits.d/

# Healthcheck to make sure the service is running
SHELL       ["/bin/bash"]
HEALTHCHECK --interval=15s --timeout=5s \
    CMD  /usr/local/freeswitch/bin/fs_cli -x status | grep -q ^UP || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]


CMD ["freeswitch"]

